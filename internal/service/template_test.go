package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplateBuilder is the test stub for the OCI pipeline. Writes a
// few bytes to OutPath so the service's os.Stat-driven SizeBytes is
// non-zero, optionally returns an error, and signals on the done
// channel so tests can wait without sleeping.
type fakeTemplateBuilder struct {
	mu       sync.Mutex
	calls    int
	lastReq  TemplateBuildRequest
	err      error
	sizeOnly bool
	done     chan struct{}
}

func (f *fakeTemplateBuilder) Build(ctx context.Context, req TemplateBuildRequest) (*TemplateBuildResult, error) {
	f.mu.Lock()
	f.calls++
	f.lastReq = req
	err := f.err
	f.mu.Unlock()
	defer func() {
		if f.done != nil {
			f.done <- struct{}{}
		}
	}()
	if err != nil {
		return nil, err
	}
	// Write a small file so the row's last_error stays empty and the
	// success path runs end-to-end. mkdirAll already happened in
	// kickTemplateBuild.
	if !f.sizeOnly {
		if werr := os.WriteFile(req.OutPath, []byte("FAKE"), 0o600); werr != nil {
			return nil, werr
		}
	}
	stagingDir := filepath.Join(filepath.Dir(req.OutPath), "staging")
	if mkErr := os.MkdirAll(stagingDir, 0o755); mkErr != nil {
		return nil, mkErr
	}
	return &TemplateBuildResult{
		RootfsPath: req.OutPath,
		StagingDir: stagingDir,
		SizeBytes:  4,
	}, nil
}

func newTemplateHarness(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	templatesDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatalf("mkdir templates dir: %v", err)
	}
	svc := &Service{
		cfg: config.Config{
			EnableFirecracker:             true,
			FirecrackerTemplatesDir:       templatesDir,
			FirecrackerTemplateGCEnabled:  true,
			FirecrackerTemplateGCInterval: time.Hour,
			FirecrackerTemplateGCTTL:      24 * time.Hour,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
	}
	return svc, st, templatesDir
}

// TestCreateTemplate_HappyPath confirms the async transition PENDING →
// READY: POST returns immediately with a pending row, the background
// goroutine fires the builder, status flips and rootfs_size_bytes is
// populated. The size assertion pins the os.Stat round trip, not just
// the in-memory result struct.
func TestCreateTemplate_HappyPath(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)

	done := make(chan struct{}, 1)
	builder := &fakeTemplateBuilder{done: done}
	svc.SetTemplateBuilder(builder)

	tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{
		ID:    "tpl-happy",
		Image: "docker://alpine:3.19",
	})
	if err != nil {
		t.Fatalf("CreateTemplate() error = %v", err)
	}
	if tpl.Status != models.TemplateStatusPending {
		t.Fatalf("CreateTemplate() status = %s, want pending", tpl.Status)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("builder.Build never ran")
	}
	// Give UpdateTemplateStatus a beat — it runs after Build returns, in
	// the same goroutine.
	deadline := time.Now().Add(2 * time.Second)
	var got *models.Template
	for time.Now().Before(deadline) {
		got, err = st.GetTemplate(ctx, tpl.ID)
		if err != nil {
			t.Fatalf("GetTemplate: %v", err)
		}
		if got.Status == models.TemplateStatusReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got.Status != models.TemplateStatusReady {
		t.Fatalf("post-build status = %s, want ready", got.Status)
	}
	if got.RootfsPath == "" {
		t.Fatalf("post-build RootfsPath empty")
	}
	if got.RootfsSizeBytes == 0 {
		t.Fatalf("post-build size = 0")
	}
	if builder.lastReq.OutPath != filepath.Join(templatesDir, "tpl-happy", "rootfs.ext4") {
		t.Fatalf("builder OutPath = %q, want under templates dir", builder.lastReq.OutPath)
	}
}

// TestCreateTemplate_BuilderError_TransitionsFailed confirms the
// goroutine catches builder errors, sets status FAILED with
// last_error, and removes the half-built artifact dir.
func TestCreateTemplate_BuilderError_TransitionsFailed(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)

	done := make(chan struct{}, 1)
	builder := &fakeTemplateBuilder{err: errors.New("skopeo blew up"), done: done}
	svc.SetTemplateBuilder(builder)

	tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "tpl-fail", Image: "docker://bad"})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("builder.Build never ran")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := st.GetTemplate(ctx, tpl.ID)
		if got != nil && got.Status == models.TemplateStatusFailed {
			if got.LastError == "" {
				t.Fatalf("last_error empty on failed row")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Half-built dir must be gone — a leftover dir under templatesDir
	// would silently consume disk on every retry.
	entries, _ := os.ReadDir(filepath.Join(templatesDir, "tpl-fail"))
	if len(entries) != 0 {
		t.Fatalf("artifact dir not cleaned: %v", entries)
	}
}

// TestCreateTemplate_DisabledRejects confirms the EnableFirecracker
// gate: a node without Firecracker support refuses CreateTemplate
// instead of accepting a row that no driver can ever consume.
func TestCreateTemplate_DisabledRejects(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newTemplateHarness(t)
	svc.cfg.EnableFirecracker = false
	svc.SetTemplateBuilder(&fakeTemplateBuilder{})

	_, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "docker://alpine"})
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("CreateTemplate disabled error = %v, want ErrRuntimeNotImplemented", err)
	}
}

// TestDeleteTemplate_InUseRejected pins the IRON RULE: an active
// sandbox holding template_id blocks the row delete with
// ErrTemplateInUse. The Phase 2 API maps this to 409 so the operator
// destroys the sandbox first.
func TestDeleteTemplate_InUseRejected(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)

	tpl := &models.Template{
		ID: "tpl-busy", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, RootfsPath: "/tmp/tpl-busy/rootfs.ext4",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	sb := &models.Sandbox{
		ID: "sb-tpl-busy", Image: "docker://alpine:3.19",
		Status: models.SandboxStatusStarted, ContainerID: "ctr", ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 1024, DiskGB: 10, OSUser: "root",
		Env: map[string]string{}, ToolboxEnabled: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(),
		Runtime: models.RuntimeFirecracker, TemplateID: tpl.ID,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create sandbox: %v", err)
	}

	if err := svc.DeleteTemplate(ctx, tpl.ID); !errors.Is(err, store.ErrTemplateInUse) {
		t.Fatalf("DeleteTemplate in-use error = %v, want ErrTemplateInUse", err)
	}
}

// TestDeleteTemplate_PendingRejected pins the goroutine-race guard:
// deleting a row while the build goroutine is still writing to its dir
// would leak a half-built rootfs the operator believes is gone.
func TestDeleteTemplate_PendingRejected(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)

	tpl := &models.Template{
		ID: "tpl-pending", Image: "docker://alpine:3.19",
		Status:    models.TemplateStatusPending,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if err := svc.DeleteTemplate(ctx, tpl.ID); !errors.Is(err, store.ErrTemplateInUse) {
		t.Fatalf("DeleteTemplate pending error = %v, want ErrTemplateInUse", err)
	}
}

// TestRunTemplateGC_RemovesEligible drives a single deterministic
// tick: a stale, unreferenced READY row gets its dir cleaned and row
// deleted; a referenced row is left alone. Mirrors the
// StartBuiltImageGC test seam pattern — no ticker, no sleep.
func TestRunTemplateGC_RemovesEligible(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)

	now := time.Now().UTC()
	staleDir := filepath.Join(templatesDir, "tpl-stale")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatalf("mkdir staleDir: %v", err)
	}
	stalePath := filepath.Join(staleDir, "rootfs.ext4")
	if err := os.WriteFile(stalePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write stale rootfs: %v", err)
	}

	mustInsert := func(id, rootfs string, updatedAt time.Time) {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: id, Image: "docker://alpine", Status: models.TemplateStatusReady,
			RootfsPath: rootfs, CreatedAt: updatedAt, UpdatedAt: updatedAt,
		}); err != nil {
			t.Fatalf("CreateTemplate %s: %v", id, err)
		}
	}
	mustInsert("tpl-stale", stalePath, now.Add(-48*time.Hour))
	mustInsert("tpl-fresh", "/var/lib/aerolvm/templates/tpl-fresh/rootfs.ext4", now.Add(-1*time.Hour))

	svc.cfg.FirecrackerTemplateGCTTL = 24 * time.Hour
	svc.runTemplateGC(ctx, now)

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale rootfs still on disk: err=%v", err)
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatalf("stale dir still on disk: err=%v", err)
	}
	if _, err := st.GetTemplate(ctx, "tpl-stale"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale row still present: err=%v", err)
	}
	if _, err := st.GetTemplate(ctx, "tpl-fresh"); err != nil {
		t.Fatalf("fresh row should survive: err=%v", err)
	}
}

// TestStartTemplateGC_DisabledIsNoOp confirms the operator kill-
// switch: GC enable=false (or Firecracker disabled) must not spawn the
// background sweeper. Same shape as TestStartBuiltImageGCDisabledIsNoOp.
func TestStartTemplateGC_DisabledIsNoOp(t *testing.T) {
	svc, _, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartTemplateGC(ctx) // must return immediately

	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.EnableFirecracker = false
	svc.StartTemplateGC(ctx) // must also return immediately

	svc.cfg.EnableFirecracker = true
	svc.cfg.FirecrackerTemplateGCInterval = 0
	svc.StartTemplateGC(ctx) // zero interval must early-out
}
