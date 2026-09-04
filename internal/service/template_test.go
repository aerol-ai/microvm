package service

import (
	"context"
	crand "crypto/rand"
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

// TestCreateTemplate_RootfsOnlyHappyPath confirms the async transition
// PENDING → BUILDING_ROOTFS → READY_NO_SNAPSHOT for a node without a
// snapshotter wired: POST returns immediately with a pending row, the
// background goroutine fires the builder, status flips and
// rootfs_size_bytes is populated. The terminal status is
// ready_no_snapshot (not ready) because no snapshot phase ran — the
// rootfs is on disk and cold-bootable, but no snapshot artifacts exist.
// The full two-phase ready transition is covered by
// TestCreateTemplate_TwoStageHappyPath.
func TestCreateTemplate_RootfsOnlyHappyPath(t *testing.T) {
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
		if got.Status == models.TemplateStatusReadyNoSnapshot {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got.Status != models.TemplateStatusReadyNoSnapshot {
		t.Fatalf("post-build status = %s, want ready_no_snapshot", got.Status)
	}
	if got.RootfsPath == "" {
		t.Fatalf("post-build RootfsPath empty")
	}
	if got.RootfsSizeBytes == 0 {
		t.Fatalf("post-build size = 0")
	}
	if got.HasSnapshot {
		t.Fatalf("post-build HasSnapshot = true, want false (no snapshotter)")
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

func TestCreateTemplateValidationAndIdentifierErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("builder missing", func(t *testing.T) {
		svc, _, _ := newTemplateHarness(t)
		_, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "docker://alpine"})
		if err == nil || !contains(err.Error(), "template builder is not configured") {
			t.Fatalf("CreateTemplate() error = %v, want missing builder", err)
		}
	})

	t.Run("blank image", func(t *testing.T) {
		svc, _, _ := newTemplateHarness(t)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{})
		_, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "   "})
		if err == nil || !contains(err.Error(), "image is required") {
			t.Fatalf("CreateTemplate() error = %v, want blank image rejection", err)
		}
	})

	t.Run("negative min size", func(t *testing.T) {
		svc, _, _ := newTemplateHarness(t)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{})
		_, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "docker://alpine", MinSizeMiB: -1})
		if err == nil || !contains(err.Error(), "min_size_mib must be >= 0") {
			t.Fatalf("CreateTemplate() error = %v, want min_size_mib rejection", err)
		}
	})

	t.Run("path traversal id", func(t *testing.T) {
		svc, _, _ := newTemplateHarness(t)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{})
		_, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "../outside", Image: "docker://alpine"})
		if err == nil || !contains(err.Error(), "template id must") {
			t.Fatalf("CreateTemplate() error = %v, want unsafe id rejection", err)
		}
	})
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

func TestDeleteTemplate_VMMReferenceRejected(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)
	now := time.Now().UTC()

	tpl := &models.Template{
		ID:         "tpl-vmm-busy",
		Image:      "docker://alpine:3.19",
		Status:     models.TemplateStatusReady,
		RootfsPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if err := st.InsertFirecrackerVMMSlot(ctx, store.FirecrackerVMMSlot{
		ID:         "vmms-busy",
		TemplateID: tpl.ID,
	}, now); err != nil {
		t.Fatalf("InsertFirecrackerVMMSlot: %v", err)
	}

	if err := svc.DeleteTemplate(ctx, tpl.ID); !errors.Is(err, store.ErrTemplateInUse) {
		t.Fatalf("DeleteTemplate vmm-ref error = %v, want ErrTemplateInUse", err)
	}
	if _, err := st.GetTemplate(ctx, tpl.ID); err != nil {
		t.Fatalf("template row should survive VMM reference: %v", err)
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
	warmDir := filepath.Join(templatesDir, "tpl-warm")
	if err := os.MkdirAll(warmDir, 0o755); err != nil {
		t.Fatalf("mkdir warmDir: %v", err)
	}
	warmPath := filepath.Join(warmDir, "rootfs.ext4")
	if err := os.WriteFile(warmPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write warm rootfs: %v", err)
	}
	mustInsert("tpl-warm", warmPath, now.Add(-48*time.Hour))
	if err := st.InsertFirecrackerVMMSlot(ctx, store.FirecrackerVMMSlot{
		ID:         "vmms-warm",
		TemplateID: "tpl-warm",
	}, now); err != nil {
		t.Fatalf("InsertFirecrackerVMMSlot: %v", err)
	}

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
	if _, err := os.Stat(warmPath); err != nil {
		t.Fatalf("VMM-referenced rootfs should survive: %v", err)
	}
	if _, err := st.GetTemplate(ctx, "tpl-warm"); err != nil {
		t.Fatalf("VMM-referenced row should survive: %v", err)
	}
}

func TestRunTemplateGCDuringStoreFailure(t *testing.T) {
	svc, st, _ := newTemplateHarness(t)
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
	svc.runTemplateGC(context.Background(), time.Now())
}

func TestRunTemplateGCEdgeBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		templatesDir := filepath.Join(dir, "templates")
		if err := os.MkdirAll(templatesDir, 0o755); err != nil {
			t.Fatalf("mkdir templates: %v", err)
		}
		svc := &Service{
			cfg: config.Config{
				EnableFirecracker:            true,
				FirecrackerTemplatesDir:      templatesDir,
				FirecrackerTemplateGCEnabled: true,
				FirecrackerTemplateGCTTL:     time.Hour,
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			store:  st,
		}
		tpl := &models.Template{
			ID:              "tpl-gc-ref",
			Image:           "docker://alpine:3.19",
			Status:          models.TemplateStatusReady,
			RootfsPath:      filepath.Join(templatesDir, "tpl-gc-ref", "rootfs.ext4"),
			RootfsSizeBytes: 1,
			CreatedAt:       time.Now().UTC().Add(-2 * time.Hour),
			UpdatedAt:       time.Now().UTC().Add(-2 * time.Hour),
		}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		dropSQLiteTable(t, dbPath, "sandboxes")
		svc.runTemplateGC(ctx, time.Now())
		if _, err := st.GetTemplate(ctx, tpl.ID); err != nil {
			t.Fatalf("template should remain after reference-check error: %v", err)
		}
	})

	t.Run("vmm reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		templatesDir := filepath.Join(dir, "templates")
		if err := os.MkdirAll(templatesDir, 0o755); err != nil {
			t.Fatalf("mkdir templates: %v", err)
		}
		svc := &Service{
			cfg: config.Config{
				EnableFirecracker:            true,
				FirecrackerTemplatesDir:      templatesDir,
				FirecrackerTemplateGCEnabled: true,
				FirecrackerTemplateGCTTL:     time.Hour,
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			store:  st,
		}
		tpl := &models.Template{
			ID:              "tpl-gc-vmm",
			Image:           "docker://alpine:3.19",
			Status:          models.TemplateStatusReady,
			RootfsPath:      filepath.Join(templatesDir, "tpl-gc-vmm", "rootfs.ext4"),
			RootfsSizeBytes: 1,
			CreatedAt:       time.Now().UTC().Add(-2 * time.Hour),
			UpdatedAt:       time.Now().UTC().Add(-2 * time.Hour),
		}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		dropSQLiteTable(t, dbPath, "firecracker_vmm_pool")
		svc.runTemplateGC(ctx, time.Now())
		if _, err := st.GetTemplate(ctx, tpl.ID); err != nil {
			t.Fatalf("template should remain after VMM reference-check error: %v", err)
		}
	})

	t.Run("cid release error", func(t *testing.T) {
		svc, st, templatesDir := newTemplateHarness(t)
		now := time.Now().UTC()
		tpl := &models.Template{
			ID:              "tpl-gc-release",
			Image:           "docker://alpine:3.19",
			Status:          models.TemplateStatusReady,
			RootfsPath:      filepath.Join(templatesDir, "tpl-gc-release", "rootfs.ext4"),
			RootfsSizeBytes: 1,
			HasSnapshot:     true,
			CreatedAt:       now.Add(-48 * time.Hour),
			UpdatedAt:       now.Add(-48 * time.Hour),
		}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		alloc := &fakeCIDAllocator{releaseErr: errors.New("release failed")}
		svc.SetTemplateCIDAllocator(alloc)
		svc.runTemplateGC(ctx, time.Now())
		alloc.mu.Lock()
		defer alloc.mu.Unlock()
		if len(alloc.releaseIDs) != 1 || alloc.releaseIDs[0] != tpl.ID {
			t.Fatalf("releaseIDs = %v, want [%q]", alloc.releaseIDs, tpl.ID)
		}
	})
}

func TestWriteTemplateManifestRejectsDirectoryPath(t *testing.T) {
	if err := writeTemplateManifest(t.TempDir(), templateManifest{
		SourceImage:      "docker://alpine:3.19",
		SnapshotChecksum: "sha256:deadbeef",
		VsockCID:         42,
		CreatedAt:        time.Now().UTC(),
	}); err == nil {
		t.Fatal("writeTemplateManifest should fail when asked to write to a directory")
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

// fakeTemplateSnapshotter is the test stub for the Phase 3 snapshot
// phase. Records the request, writes a few bytes to the snapshot
// artifact paths so the row's snapshot_size_bytes is non-zero, and
// signals on the done channel so tests can wait without sleeping.
// When `block` is non-nil it gates SnapshotTemplate's return — the
// test releases all in-flight rebuilds by closing the channel. This
// lets concurrency tests pin "rebuild stays in flight while N callers
// race" without depending on goroutine timing.
type fakeTemplateSnapshotter struct {
	mu      sync.Mutex
	calls   int
	lastReq TemplateSnapshotRequest
	err     error
	done    chan struct{}
	block   chan struct{}
}

func (f *fakeTemplateSnapshotter) SnapshotTemplate(_ context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error) {
	f.mu.Lock()
	f.calls++
	f.lastReq = req
	err := f.err
	block := f.block
	f.mu.Unlock()
	defer func() {
		if f.done != nil {
			f.done <- struct{}{}
		}
	}()
	if block != nil {
		<-block
	}
	if err != nil {
		return nil, err
	}
	if werr := os.WriteFile(req.OutMemoryPath, []byte("MEMORY"), 0o600); werr != nil {
		return nil, werr
	}
	if werr := os.WriteFile(req.OutStatePath, []byte("STATE"), 0o600); werr != nil {
		return nil, werr
	}
	return &TemplateSnapshotResult{
		MemorySizeBytes: 6,
		StateSizeBytes:  5,
		Checksum:        "sha256:dead|sha256:beef",
	}, nil
}

// fakeCIDAllocator records calls and returns either a canned CID or an
// error. The pool's per-id idempotency isn't modelled here; tests that
// need it can drive Allocate twice and compare the returned CIDs.
type fakeCIDAllocator struct {
	mu          sync.Mutex
	allocCalls  int
	releaseIDs  []string
	cid         uint32
	allocateErr error
	releaseErr  error
}

func (a *fakeCIDAllocator) AllocateForTemplate(_ context.Context, _ string) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allocCalls++
	if a.allocateErr != nil {
		return 0, a.allocateErr
	}
	return a.cid, nil
}

func (a *fakeCIDAllocator) ReleaseForTemplate(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseIDs = append(a.releaseIDs, id)
	return a.releaseErr
}

// waitForStatus polls the row until it reaches `want` or the deadline
// expires. Returns the last-read row regardless. Used so the snapshot
// tests don't have to coordinate two `done` channels (builder + snapshotter).
func waitForStatus(t *testing.T, st *store.Store, id string, want models.TemplateStatus, dl time.Duration) *models.Template {
	t.Helper()
	deadline := time.Now().Add(dl)
	var got *models.Template
	for time.Now().Before(deadline) {
		var err error
		got, err = st.GetTemplate(context.Background(), id)
		if err == nil && got != nil && got.Status == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return got
}

// TestCreateTemplate_TwoStageHappyPath drives both phases: builder OK,
// allocator returns a CID, snapshotter OK. Terminal status MUST be
// ready (not ready_no_snapshot), has_snapshot=true, snapshot fields
// populated. Confirms the snapshot phase sees the rootfs path the
// builder produced and the CID the allocator returned.
func TestCreateTemplate_TwoStageHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true
	svc.cfg.FirecrackerTemplateMemoryMB = 512
	svc.cfg.FirecrackerTemplateVCPU = 1

	svc.SetTemplateBuilder(&fakeTemplateBuilder{})
	snap := &fakeTemplateSnapshotter{}
	svc.SetTemplateSnapshotter(snap)
	alloc := &fakeCIDAllocator{cid: 42}
	svc.SetTemplateCIDAllocator(alloc)

	tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "tpl-two", Image: "docker://alpine:3.19"})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if tpl.Status != models.TemplateStatusPending {
		t.Fatalf("initial status = %s, want pending", tpl.Status)
	}

	got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReady, 5*time.Second)
	if got == nil || got.Status != models.TemplateStatusReady {
		t.Fatalf("post-build status = %v, want ready", got)
	}
	if !got.HasSnapshot {
		t.Errorf("HasSnapshot = false, want true")
	}
	if got.SnapshotMemoryPath != filepath.Join(templatesDir, "tpl-two", snapshotMemoryFilename) {
		t.Errorf("SnapshotMemoryPath = %q", got.SnapshotMemoryPath)
	}
	if got.SnapshotStatePath != filepath.Join(templatesDir, "tpl-two", snapshotStateFilename) {
		t.Errorf("SnapshotStatePath = %q", got.SnapshotStatePath)
	}
	if got.SnapshotChecksum != "sha256:dead|sha256:beef" {
		t.Errorf("SnapshotChecksum = %q", got.SnapshotChecksum)
	}
	if got.SnapshotVsockCID != 42 {
		t.Errorf("SnapshotVsockCID = %d, want 42", got.SnapshotVsockCID)
	}
	if got.SnapshotSizeBytes != 11 { // 6 (mem) + 5 (state)
		t.Errorf("SnapshotSizeBytes = %d, want 11", got.SnapshotSizeBytes)
	}
	// Snapshotter saw the rootfs the builder produced and the CID the
	// allocator returned.
	if snap.lastReq.RootfsPath == "" {
		t.Errorf("snapshotter RootfsPath empty")
	}
	if snap.lastReq.GuestCID != 42 {
		t.Errorf("snapshotter GuestCID = %d, want 42", snap.lastReq.GuestCID)
	}
	if snap.lastReq.MemoryMB != 512 || snap.lastReq.VCPU != 1 {
		t.Errorf("snapshotter resources = %d MiB / %d vCPU, want 512/1", snap.lastReq.MemoryMB, snap.lastReq.VCPU)
	}
	// manifest.json must be on disk for operator debugging.
	if _, err := os.Stat(filepath.Join(templatesDir, "tpl-two", templateManifestFilename)); err != nil {
		t.Errorf("manifest.json not written: %v", err)
	}
}

// TestCreateTemplate_SnapshotFailFallsBackToReadyNoSnapshot is the
// degraded path: builder OK, allocator OK, snapshotter returns error.
// Terminal status MUST be ready_no_snapshot, snapshot_error populated,
// CID released so a future retry can re-allocate, rootfs untouched.
func TestCreateTemplate_SnapshotFailFallsBackToReadyNoSnapshot(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true

	svc.SetTemplateBuilder(&fakeTemplateBuilder{})
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{err: errors.New("vmm boot timed out")})
	alloc := &fakeCIDAllocator{cid: 17}
	svc.SetTemplateCIDAllocator(alloc)

	tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "tpl-snapfail", Image: "docker://alpine:3.19"})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReadyNoSnapshot, 5*time.Second)
	if got == nil || got.Status != models.TemplateStatusReadyNoSnapshot {
		t.Fatalf("post-build status = %v, want ready_no_snapshot", got)
	}
	if got.HasSnapshot {
		t.Errorf("HasSnapshot = true, want false on snapshot failure")
	}
	if got.SnapshotError == "" {
		t.Errorf("SnapshotError empty, want populated")
	}
	if got.RootfsPath == "" {
		t.Errorf("RootfsPath empty, rootfs phase succeeded")
	}
	// CID must be released exactly once — the next CreateTemplate retry
	// would otherwise drain the pool.
	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	if len(alloc.releaseIDs) != 1 || alloc.releaseIDs[0] != tpl.ID {
		t.Errorf("releaseIDs = %v, want [%q]", alloc.releaseIDs, tpl.ID)
	}
}

// TestCreateTemplate_CIDAllocFailFallsBackToReadyNoSnapshot is the
// path where the snapshot phase never even starts: builder OK,
// allocator returns error. Terminal status MUST be ready_no_snapshot,
// snapshot_error populated with the allocator error, snapshotter MUST
// NOT have been called (no CID = no VMM).
func TestCreateTemplate_CIDAllocFailFallsBackToReadyNoSnapshot(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true

	svc.SetTemplateBuilder(&fakeTemplateBuilder{})
	snap := &fakeTemplateSnapshotter{}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{allocateErr: errors.New("pool exhausted")})

	tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "tpl-cidfail", Image: "docker://alpine:3.19"})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReadyNoSnapshot, 5*time.Second)
	if got == nil || got.Status != models.TemplateStatusReadyNoSnapshot {
		t.Fatalf("post-build status = %v, want ready_no_snapshot", got)
	}
	if got.HasSnapshot {
		t.Errorf("HasSnapshot = true, want false")
	}
	if got.SnapshotError == "" || !contains(got.SnapshotError, "pool exhausted") {
		t.Errorf("SnapshotError = %q, want to include 'pool exhausted'", got.SnapshotError)
	}
	snap.mu.Lock()
	defer snap.mu.Unlock()
	if snap.calls != 0 {
		t.Errorf("snapshotter calls = %d, want 0 (cid alloc failed first)", snap.calls)
	}
}

func TestCreateTemplateEdgeBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("store create error", func(t *testing.T) {
		svc, st, _ := newTemplateHarness(t)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{})
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if _, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "docker://alpine:3.19"}); err == nil {
			t.Fatal("closed store should fail CreateTemplate")
		}
	})

	t.Run("template id generation error", func(t *testing.T) {
		old := crand.Reader
		crand.Reader = &scriptedRandReader{errs: []error{errors.New("rand down")}}
		t.Cleanup(func() { crand.Reader = old })

		svc, _, _ := newTemplateHarness(t)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{})
		if _, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "docker://alpine:3.19"}); err == nil || !contains(err.Error(), "rand down") {
			t.Fatalf("CreateTemplate random failure = %v, want rand down", err)
		}
	})

	t.Run("build side effects with closed store and manifest dir", func(t *testing.T) {
		svc, st, templatesDir := newTemplateHarness(t)
		done := make(chan struct{}, 1)
		builder := &fakeTemplateBuilder{done: done}
		svc.SetTemplateBuilder(builder)

		tplDir := filepath.Join(templatesDir, "tpl-build-edge")
		if err := os.MkdirAll(filepath.Join(tplDir, templateManifestFilename), 0o755); err != nil {
			t.Fatalf("mkdir manifest dir: %v", err)
		}

		tpl, err := svc.CreateTemplate(ctx, models.CreateTemplateRequest{ID: "tpl-build-edge", Image: "docker://alpine:3.19"})
		if err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("builder never ran")
		}
		if builder.calls != 1 {
			t.Fatalf("builder calls = %d, want 1", builder.calls)
		}
		if tpl.ID != "tpl-build-edge" {
			t.Fatalf("template ID = %q, want tpl-build-edge", tpl.ID)
		}
	})
}

// TestDeleteTemplate_ReleasesCID pins the cleanup contract: deleting a
// template with has_snapshot=true releases the per-template CID, so a
// later CreateTemplate against the same id can re-reserve it.
func TestDeleteTemplate_ReleasesCID(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)

	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-cid-del", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady,
		// Provide a fake rootfs path under a tmp dir we own so the
		// service's RemoveAll cleanup doesn't try to nuke /tmp/tpl-foo.
		RootfsPath:       filepath.Join(t.TempDir(), "rootfs.ext4"),
		HasSnapshot:      true,
		SnapshotVsockCID: 99,
		CreatedAt:        time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	alloc := &fakeCIDAllocator{}
	svc.SetTemplateCIDAllocator(alloc)

	if err := svc.DeleteTemplate(ctx, "tpl-cid-del"); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	if len(alloc.releaseIDs) != 1 || alloc.releaseIDs[0] != "tpl-cid-del" {
		t.Errorf("releaseIDs = %v, want [tpl-cid-del]", alloc.releaseIDs)
	}
}

func TestDeleteTemplateEdgeBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		templatesDir := filepath.Join(dir, "templates")
		if err := os.MkdirAll(templatesDir, 0o755); err != nil {
			t.Fatalf("mkdir templates: %v", err)
		}
		svc := &Service{
			cfg: config.Config{
				EnableFirecracker:       true,
				FirecrackerTemplatesDir: templatesDir,
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			store:  st,
		}
		tpl := &models.Template{
			ID:         "tpl-del-ref",
			Image:      "docker://alpine:3.19",
			Status:     models.TemplateStatusReady,
			RootfsPath: filepath.Join(templatesDir, "tpl-del-ref", "rootfs.ext4"),
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		dropSQLiteTable(t, dbPath, "sandboxes")
		if err := svc.DeleteTemplate(ctx, tpl.ID); err == nil {
			t.Fatal("dropping sandboxes table should fail DeleteTemplate")
		}
	})

	t.Run("vmm reference check error", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		templatesDir := filepath.Join(dir, "templates")
		if err := os.MkdirAll(templatesDir, 0o755); err != nil {
			t.Fatalf("mkdir templates: %v", err)
		}
		svc := &Service{
			cfg: config.Config{
				EnableFirecracker:       true,
				FirecrackerTemplatesDir: templatesDir,
			},
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			store:  st,
		}
		tpl := &models.Template{
			ID:         "tpl-del-vmm",
			Image:      "docker://alpine:3.19",
			Status:     models.TemplateStatusReady,
			RootfsPath: filepath.Join(templatesDir, "tpl-del-vmm", "rootfs.ext4"),
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate: %v", err)
		}
		dropSQLiteTable(t, dbPath, "firecracker_vmm_pool")
		if err := svc.DeleteTemplate(ctx, tpl.ID); err == nil {
			t.Fatal("dropping firecracker_vmm_slots should fail DeleteTemplate")
		}
	})
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
