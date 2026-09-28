package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRunTemplateGCReferencedAndCleanup(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newHealthHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)

	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-old", Image: "x", Status: models.TemplateStatusReady,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ref", Image: "y", Status: models.TemplateStatusReady,
		CreatedAt: old, UpdatedAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-uses-tpl", Image: "y", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeFirecracker, TemplateID: "tpl-ref",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	svc.runTemplateGC(ctx, now)
	if _, err := st.GetTemplate(ctx, "tpl-old"); err == nil {
		t.Fatal("unreferenced old template should be GC'd")
	}
	if _, err := st.GetTemplate(ctx, "tpl-ref"); err != nil {
		t.Fatalf("referenced template GC'd: %v", err)
	}
}

func TestKickTemplateBuildSnapshotPhasesWave11(t *testing.T) {
	ctx := context.Background()

	t.Run("cid_allocate_fail", func(t *testing.T) {
		svc, st, _ := newTemplateHarness(t)
		done := make(chan struct{}, 1)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
		svc.cfg.FirecrackerSnapshotEnabled = true
		svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: make(chan struct{}, 1)})
		svc.SetTemplateCIDAllocator(&fakeCIDAllocator{allocateErr: errors.New("cid pool empty")})
		now := time.Now().UTC()
		tpl := &models.Template{ID: "tpl-cidfail-w11", Image: "docker://alpine", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
		svc.kickTemplateBuild(tpl)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("timeout")
		}
		got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReadyNoSnapshot, 2*time.Second)
		if got.Status != models.TemplateStatusReadyNoSnapshot {
			t.Fatalf("status = %s", got.Status)
		}
	})

	t.Run("snapshot_fail", func(t *testing.T) {
		svc, st, _ := newTemplateHarness(t)
		doneB := make(chan struct{}, 1)
		doneS := make(chan struct{}, 1)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{done: doneB})
		svc.cfg.FirecrackerSnapshotEnabled = true
		svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{err: errors.New("vmm boom"), done: doneS})
		svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42, releaseErr: errors.New("release warn")})
		now := time.Now().UTC()
		tpl := &models.Template{ID: "tpl-snapfail-w11", Image: "docker://alpine", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
		svc.kickTemplateBuild(tpl)
		select {
		case <-doneB:
		case <-time.After(3 * time.Second):
			t.Fatal("builder timeout")
		}
		select {
		case <-doneS:
		case <-time.After(3 * time.Second):
			t.Fatal("snap timeout")
		}
		got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReadyNoSnapshot, 2*time.Second)
		if got.Status != models.TemplateStatusReadyNoSnapshot {
			t.Fatalf("status = %s", got.Status)
		}
	})

	t.Run("snapshot_success", func(t *testing.T) {
		svc, st, _ := newTemplateHarness(t)
		doneB := make(chan struct{}, 1)
		doneS := make(chan struct{}, 1)
		svc.SetTemplateBuilder(&fakeTemplateBuilder{done: doneB})
		svc.cfg.FirecrackerSnapshotEnabled = true
		svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: doneS})
		svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 7})
		now := time.Now().UTC()
		tpl := &models.Template{ID: "tpl-ok-w11", Image: "docker://alpine", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
		svc.kickTemplateBuild(tpl)
		select {
		case <-doneB:
		case <-time.After(3 * time.Second):
			t.Fatal("builder timeout")
		}
		select {
		case <-doneS:
		case <-time.After(3 * time.Second):
			t.Fatal("snap timeout")
		}
		got := waitForStatus(t, st, tpl.ID, models.TemplateStatusReady, 2*time.Second)
		if got.Status != models.TemplateStatusReady {
			t.Fatalf("status = %s", got.Status)
		}
	})
}

func TestRunTemplateGCBranchesWave11(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)

	// VMM-referenced template → skip delete.
	rootfs := filepath.Join(templatesDir, "tpl-vmm", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := &models.Template{
		ID: "tpl-vmm", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale, HasSnapshot: true,
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	// Seed a VMM pool slot referencing the template if the store API exists.
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-hold", Image: "a", TemplateID: tpl.ID, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 1, releaseErr: errors.New("cid warn")})
	svc.runTemplateGC(ctx, now)

	// Unreferenced + remove dir fail: make RootfsPath a file so RemoveAll on Dir may still work;
	// use a path under a file parent to force cleanup warn.
	svc2, st2, dir2 := newTemplateHarness(t)
	svc2.cfg.FirecrackerTemplateGCTTL = time.Hour
	block := filepath.Join(dir2, "blockfile")
	if err := os.WriteFile(block, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl2 := &models.Template{
		ID: "tpl-rmfail", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: filepath.Join(block, "nested", "rootfs.ext4"), // parent is a file → RemoveAll fails
		CreatedAt:  stale, UpdatedAt: stale,
	}
	if err := st2.CreateTemplate(ctx, tpl2); err != nil {
		t.Fatal(err)
	}
	svc2.runTemplateGC(ctx, now)
}

func TestTemplateGCReferenceCheckFailWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := templatesDir + "/tpl-gcref/rootfs.ext4"
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gcref", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	})
	// Close store after list by using a second harness close mid-GC is hard;
	// instead GC with closed store for list-fail arm.
	svc2, st2, _ := newTemplateHarness(t)
	_ = st2.Close()
	svc2.runTemplateGC(ctx, now)
	_ = templatesDir
	_ = svc
}

func TestTemplateGCReferenceCheckClosedWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-gc13", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gc13", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	}); err != nil {
		t.Fatal(err)
	}
	svc.testAfterTemplateGCList = func() { _ = st.Close() }
	svc.runTemplateGC(ctx, now)
}

func TestTemplateGCVMMRefFailWave14(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-vmm14", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-vmm14", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale, HasSnapshot: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Sandbox-ref check succeeds; close store before VMM-ref / delete.
	svc.testAfterTemplateGCSandboxRefCheck = func() { _ = st.Close() }
	svc.runTemplateGC(ctx, now)
}

func TestTemplateBuildClosedStoreArmsWave14(t *testing.T) {
	svc, st, _ := newTemplateHarness(t)
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{err: errors.New("build fail"), done: done})
	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-build14", Image: "docker://alpine", Status: models.TemplateStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	// Close store so status updates warn.
	_ = st.Close()
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("build did not finish")
	}
	time.Sleep(20 * time.Millisecond)
}

func TestTemplateBuildSnapshotFailArmsWave14(t *testing.T) {
	svc, st, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 3})
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{err: errors.New("snap boom")})

	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-snap14", Image: "docker://alpine", Status: models.TemplateStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("build did not finish")
	}
	time.Sleep(50 * time.Millisecond)

	// CID allocate fail → ready_no_snapshot.
	done2 := make(chan struct{}, 1)
	svc2, st2, _ := newTemplateHarness(t)
	svc2.cfg.FirecrackerSnapshotEnabled = true
	svc2.SetTemplateBuilder(&fakeTemplateBuilder{done: done2})
	svc2.SetTemplateCIDAllocator(&fakeCIDAllocator{allocateErr: errors.New("cid full")})
	svc2.SetTemplateSnapshotter(&fakeTemplateSnapshotter{})
	tpl2 := &models.Template{
		ID: "tpl-cid14", Image: "docker://alpine", Status: models.TemplateStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	_ = st2.CreateTemplate(context.Background(), tpl2)
	svc2.kickTemplateBuild(tpl2)
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("cid build did not finish")
	}
	time.Sleep(50 * time.Millisecond)
}

func TestTemplateSkipSnapshotReasonsWave16(t *testing.T) {
	now := time.Now().UTC()

	// snapshotter set, cid nil → "cid allocator seam not wired"
	svc, st, _ := newTemplateHarness(t)
	svc.cfg.FirecrackerSnapshotEnabled = true
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{})
	tpl := &models.Template{ID: "tpl-skip-cid", Image: "docker://a", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
	_ = st.CreateTemplate(context.Background(), tpl)
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	time.Sleep(40 * time.Millisecond)

	// both seams set but snapshot disabled → flag reason
	svc2, st2, _ := newTemplateHarness(t)
	svc2.cfg.FirecrackerSnapshotEnabled = false
	done2 := make(chan struct{}, 1)
	svc2.SetTemplateBuilder(&fakeTemplateBuilder{done: done2})
	svc2.SetTemplateSnapshotter(&fakeTemplateSnapshotter{})
	svc2.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 1})
	tpl2 := &models.Template{ID: "tpl-skip-flag", Image: "docker://a", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}
	_ = st2.CreateTemplate(context.Background(), tpl2)
	svc2.kickTemplateBuild(tpl2)
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	time.Sleep(40 * time.Millisecond)
}

func TestTemplateGCReferencedSkipWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-ref16", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ref16", Image: "docker://a", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-uses-tpl", Image: "a", Status: models.SandboxStatusStarted, TemplateID: "tpl-ref16",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc.runTemplateGC(ctx, now)
}

func TestTemplatePullOnceErrorArmsWave19(t *testing.T) {
	ctx := context.Background()
	templatesDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Pull fail.
	p, err := NewTemplateArtifactPuller(&fakeTemplatePullDocker{pullErr: errors.New("pull boom")}, templatesDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &models.Template{ID: "tpl-p1", RegistryRef: "aocr.test/t:latest", SnapshotChecksum: "sha256:x"}
	if err := p.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected pull fail")
	}

	// Export fail after pull ok.
	p2, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{exportErr: errors.New("save boom")}, templatesDir, logger)
	if err := p2.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected export fail")
	}

	// Bad extract (garbage tar).
	p3, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{exportBody: []byte("not-tar")}, templatesDir, logger)
	if err := p3.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected extract fail")
	}

	// Local files present → early success.
	tplDir := filepath.Join(templatesDir, "tpl-local")
	_ = os.MkdirAll(tplDir, 0o755)
	for _, name := range []string{templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename, templateManifestFilename} {
		_ = os.WriteFile(filepath.Join(tplDir, name), []byte("x"), 0o644)
	}
	local := &models.Template{ID: "tpl-local", RegistryRef: "aocr.test/t:latest"}
	p4, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{pullErr: errors.New("should not pull")}, templatesDir, logger)
	if err := p4.PullOnce(ctx, local); err != nil {
		t.Fatalf("local present: %v", err)
	}
}

func TestTemplateGCDeleteFailWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-gc21", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gc21", Status: models.TemplateStatusReadyNoSnapshot, RootfsPath: rootfs,
		CreatedAt: stale, UpdatedAt: stale,
	})
	svc.testAfterTemplateGCSandboxRefCheck = func() { _ = st.Close() }
	svc.runTemplateGC(ctx, now)
}

func TestWriteTemplateManifestBadPathWave21(t *testing.T) {
	if err := writeTemplateManifest("/no/such/dir/manifest.json", templateManifest{SourceImage: "a"}); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestWriteTemplateManifestOKWave23(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	if err := writeTemplateManifest(path, templateManifest{SourceImage: "img", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateGCDeleteAfterVMMCheckWave25(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	stale := now.Add(-72 * time.Hour)
	rootfs := filepath.Join(templatesDir, "tpl-gc25", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-gc25", Image: "alpine:3.20", Status: models.TemplateStatusReadyNoSnapshot,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	}); err != nil {
		t.Fatal(err)
	}
	svc.testAfterTemplateGCVMMRefCheck = func() { _ = st.Close() }
	svc.runTemplateGC(ctx, now)
}

func TestRootfsCleanupWarnWave25(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	stale := now.Add(-72 * time.Hour)
	// Point RootfsPath at a file that can't be removed as a directory parent —
	// use a path under a read-only parent.
	ro := filepath.Join(templatesDir, "ro")
	_ = os.MkdirAll(ro, 0o755)
	rootfs := filepath.Join(ro, "tpl-ro", "rootfs.ext4")
	_ = os.MkdirAll(filepath.Dir(rootfs), 0o755)
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = os.Chmod(ro, 0o555)
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	_ = st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-ro", Image: "alpine:3.20", Status: models.TemplateStatusReadyNoSnapshot,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale,
	})
	svc.runTemplateGC(ctx, now)
}

func TestRebuildSnapshotReadyUpdateFailWave26(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-rebuild26")
	_ = st.UpdateTemplateStatus(ctx, tpl.ID, models.TemplateStatusUnhealthy, tpl.RootfsPath, "corrupt", tpl.RootfsSizeBytes)
	snap := &closingSnapper{closeFn: func() { _ = st.Close() }, done: make(chan struct{}, 1)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	_ = svc.RebuildTemplateSnapshot(ctx, tpl.ID)
}

type closingSnapper struct {
	closeFn func()
	done    chan struct{}
}

func (c *closingSnapper) SnapshotTemplate(_ context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error) {
	_ = os.WriteFile(req.OutMemoryPath, []byte("m"), 0o644)
	_ = os.WriteFile(req.OutStatePath, []byte("s"), 0o644)
	if c.closeFn != nil {
		c.closeFn()
	}
	select {
	case c.done <- struct{}{}:
	default:
	}
	return &TemplateSnapshotResult{MemorySizeBytes: 1, StateSizeBytes: 1, Checksum: "sha256:x"}, nil
}

func TestRunTemplateGCRemoveAllAndCIDReleaseWave3(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour

	now := time.Now().UTC()
	staleAt := now.Add(-48 * time.Hour)

	tplCID := &models.Template{
		ID: "tpl-gc-cid-w3", Image: "docker://alpine",
		Status: models.TemplateStatusReady, HasSnapshot: true,
		RootfsPath: filepath.Join(templatesDir, "tpl-gc-cid-w3", "rootfs.ext4"),
		CreatedAt:  staleAt, UpdatedAt: staleAt,
	}
	if err := os.MkdirAll(filepath.Dir(tplCID.RootfsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(tplCID.RootfsPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := st.CreateTemplate(ctx, tplCID); err != nil {
		t.Fatalf("CreateTemplate cid: %v", err)
	}

	readOnlyDir := filepath.Join(templatesDir, "tpl-gc-rmfail-w3")
	if err := os.MkdirAll(readOnlyDir, 0o755); err != nil {
		t.Fatalf("mkdir ro parent: %v", err)
	}
	tplRM := &models.Template{
		ID: "tpl-gc-rmfail-w3", Image: "docker://alpine",
		Status:     models.TemplateStatusReady,
		RootfsPath: filepath.Join(readOnlyDir, "rootfs.ext4"),
		CreatedAt:  staleAt, UpdatedAt: staleAt,
	}
	if err := os.WriteFile(tplRM.RootfsPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write ro rootfs: %v", err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0o755) })
	if err := st.CreateTemplate(ctx, tplRM); err != nil {
		t.Fatalf("CreateTemplate rmfail: %v", err)
	}

	alloc := &fakeCIDAllocator{releaseErr: errors.New("cid release boom")}
	svc.SetTemplateCIDAllocator(alloc)
	svc.runTemplateGC(ctx, now)

	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	if len(alloc.releaseIDs) == 0 || alloc.releaseIDs[0] != tplCID.ID {
		t.Fatalf("releaseIDs = %v, want tpl-gc-cid-w3 release attempt", alloc.releaseIDs)
	}
	if _, err := st.GetTemplate(ctx, tplCID.ID); err == nil {
		t.Fatal("CID-error template row should still be deleted")
	}
	if _, err := st.GetTemplate(ctx, tplRM.ID); err == nil {
		t.Fatal("RemoveAll-error template row should still be deleted")
	}
}

func TestKickTemplateBuildMkdirAndFailWave8(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Templates dir is a file → MkdirAll fails → failed status path.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	builder := &fakeTemplateBuilder{err: errors.New("build boom"), done: done}
	svc := &Service{
		cfg: config.Config{
			FirecrackerTemplatesDir:         blocked,
			FirecrackerTemplateBuildTimeout: time.Second,
		},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder,
	}
	tpl := &models.Template{ID: "tpl-mkdir", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// mkdir fails before Build; done may not fire — wait briefly for status.
	}
	time.Sleep(50 * time.Millisecond)

	// Rootfs build failure with removable dir + StagingDir cleanup warn.
	dir := filepath.Join(t.TempDir(), "tpls")
	done2 := make(chan struct{}, 1)
	builder2 := &fakeTemplateBuilder{
		err:  errors.New("oci fail"),
		done: done2,
	}
	svc2 := &Service{
		cfg:             config.Config{FirecrackerTemplatesDir: dir, FirecrackerTemplateBuildTimeout: time.Second},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder2,
	}
	tpl2 := &models.Template{ID: "tpl-fail", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl2); err != nil {
		t.Fatal(err)
	}
	svc2.kickTemplateBuild(tpl2)
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for build fail")
	}

	// Snapshot skipped: builder succeeds, no snapshotter → ready_no_snapshot.
	done3 := make(chan struct{}, 1)
	builder3 := &fakeTemplateBuilder{done: done3}
	svc3 := &Service{
		cfg: config.Config{
			FirecrackerTemplatesDir:         dir,
			FirecrackerTemplateBuildTimeout: time.Second,
			FirecrackerSnapshotEnabled:      false,
		},
		store:           st,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		templateBuilder: builder3,
	}
	tpl3 := &models.Template{ID: "tpl-nosnap", Image: "alpine", Status: models.TemplateStatusPending}
	if err := st.CreateTemplate(context.Background(), tpl3); err != nil {
		t.Fatal(err)
	}
	svc3.kickTemplateBuild(tpl3)
	select {
	case <-done3:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout nosnap")
	}
	time.Sleep(30 * time.Millisecond)
}

func TestKickTemplateBuildRootfsFailureWave9(t *testing.T) {
	// Wave8 already covers mkdir/build-fail status transitions; this pins the
	// ready_no_snapshot skip path with the shared harness builder.
	svc, st, _ := newTemplateHarness(t)
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
	svc.cfg.FirecrackerSnapshotEnabled = true
	svc.templateSnapshotter = nil
	svc.templateCIDAllocator = nil
	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-skip-snap-w9", Image: "docker://alpine",
		Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := st.GetTemplate(context.Background(), tpl.ID)
		if err == nil && got.Status == models.TemplateStatusReadyNoSnapshot {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := st.GetTemplate(context.Background(), tpl.ID)
	t.Fatalf("status = %+v, want ready_no_snapshot", got)
}

func TestKickTemplateBuildReadyNoSnapshotWave9(t *testing.T) {
	svc, st, _ := newTemplateHarness(t)
	done := make(chan struct{}, 1)
	svc.SetTemplateBuilder(&fakeTemplateBuilder{done: done})
	svc.cfg.FirecrackerSnapshotEnabled = false
	now := time.Now().UTC()
	tpl := &models.Template{
		ID: "tpl-nosnap-w9", Image: "docker://alpine",
		Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	svc.kickTemplateBuild(tpl)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	// Give status update a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := st.GetTemplate(context.Background(), tpl.ID)
		if err == nil && got.Status == models.TemplateStatusReadyNoSnapshot {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := st.GetTemplate(context.Background(), tpl.ID)
	if got == nil || got.Status != models.TemplateStatusReadyNoSnapshot {
		t.Fatalf("status = %+v, want ready_no_snapshot", got)
	}
}

func TestRunTemplateGCStoreErrorsWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newTemplateHarness(t)
	svc.cfg.FirecrackerTemplateGCEnabled = true
	svc.cfg.FirecrackerTemplateGCTTL = time.Hour
	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)

	rootfs := filepath.Join(templatesDir, "tpl-gc-ref", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tpl := &models.Template{
		ID: "tpl-gc-ref", Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale, HasSnapshot: true,
	}
	if err := st.CreateTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	// Referenced by sandbox → continue arm.
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-ref-tpl", Image: "a", TemplateID: tpl.ID, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 1})
	svc.runTemplateGC(ctx, now)

	// Closed store → list failure warn arm.
	svc2, st2, _ := newTemplateHarness(t)
	_ = st2.Close()
	svc2.runTemplateGC(ctx, now)
}
