package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

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

func TestEnsureSandboxAwakeArmsWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()

	started := &models.Sandbox{
		ID: "sb-awake-started", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, started); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-started"); err != nil {
		t.Fatalf("already started: %v", err)
	}

	destroying := &models.Sandbox{
		ID: "sb-awake-other", Image: "a", Status: models.SandboxStatusError,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, destroying); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-other"); err != nil {
		t.Fatalf("non-stopped: %v", err)
	}

	stoppedPlain := &models.Sandbox{
		ID: "sb-awake-plain", Image: "a", Status: models.SandboxStatusStopped,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, stoppedPlain); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-plain"); err != nil {
		t.Fatalf("non-serverless stopped: %v", err)
	}

	disarmed := &models.Sandbox{
		ID: "sb-awake-disarm", Image: "a", Status: models.SandboxStatusStopped,
		WakeArmed: false, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, disarmed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-disarm"); !errors.Is(err, ErrSandboxManuallyStopped) {
		t.Fatalf("disarmed = %v", err)
	}

	// Trip circuit: record failures then expect ErrWakeCircuitOpen.
	armed := &models.Sandbox{
		ID: "sb-awake-circ", Image: "a", Status: models.SandboxStatusStopped,
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, armed); err != nil {
		t.Fatal(err)
	}
	flight := svc.wakeFlightFor("sb-awake-circ")
	flight.mu.Lock()
	for i := 0; i < 8; i++ {
		flight.recordFailure(time.Now())
	}
	flight.mu.Unlock()
	if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-awake-circ"); !errors.Is(err, ErrWakeCircuitOpen) {
		t.Fatalf("circuit = %v", err)
	}
}

func TestStartL4WakeProxyIdempotentAndAcceptWave9(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	svc.cfg.InternalL4WakeAddr = addr
	if err := svc.StartL4WakeProxy(ctx); err != nil {
		t.Fatalf("StartL4WakeProxy: %v", err)
	}
	// Second call hits already-listening arm.
	if err := svc.StartL4WakeProxy(ctx); err != nil {
		t.Fatalf("idempotent StartL4WakeProxy: %v", err)
	}
	// Empty addr no-op.
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableServerless = true
	svc2.cfg.EnableCaddy = true
	svc2.cfg.InternalL4WakeAddr = ""
	if err := svc2.StartL4WakeProxy(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWasmMigrateErrorArmsWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true

	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil {
		t.Fatal("expected wasm nil")
	}
	svc.SetWasmRuntime(&recordingRuntime{}) // does not implement MigrationHost
	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil || !strings.Contains(err.Error(), "does not implement migration") {
		t.Fatalf("err = %v", err)
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-docker", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Export checks wasm configured then Get+isWasm before migrate.
	if _, err := svc.ExportWasmMigration(ctx, "sb-docker", io.Discard); err == nil || !strings.Contains(err.Error(), "not wasm") {
		t.Fatalf("export non-wasm = %v", err)
	}

	svc.cfg.EnableWasm = false
	if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err != nil {
		t.Fatal(err)
	}
	svc.cfg.EnableWasm = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-ev", Image: "m", Runtime: models.RuntimeWasm,
		Durability: models.DurabilityDurable, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_ = svc.EvacuateLocalWasmSandboxesForDrain(ctx)
}

func TestCreateSandboxMountAllFailWave9(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.admitter = nil
	svc.cipher = newTestCipher(t)
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
		Mounts: []models.MountSpec{{
			Type: models.MountTypeS3, Source: "bucket/key", Target: "/data",
		}},
	}, "sb-mnt-fail")
	if err == nil || !strings.Contains(err.Error(), "mount") {
		t.Fatalf("err = %v, want mount failure", err)
	}
}

func TestStopSandboxInternalAndForceReconcileWave9(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-stop-int", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP:  "10.0.0.1",
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.stopSandboxInternal(ctx, "sb-stop-int", stopModeLifecycle); err != nil {
		t.Fatalf("stopSandboxInternal: %v", err)
	}
	_ = svc.ForceReconcileHTTPWakeShape(ctx)
}

func TestCreateSandboxPutAttachmentsRollbackViaHookWave9(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.admitter = nil
	svc.testForcePlatformAttachments = []models.VolumeAttachment{{
		Tenant: "op", VolumeID: "vol-x", Target: "/data", Source: "s3://b/v",
	}}
	svc.testAfterStoreCreate = func() { _ = svc.store.Close() }
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-putatt")
	if err == nil || !strings.Contains(err.Error(), "persist platform volume attachments") {
		t.Fatalf("err = %v, want PutAttachments rollback", err)
	}
}

func TestPlatformVolumesResolveErrorsWave9(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "../bad", Path: "/data"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil {
		t.Fatal("expected sanitize name failure")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no vol id")}})
	req2 := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &req2, models.RuntimeDocker); err == nil {
		t.Fatal("expected volume id entropy failure")
	}
}
