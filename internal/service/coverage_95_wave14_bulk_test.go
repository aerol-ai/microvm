package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestBuiltImageGCRefAndRemoveFailWave14(t *testing.T) {
	ctx := context.Background()
	old := time.Now().UTC().Add(-2 * time.Hour)

	// HasActiveImageRef fails after list returns (close store from list fn).
	svc, st, _ := newBuiltImageGCHarness(t, time.Hour)
	svc.runBuiltImageGC(ctx, func(context.Context) ([]docker.BuiltImage, error) {
		_ = st.Close()
		return []docker.BuiltImage{{Tag: "aerolvm-build/ref-fail:latest", LastTagTime: old}}, nil
	})

	// RemoveImage failure arm.
	svc2, _, _ := newBuiltImageGCHarness(t, time.Hour)
	svc2.docker = &recordingRemoveRuntime{removed: &[]string{}, removeErr: errors.New("rm boom")}
	svc2.runBuiltImageGC(ctx, func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: "aerolvm-build/rm-fail:latest", LastTagTime: old}}, nil
	})

	// StartBuiltImageGC: enabled + interval + nil dockerAux warn.
	svc3, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc3.cfg.ImageBuildGCEnabled = true
	svc3.cfg.ImageBuildGCInterval = time.Millisecond
	svc3.dockerAux = nil
	svc3.StartBuiltImageGC(ctx)

	// StartBuiltImageGC with dockerAux set starts the loop briefly.
	svc4, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc4.cfg.ImageBuildGCEnabled = true
	svc4.cfg.ImageBuildGCInterval = time.Millisecond
	svc4.SetDockerAuxClient(&docker.Client{})
	loopCtx, cancel := context.WithCancel(ctx)
	svc4.StartBuiltImageGC(loopCtx)
	cancel()
}

func TestPendingImageGCClosedAfterListWave14(t *testing.T) {
	ctx := context.Background()
	old := time.Now().UTC().Add(-2 * time.Hour)

	// Whitelist clear fail after list.
	svc, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc.cfg.ImageGCWhitelist = []string{"keep/me:latest"}
	seedPending(t, st, "keep/me:latest", old)
	svc.testAfterPendingImageGCList = func() { _ = st.Close() }
	svc.runPendingImageGC(ctx)

	// Ref-check fail (no whitelist).
	svc2, st2, _, _ := newPendingImageGCHarness(t, time.Hour)
	seedPending(t, st2, "orphan:latest", old)
	svc2.testAfterPendingImageGCList = func() { _ = st2.Close() }
	svc2.runPendingImageGC(ctx)

	// Referenced → DeletePendingImageGC fail after close mid-loop is hard;
	// hit referenced clear warn by closing after list while sandbox holds ref.
	svc3, st3, _, _ := newPendingImageGCHarness(t, time.Hour)
	seedPending(t, st3, "alive:latest", old)
	now := time.Now().UTC()
	_ = st3.Create(ctx, &models.Sandbox{
		ID: "sb-alive", Image: "alive:latest", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc3.testAfterPendingImageGCList = func() { _ = st3.Close() }
	svc3.runPendingImageGC(ctx)
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

func TestUpdateLifecycleServerlessFlipWave14(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-lc-flip", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle:    models.Lifecycle{},
		ExposedPorts: []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UpdateLifecycle(ctx, "sb-lc-flip", models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute})
	if err != nil {
		t.Fatalf("UpdateLifecycle: %v", err)
	}

	// Closed-store UpdateLifecycle after Get.
	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_ = st2.Create(ctx, &models.Sandbox{
		ID: "sb-lc-close", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc2.testAfterStoreCreate = nil
	// Close between scopedGet and UpdateLifecycle by racing: close then update.
	_ = st2.Close()
	_, _ = svc2.UpdateLifecycle(ctx, "sb-lc-close", models.Lifecycle{StopIfIdleFor: time.Hour})
}

func TestEnsureClusterReadyUnderLockWave14(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", "h"))
	svc.clusterReady.Store(false)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.EnsureClusterReady(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("EnsureClusterReady: %v", err)
		}
	}
}

func TestApplyInFluxRouteDomainErrorsWave14(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	t.Cleanup(fail.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	p := cluster.Placement{
		SandboxID: "sb-influx",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			80:  {Protocol: models.ExposedPortProtocolHTTP},
			443: {Protocol: models.ExposedPortProtocolTLS},
			99:  {Protocol: models.ExposedPortProtocolTCP, HostPort: 40099},
		},
	}
	_ = svc.applyInFluxRoute(ctx, p)

	// Path-mode (empty domain) delete fail.
	svc.cfg.Domain = ""
	_ = svc.applyInFluxRoute(ctx, p)
}

func TestReconcileClusterIngressIdleAndErrorsWave14(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})

	stub := &serviceClusterStub{
		Noop:   cluster.NewNoop("self", "http://self", "h"),
		leader: "self",
		placements: []cluster.Placement{{
			SandboxID: "sb-ing", OwnerNodeID: "self", Version: 1,
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				80: {Protocol: models.ExposedPortProtocolHTTP},
			},
		}},
	}
	svc.AttachCluster(stub)

	_ = svc.ReconcileClusterIngress(ctx)
	// Second call may idle-skip if first somehow succeeded; force hash reset.
	svc.ingressLastHash.Store(0)
	_ = svc.ReconcileClusterIngress(ctx)

	// Empty self / nil cluster early returns.
	svc.AttachCluster(cluster.NewNoop("", "http://x", ""))
	_ = svc.ReconcileClusterIngress(ctx)
	svc.cluster = nil
	_ = svc.ReconcileClusterIngress(ctx)
}

func TestKickSnapshotPushReconcilerFailWave14(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	store := newFakePushStore()
	store.listErr = errors.New("list failed")
	svc.snapshotPushReconciler = NewSnapshotPushReconciler(&SnapshotPusher{}, store, svc.logger, 1)
	svc.kickSnapshotPushReconciler(&models.SandboxSnapshot{
		Name: "s", PushState: models.SnapshotPushStatePending,
	})
	time.Sleep(30 * time.Millisecond)
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

func TestRecreateSandboxWasmAndRehydrateWave14(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCluster = true
	svc.SetWasmRuntime(&recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("self", "http://self", "h"))
	svc.cipher = newTestCipher(t)

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-rehyd", Image: "m.wasm", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusPassivated, Durability: models.DurabilityDurable,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = svc.RecreateSandbox(ctx, "sb-wasm-rehyd", models.CreateSandboxRequest{
		Image: "m.wasm", Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable,
	}, cluster.PlacementSecrets{}, nil)

	// Durable wasm recreate with OpenClusterSecrets fail (missing secret ref).
	_ = svc.RecreateSandbox(ctx, "sb-new-wasm", models.CreateSandboxRequest{
		Image: "m.wasm", Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable,
	}, cluster.PlacementSecrets{Ref: "cluster-secret:missing", Version: 1}, nil)
}

func TestDestroySandboxUnmountWarnWithoutMountsWave14(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.mounts = nil
	svc.testForceUnmountErr = errors.New("fuse phantom")
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-umount", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, "sb-umount"); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
}

func TestStartReconcileLoopErrorWave14(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.ReconcileInterval = time.Millisecond
	_ = st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	svc.StartReconcileLoop(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
}

func TestPublicTrafficAndRouteHelpersWave14(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = nil
	deny := false
	sb := &models.Sandbox{
		ID: "sb-nil-caddy", AllowPublicTraffic: &deny, Status: models.SandboxStatusStarted,
		ExposedPorts: []models.ExposedPort{{Port: 80}},
	}
	_ = svc.deleteSandboxPublicRoutes(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
	_ = svc.syncSandboxPublicRoute(ctx, &models.Sandbox{ID: "x", Status: models.SandboxStatusStarted})
}

func TestSealUnsealRegistryFailWave14(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	_, err := svc.UnsealRegistry([]byte("not-a-valid-sealed-blob"))
	if err == nil {
		t.Fatal("expected unseal fail")
	}
	// Empty auth is a no-op success.
	out, err := svc.sealRegistry(&models.RegistryAuth{})
	if err != nil || out != nil {
		t.Fatalf("empty auth = %v, %v", out, err)
	}
}

func TestAllocateHostPortClusterRecordFailWave14(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 41300
	svc.cfg.L4PortRangeEnd = 41305
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	svc.AttachCluster(&failingExposeCluster{
		Noop:   cluster.NewNoop("n1", "http://n1", "h"),
		addErr: errors.New("raft reject"),
	})

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-hp-fail", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.3",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_, _, _, _ = svc.allocateHostPort(ctx, "sb-hp-fail", 55, now, 0)
}
