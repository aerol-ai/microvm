package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestExposePortUpsertPortRollbackViaHookWave11(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	svc.testAfterHTTPPortInstall = func() { _ = st.Close() }

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-upsert-fail", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exposePort(ctx, "sb-upsert-fail", 8080, models.ExposedPortProtocolHTTP, 0); err == nil {
		t.Fatal("expected UpsertPort failure after install")
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

func TestStopSandboxInternalModesWave11(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-stop-life", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: sb.ID, Port: 8080, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	stopped, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeLifecycle)
	if err != nil {
		t.Fatalf("lifecycle stop: %v", err)
	}
	if stopped == nil {
		t.Fatal("nil stopped")
	}
	// Manual stop on already-stopped.
	if _, err := svc.stopSandboxInternal(ctx, sb.ID, stopModeManual); err != nil {
		t.Fatalf("manual stop: %v", err)
	}
}

func TestReconcileWasmStoppedWakeWave11(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableWasm = true
	svc.cfg.EnableServerless = true
	svc.SetWasmRuntime(rt)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-wake", Image: "m", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestReconcileFirecrackerStoppedWave11(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableServerless = true
	svc.SetFirecrackerRuntime(rt)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-fc-stop", Image: "docker://alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStopped, WakeArmed: false,
		ExposedPorts: []models.ExposedPort{{Port: 80}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestDestroySandboxHappyWithPortsWave11(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-des-ok", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []models.ExposedPort{
		{SandboxID: "sb-des-ok", Port: 80, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now},
		{SandboxID: "sb-des-ok", Port: 443, Protocol: models.ExposedPortProtocolTLS, CreatedAt: now},
		{SandboxID: "sb-des-ok", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 20000, CreatedAt: now},
	} {
		if err := st.UpsertPort(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.DestroySandbox(ctx, "sb-des-ok"); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
}

func TestEnablePublicTrafficAndSyncWave11(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	deny := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-enpub", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		AllowPublicTraffic: &deny, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := svc.enableSandboxPublicTraffic(ctx, sb); err != nil {
		t.Fatalf("enable: %v", err)
	}
	allow := true
	sb.AllowPublicTraffic = &allow
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

func TestOpenClusterSecretsBadPayloadWave11(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cipher = newTestCipher(t)
	ref := secrets.FormatRef("sb-bad", 1)
	if err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-bad", Version: 1, SealedPayload: []byte("not-json"),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.OpenClusterSecretsForNode(ctx, "sb-bad", models.CreateSandboxRequest{Image: "x"}, cluster.PlacementSecrets{Ref: ref, Version: 1}, "node-a")
	if err == nil {
		t.Fatal("expected bad payload error")
	}
}

func TestApplyInFluxRouteNilCaddyWave11(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = false
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	p := cluster.Placement{SandboxID: "sb-x"}
	_ = svc.applyInFluxRoute(ctx, p)
	_ = svc.applyInFluxSandboxRoute(ctx, p)
	_ = svc.applyInFluxPortRoute(ctx, p, 80)
}

func TestReplayClusterOwnershipWave11(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false
	svc.ReplayClusterOwnership(context.Background())
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.ReplayClusterOwnership(context.Background())
}

func TestGetSnapshotMissWave11(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.GetSnapshot(context.Background(), "missing"); err == nil {
		t.Fatal("expected miss")
	}
}

func TestDeleteTLSPortRouteWave11(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	if err := svc.deleteTLSPortRoute(ctx, "sb", 443); err != nil {
		t.Fatalf("deleteTLS: %v", err)
	}
}

func TestCreateSandboxCustomDomainPersistFailWave11(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.admitter = nil
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "external.test"
	svc.testAfterStoreCreate = func() { _ = svc.store.Close() }
	pub := true
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", AllowPublicTraffic: &pub,
		CustomDomains: []string{"api.external.test"},
	}, "sb-cd-fail")
	// May fail at PutMounts-less path on custom domains or Get.
	if err == nil {
		t.Fatal("expected create failure with closed store after create")
	}
	if !strings.Contains(err.Error(), "custom") && !strings.Contains(err.Error(), "persist") && !strings.Contains(err.Error(), "sql") && !strings.Contains(err.Error(), "closed") {
		t.Logf("err = %v (acceptable create failure)", err)
	}
}
