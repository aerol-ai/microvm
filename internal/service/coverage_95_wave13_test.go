package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestApplyHTTPPortRouteShapeNoneWithBypassWave13(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})

	none := &models.Sandbox{
		ID: "sb-http-none-byp", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.applyHTTPPortRoute(ctx, none, 8080); err != nil {
		t.Fatalf("http none: %v", err)
	}
	destroyed := &models.Sandbox{
		ID: "sb-http-dest", Status: models.SandboxStatusDestroyed,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.applyHTTPPortRoute(ctx, destroyed, 8081); err != nil {
		t.Fatalf("http destroyed: %v", err)
	}
	if err := svc.installTCPPortRoute(ctx, none, 5432, 40100); err != nil {
		t.Fatalf("tcp none: %v", err)
	}
	if err := svc.installTLSPortRoute(ctx, none, 8443); err != nil {
		t.Fatalf("tls none: %v", err)
	}
}

func TestDestroySandboxFailureArmsWave13(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	// store.Delete fails after runtime destroy.
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-del-fail", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.testAfterRuntimeDestroy = func() { _ = st.Close() }
	if err := svc.DestroySandbox(ctx, "sb-del-fail"); err == nil {
		t.Fatal("expected store.Delete failure")
	}

	// Unmount warn + cluster-secrets fail before irreversible row delete.
	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if err := st2.Create(ctx, &models.Sandbox{
		ID: "sb-post-del", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc2.testForceUnmountErr = errors.New("fuse busy")
	svc2.testAfterRuntimeDestroy = func() { _ = st2.Close() }
	if err := svc2.DestroySandbox(ctx, "sb-post-del"); err == nil {
		t.Fatal("expected DeleteClusterSecrets failure after store close")
	}

	// Wasm cleanup fails after delete (closed store).
	svc3, st3, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc3.cfg.EnableWasm = true
	svc3.SetWasmRuntime(&recordingRuntime{})
	if err := st3.Create(ctx, &models.Sandbox{
		ID: "sb-wasm-del", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc3.testAfterStoreDeleteOnDestroy = func() { _ = st3.Close() }
	if err := svc3.DestroySandbox(ctx, "sb-wasm-del"); err == nil {
		t.Fatal("expected wasm cleanup failure")
	}
}

func TestAllocateHostPortProtocolConflictWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 41000
	svc.cfg.L4PortRangeEnd = 41010
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	svc.AttachCluster(cluster.NewNoop("n1", "http://n1", "h"))

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-proto", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Pre-install HTTP exposure on container port 90.
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-proto", Port: 90, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := svc.allocateHostPort(ctx, "sb-proto", 90, now, 0)
	if err == nil {
		t.Fatal("expected protocol conflict")
	}

	// Preferred host port outside range.
	if _, _, _, err := svc.allocateHostPort(ctx, "sb-proto", 91, now, 999); err == nil {
		t.Fatal("expected preferred out of range")
	}
	// Misconfigured pool.
	svc.cfg.L4PortRangeEnd = svc.cfg.L4PortRangeStart
	if _, _, _, err := svc.allocateHostPort(ctx, "sb-proto", 92, now, 0); err == nil {
		t.Fatal("expected misconfigured pool")
	}
}

func TestAllocateHostPortReuseDifferentHostPortWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 41100
	svc.cfg.L4PortRangeEnd = 41120
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	cl := &hostPortReserveCluster{Noop: cluster.NewNoop("n1", "http://n1", "h")}
	svc.AttachCluster(cl)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-reuse-hp", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.2",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Existing TCP row with host port 41105.
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-reuse-hp", Port: 77, Protocol: models.ExposedPortProtocolTCP, HostPort: 41105,
		PublicURL: "tcp://h:41105",
	}); err != nil {
		t.Fatal(err)
	}
	// Preferred different candidate → reuse existing host port path with cluster re-record.
	hp, _, reused, err := svc.allocateHostPort(ctx, "sb-reuse-hp", 77, now, 41110)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if !reused || hp != 41105 {
		t.Fatalf("got hp=%d reused=%v", hp, reused)
	}
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

func TestEnsureClusterReadyDoubleCheckWave13(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.clusterReady.Store(false)
	if err := svc.EnsureClusterReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Already latched.
	if err := svc.EnsureClusterReady(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStaleOwnershipEmptySelfAndDestroyFailWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-stale", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})

	emptySelf := &stubStaleCluster{Noop: cluster.NewNoop("", "http://x", ""), otherNode: "other", otherURL: "http://other"}
	svc.AttachCluster(emptySelf)
	svc.reconcileStaleOwnership(ctx) // SelfNodeID empty → early return

	stale := &stubStaleCluster{Noop: cluster.NewNoop("self", "http://self", ""), otherNode: "other", otherURL: "http://other"}
	svc.AttachCluster(stale)
	// Force DestroySandbox to fail by clearing docker runtime mid-flight via wrong runtime.
	svc.docker = nil
	svc.reconcileStaleOwnership(ctx)

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.cfg.EnableCluster = true
	svc2.AttachCluster(stale)
	_ = st2.Close()
	svc2.reconcileStaleOwnership(ctx) // list fail
}

func TestWasmMigrateErrorArmsWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = false
	if _, _, err := svc.MigrateWasmSandbox(ctx, "x", t.TempDir()); err == nil {
		t.Fatal("expected wasm disabled")
	}
	if _, err := svc.ExportWasmMigration(ctx, "x", io.Discard); err == nil {
		t.Fatal("expected export disabled")
	}
	if err := svc.ImportWasmMigration(ctx, "x", "", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected import disabled")
	}

	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "g"})
	if err := svc.ImportWasmMigration(ctx, "  ", "", bytes.NewReader(nil)); err == nil {
		t.Fatal("expected empty id")
	}
	if err := svc.ImportWasmMigration(ctx, "sb", "", bytes.NewReader([]byte("not-a-tar"))); err == nil {
		t.Fatal("expected bad tar")
	}

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-docker-mig", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, _, err := svc.MigrateWasmSandbox(ctx, "sb-docker-mig", t.TempDir()); err == nil {
		t.Fatal("expected non-wasm")
	}
	if _, err := svc.ExportWasmMigration(ctx, "sb-docker-mig", io.Discard); err == nil {
		t.Fatal("expected export non-wasm")
	}

	if _, err := svc.MigrateWasmSandboxToNode(ctx, "", ""); err == nil {
		t.Fatal("expected missing ids")
	}
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if _, err := svc.MigrateWasmSandboxToNode(ctx, "sb", "other"); err == nil {
		t.Fatal("expected owner/member miss")
	}
	_ = svc.EvacuateLocalWasmSandboxesForDrain(ctx)
}

func TestPublicTrafficCleanupFailsWave13(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	deny := false
	sb := &models.Sandbox{
		ID: "sb-pt", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		AllowPublicTraffic: &deny,
		ExposedPorts: []models.ExposedPort{
			{Port: 80, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 443, Protocol: models.ExposedPortProtocolTLS},
		},
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com"}, {Hostname: ""}},
	}
	now := time.Now().UTC()
	sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
	_ = st.Create(ctx, sb)
	_ = svc.deleteSandboxPublicRoutes(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
}

func TestL4WakeAcceptAndProxyBranchesWave13(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:0"
	svc.cfg.L4WakeMaxPendingPerSandbox = 1
	svc.cfg.L4WakeMaxPendingGlobal = 1
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	svc.l4WakeMu.Lock()
	svc.l4WakeTCP = ln
	svc.l4WakeMu.Unlock()
	go svc.acceptL4WakeTCP(ctx, ln)

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-l4w", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-l4w", Port: 9, Protocol: models.ExposedPortProtocolTCP, HostPort: 41234, PublicURL: "tcp://x:41234",
		CreatedAt: now,
	})

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn1.Write([]byte("GARBAGE\n"))
	_ = conn1.Close()

	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn2.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 59999\r\n"))
	_ = conn2.Close()

	// Saturate pending so the real exposure PROXY returns immediately (no 30s dial).
	hold, ok := svc.tryAcquireL4Pending("sb-l4w")
	if !ok {
		t.Fatal("expected pending slot")
	}
	conn3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn3.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 41234\r\n"))
	time.Sleep(30 * time.Millisecond)
	_ = conn3.Close()
	hold()

	cancel()
	_ = ln.Close()
	time.Sleep(20 * time.Millisecond)

	svc.l4WakeMu.Lock()
	svc.l4WakeTCP = ln
	svc.l4WakeMu.Unlock()
	_ = svc.StartL4WakeProxy(context.Background())

	svc.closeAllTLSWakeListeners()
	svc.testL4ActivityInterval = time.Millisecond
	release2, ok := svc.tryAcquireL4Active("sb-l4w")
	if ok {
		svc.l4LimitMu.Lock()
		gen := svc.l4ActivityGenerations["sb-l4w"]
		svc.l4LimitMu.Unlock()
		done := make(chan struct{})
		go func() {
			svc.touchDuringL4Activity("sb-l4w", gen)
			close(done)
		}()
		time.Sleep(3 * time.Millisecond)
		_ = st.Close()
		time.Sleep(3 * time.Millisecond)
		release2()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("touchDuringL4Activity did not exit")
		}
	}
	_ = svc.l4ActivityStillActive("sb-l4w", 0)
	_ = tlsWakeKey("sb-l4w", 443)
}

func TestServerlessForceReconcileAndStopArmsWave13(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-frc", Image: "a", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle:    models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		ExposedPorts: []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = svc.ForceReconcileHTTPWakeShape(ctx)

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.cfg.EnableServerless = true
	_ = st2.Create(ctx, &models.Sandbox{
		ID: "sb-stop-int", Image: "a", Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st2.Close()
	_, _ = svc2.stopSandboxInternal(ctx, "sb-stop-int", stopModeLifecycle)
}
