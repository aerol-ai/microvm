package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type dupCreateRuntime struct {
	*recordingRuntime
	err error
}

func (r *dupCreateRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.recordingRuntime.Create(ctx, req, sandboxID, toolboxToken, binds)
}

func TestDuplicateCreateAfterRuntimeWave15(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	// ErrSandboxContainerExists + existing row → idempotent return.
	base := &recordingRuntime{}
	rt := &dupCreateRuntime{recordingRuntime: base, err: docker.ErrSandboxContainerExists}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/dup1.db", rt)
	svc.admitter = nil
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-dup-ok", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-dup-ok")
	if err != nil || resp == nil || resp.Sandbox.ID != "sb-dup-ok" {
		t.Fatalf("idempotent dup = %v resp=%v", err, resp)
	}

	// ErrSandboxContainerExists + no row → ErrSandboxExists (!errors.Is branch).
	base2 := &recordingRuntime{}
	rt2 := &dupCreateRuntime{recordingRuntime: base2, err: docker.ErrSandboxContainerExists}
	svc2, _, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/dup2.db", rt2)
	svc2.admitter = nil
	_, err = svc2.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-dup-miss")
	if !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("missing row dup = %v, want ErrSandboxExists", err)
	}
}

func TestUpdateLifecycleFlipAndStoreFailWave15(t *testing.T) {
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
		ID: "sb-lc15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-lc15", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateLifecycle(ctx, "sb-lc15", models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("flip: %v", err)
	}

	// Store UpdateLifecycle fails after scopedGet.
	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_ = st2.Create(ctx, &models.Sandbox{
		ID: "sb-lc15b", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc2.testAfterLifecycleScopedGet = func() { _ = st2.Close() }
	if _, err := svc2.UpdateLifecycle(ctx, "sb-lc15b", models.Lifecycle{StopIfIdleFor: time.Hour}); err == nil {
		t.Fatal("expected UpdateLifecycle store failure")
	}
}

type acceptOnceErrListener struct {
	net.Listener
	n atomic.Int32
}

func (l *acceptOnceErrListener) Accept() (net.Conn, error) {
	if l.n.Add(1) == 1 {
		return nil, errors.New("temporary accept failure")
	}
	return nil, net.ErrClosed
}

func TestL4WakeAcceptWarnArmsWave15(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = real.Close()
	ln := &acceptOnceErrListener{Listener: real}
	done := make(chan struct{})
	go func() {
		svc.acceptL4WakeTCP(ctx, ln)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptL4WakeTCP did not exit")
	}

	// TLS accept warn then closed.
	unixPath := t.TempDir() + "/tls.sock"
	uln, err := net.Listen("unix", unixPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = uln.Close()
	tln := &acceptOnceErrListener{Listener: uln}
	done2 := make(chan struct{})
	go func() {
		svc.acceptL4WakeTLS("sb-tls15", 8443, tln)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptL4WakeTLS did not exit")
	}
}

func TestScheduleTLSWakeListenerCloseReplaceWave15(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	path, err := svc.ensureTLSWakeListener("sb-sched15", 9443)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if path == "" {
		t.Fatal("empty socket path")
	}
	svc.scheduleTLSWakeListenerClose("sb-sched15", 9443, 50*time.Millisecond)
	// Replace pending timer — covers stop-old-timer arm.
	svc.scheduleTLSWakeListenerClose("sb-sched15", 9443, 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	// closeTLSWakeListener with pending timer present.
	_, _ = svc.ensureTLSWakeListener("sb-sched15b", 9444)
	svc.scheduleTLSWakeListenerClose("sb-sched15b", 9444, time.Hour)
	svc.closeTLSWakeListener("sb-sched15b", 9444)
}

func TestStopSandboxInternalWarnArmsWave15(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-stop15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-stop15", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})
	_, _ = svc.stopSandboxInternal(ctx, "sb-stop15", stopModeLifecycle)

	// Runtime Stop failure.
	rt := &recordingRuntime{stopErr: errors.New("stop boom")}
	svc2, st2, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/stop2.db", rt)
	svc2.cfg.EnableServerless = true
	_ = st2.Create(ctx, &models.Sandbox{
		ID: "sb-stop-fail", Image: "a", Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc2.stopSandboxInternal(ctx, "sb-stop-fail", stopModeManual); err == nil {
		t.Fatal("expected stop failure")
	}
}

func TestForceReconcileHTTPWakeShapeWave15(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-frc15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		WakeArmed: true, Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-frc15", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x",
	})
	_ = svc.ForceReconcileHTTPWakeShape(ctx)
}

func TestWakeAwareTargetsMissWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_, _ = svc.WakeAwarePortTarget(ctx, "missing", 80)
	_, _ = svc.WakeAwareL4PortTarget(ctx, "missing", 59999)
	_ = st.Close()
	_, _ = svc.WakeAwarePortTarget(ctx, "x", 80)
	_, _ = svc.WakeAwareL4PortTarget(ctx, "x", 1)
}

func TestRecreateDurableWasmWave15(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCluster = true
	svc.SetWasmRuntime(&recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("self", "http://self", "h"))
	svc.cipher = newTestCipher(t)

	err := svc.RecreateSandbox(ctx, "sb-wasm-new15", models.CreateSandboxRequest{
		Image: "mod.wasm", Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable,
	}, cluster.PlacementSecrets{Ref: "cluster-secret:nope", Version: 1}, nil)
	if err == nil {
		t.Fatal("expected secret open failure on durable wasm recreate")
	}
}

func TestProxyL4WakeDialFailWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-proxy15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = server.Close()
	}()
	// Port 1 won't accept → dial fail arm inside proxy.
	svc.proxyL4WakeConn(ctx, "sb-proxy15", 1, server, nil)
	_ = client.Close()
}

func TestStartL4WakeProxyListenFailWave15(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:1" // privileged / likely fail, or bind fail
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, Domain: "x", HTTPClientTimeout: time.Second})
	// Occupy an address then ask Start to bind the same one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	svc.cfg.InternalL4WakeAddr = ln.Addr().String()
	if err := svc.StartL4WakeProxy(context.Background()); err == nil {
		t.Fatal("expected listen failure on occupied addr")
	}
}

func TestHandleL4WakeNoTCPExposureWave15(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctxBackground(), &models.Sandbox{
		ID: "sb-http-exp", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(context.Background(), models.ExposedPort{
		SandboxID: "sb-http-exp", Port: 80, Protocol: models.ExposedPortProtocolHTTP,
		HostPort: 41555, PublicURL: "https://x",
	})
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 41555\r\n"))
		_ = client.Close()
	}()
	svc.handleL4WakeTCPConn(server)
}

func ctxBackground() context.Context { return context.Background() }

func TestInstallTLSPortRouteShapesWave15(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})

	started := &models.Sandbox{
		ID: "sb-tls-direct", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installTLSPortRoute(ctx, started, 8443)

	armed := &models.Sandbox{
		ID: "sb-tls-wake", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installTLSPortRoute(ctx, armed, 8443)
}

func TestConcurrentEnsureClusterReadyWave15(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	// Leader empty initially so first waiter takes the lock path; then set via noop which always has leader.
	noop := cluster.NewNoop("self", "http://self", "h")
	svc.AttachCluster(noop)
	svc.clusterReady.Store(false)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.EnsureClusterReady(context.Background())
		}()
	}
	wg.Wait()
}
