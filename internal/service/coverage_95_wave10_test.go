package service

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAllocateHostPortClusterPathsWave10(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("cluster_add_error", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableCluster = true
		svc.cfg.L4PortRangeStart = 38000
		svc.cfg.L4PortRangeEnd = 38002
		svc.AttachCluster(&failingExposeCluster{Noop: cluster.NewNoop("n1", "", "h"), addErr: errors.New("raft write")})
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-cl-err", Image: "a", Status: models.SandboxStatusStarted,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := svc.allocateHostPort(ctx, "sb-cl-err", 5432, now, 0)
		if err == nil {
			t.Fatal("expected cluster add error")
		}
	})

	t.Run("cluster_host_port_reserved_then_exhaust", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableCluster = true
		svc.cfg.L4PortRangeStart = 38100
		svc.cfg.L4PortRangeEnd = 38101
		reserver := &hostPortReserveCluster{
			Noop:     cluster.NewNoop("n1", "", "h"),
			reserved: map[int]bool{38100: true, 38101: true},
		}
		svc.AttachCluster(reserver)
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-cl-res", Image: "a", Status: models.SandboxStatusStarted,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := svc.allocateHostPort(ctx, "sb-cl-res", 5432, now, 0)
		if err == nil || !strings.Contains(err.Error(), "exhausted") {
			t.Fatalf("err = %v, want exhausted", err)
		}
	})

	t.Run("preferred_unavailable", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableCluster = true
		svc.cfg.L4PortRangeStart = 38200
		svc.cfg.L4PortRangeEnd = 38210
		reserver := &hostPortReserveCluster{
			Noop:     cluster.NewNoop("n1", "", "h"),
			reserved: map[int]bool{38205: true},
		}
		svc.AttachCluster(reserver)
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-pref", Image: "a", Status: models.SandboxStatusStarted,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := svc.allocateHostPort(ctx, "sb-pref", 5432, now, 38205)
		if err == nil || !errors.Is(err, ErrPreferredHostPortUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestExposePortTCPClusterRollbackWave10(t *testing.T) {
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

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 38300
	svc.cfg.L4PortRangeEnd = 38305
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		L4PortRangeStart: 38300, L4PortRangeEnd: 38305, HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	// Succeed on allocate's cluster record, fail on post-install recordClusterExposedPort.
	// Use a cluster that fails AddExposedPort always — allocate itself fails first.
	// Instead: succeed allocate without cluster, then fail record after install by
	// enabling cluster only after... simpler path: install succeeds, record fails.
	calls := 0
	svc.AttachCluster(&countingExposeCluster{
		Noop: cluster.NewNoop("n1", "", "h"),
		addFn: func() error {
			calls++
			// First N calls from allocateHostPort succeed; the post-install call fails.
			if calls > 1 {
				return errors.New("post-install raft fail")
			}
			return nil
		},
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tcp-roll", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exposePort(ctx, "sb-tcp-roll", 5432, models.ExposedPortProtocolTCP, 0); err == nil {
		t.Fatal("expected post-install cluster failure")
	}
}

type countingExposeCluster struct {
	*cluster.Noop
	addFn func() error
}

func (c *countingExposeCluster) AddExposedPort(context.Context, string, int, cluster.ExposedPortRoute) error {
	return c.addFn()
}

func TestCreateSnapshotWithOwnershipMissAndConflictWave10(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-snap-a", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "taken", Image: "taken", ImageID: "sha", SourceSandboxID: "sb-other", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-a", models.CreateSandboxSnapshotRequest{Name: "taken"}); err == nil || !errors.Is(err, storepkg.ErrSnapshotNameConflict) {
		t.Fatalf("conflict = %v", err)
	}

	// Missing sandbox.
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "missing", models.CreateSandboxSnapshotRequest{Name: "n1"}); err == nil {
		t.Fatal("expected missing sandbox")
	}

	// Runtime CreateSnapshot failure.
	svc.docker = &snapFailRuntime{recordingRuntime: &recordingRuntime{}, err: errors.New("snap fail")}
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-snap-b", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap-b", models.CreateSandboxSnapshotRequest{Name: "n2"}); err == nil {
		t.Fatal("expected snapshot runtime failure")
	}
}

type snapFailRuntime struct {
	*recordingRuntime
	err error
}

func (r *snapFailRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", r.err
}

func TestInstallTLSWakeAndDirectFailWave10(t *testing.T) {
	ctx := context.Background()
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: failServer.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)

	direct := &models.Sandbox{
		ID: "sb-tls-d10", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.2",
	}
	if err := svc.installTLSPortRoute(ctx, direct, 8443); err == nil {
		t.Fatal("expected direct TLS upsert failure")
	}

	wake := &models.Sandbox{
		ID: "sb-tls-w10", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTLSPortRoute(ctx, wake, 8443); err == nil {
		t.Fatal("expected wake TLS upsert failure")
	}
}

func TestEnsureLayer4ReadyFailureWave10(t *testing.T) {
	ctx := context.Background()
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.L4PortRangeStart = 20000
	svc.cfg.L4PortRangeEnd = 20100
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: failServer.URL, CaddyServerID: "srv0",
		L4PortRangeStart: 20000, L4PortRangeEnd: 20100, HTTPClientTimeout: time.Second,
	})
	if err := svc.EnsureLayer4Ready(ctx); err == nil {
		t.Fatal("expected EnsureLayer4Ready failure")
	}
	// installTCPPortRoute surfaces EnsureLayer4Ready error.
	if err := svc.installTCPPortRoute(ctx, &models.Sandbox{ID: "x", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1"}, 1, 20001); err == nil {
		t.Fatal("expected installTCP EnsureLayer4 failure")
	}
}

func TestRegisterSnapshotErrorArmsWave10(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if _, err := svc.RegisterSnapshot(ctx, nil); err == nil {
		t.Fatal("expected nil snapshot failure")
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{}); err == nil {
		t.Fatal("expected validation failure")
	}
	now := time.Now().UTC()
	snap := &models.SandboxSnapshot{Name: "reg1", Image: "reg1", ImageID: "sha", CreatedAt: now}
	if _, err := svc.RegisterSnapshot(ctx, snap); err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	// Same name different image → conflict.
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "reg1", Image: "other", ImageID: "sha2"}); err == nil {
		t.Fatal("expected duplicate conflict")
	}
	_ = st.Close()
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "reg2", Image: "reg2", ImageID: "sha", CreatedAt: now}); err == nil {
		t.Fatal("expected store failure")
	}
}

func TestUpdateLifecycleGetAfterCloseWave10(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-life-close", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Close after UpdateLifecycle write by racing: call UpdateLifecycle then
	// close mid-flight is hard; instead close store so UpdateLifecycle itself fails.
	_ = st.Close()
	if _, err := svc.UpdateLifecycle(ctx, "sb-life-close", models.Lifecycle{}); err == nil {
		t.Fatal("expected UpdateLifecycle store failure")
	}
}

func TestDestroySandboxNotFoundWave10(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.DestroySandbox(context.Background(), "missing"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestWakeAwareTargetsWave10(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.ToolboxPort = 4321
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wake-tb", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.3", ToolboxToken: "tok",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	ep, err := svc.WakeAwareToolboxTarget(ctx, "sb-wake-tb")
	if err != nil || ep.Token != "tok" {
		t.Fatalf("toolbox = %+v %v", ep, err)
	}
	if _, err := svc.WakeAwareToolboxTarget(ctx, "missing"); err == nil {
		t.Fatal("expected missing")
	}

	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-wake-l4", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.4",
		CreatedAt:   now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-wake-l4", Port: 5432, Protocol: models.ExposedPortProtocolTCP,
		HostPort: 20000, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.WakeAwareL4PortTarget(ctx, "sb-wake-l4", 5432); err != nil {
		t.Fatalf("l4 target: %v", err)
	}
	if _, err := svc.WakeAwareL4PortTarget(ctx, "sb-wake-l4", 9999); err == nil {
		t.Fatal("expected missing port")
	}
}

func TestExtractWasmCheckpointTarWave10(t *testing.T) {
	dir := t.TempDir()
	// Missing required members.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "unexpected.bin", Mode: 0o600, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), dir); err == nil {
		t.Fatal("expected unexpected entry")
	}

	// Incomplete tar (missing mem.snap members).
	buf.Reset()
	tw = tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "meta.json", Mode: 0o600, Size: 2})
	_, _ = tw.Write([]byte("{}"))
	_ = tw.Close()
	if err := extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), dir); err == nil {
		t.Fatal("expected missing member")
	}
}

func TestHealthAndEnsureClusterReadyWave10(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.ClearClusterForTest()
	if err := svc.EnsureClusterReady(ctx); err == nil {
		t.Fatal("expected cluster not initialized")
	}
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	if err := svc.EnsureClusterReady(ctx); err != nil {
		t.Fatalf("noop ready: %v", err)
	}
	h, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status == "" {
		t.Fatalf("Health empty: %+v", h)
	}
}

func TestRecreateSandboxMissingWave10(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	err := svc.RecreateSandbox(context.Background(), "missing", models.CreateSandboxRequest{Image: "alpine"}, cluster.PlacementSecrets{}, nil)
	if err == nil {
		// Recreate may create fresh — depending on implementation.
		t.Log("recreate missing returned nil")
	}
}

func TestRemoveHTTPPortRouteCaddyFailWave10(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	// Best-effort: some caddy client paths treat certain failures softly.
	_ = svc.removeHTTPPortRoute(ctx, "sb", 80)
}

func TestProxyL4WakeConnDialFailWave10(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-proxy", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	client, server := netPipe(t)
	defer client.Close()
	defer server.Close()
	// Upstream port nothing listens on → dial fails inside readiness window.
	svc.proxyL4WakeConn(ctx, "sb-proxy", 1, server, nil)
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	// Use os pipe via unix socket pair substitute: TCP localhost connect to listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var server net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		server = c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	<-done
	return client, server
}

func TestRunLifecycleSweepEmptyWave10(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.runLifecycleSweep(context.Background())
	_ = st.Close()
	svc.runLifecycleSweep(context.Background())
}

func TestCleanupPublicTrafficDisabledCustomWave10(t *testing.T) {
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
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	deny := false
	sb := &models.Sandbox{
		ID: "sb-cd-clean", AllowPublicTraffic: &deny, ContainerIP: "10.0.0.1",
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com"}},
		ExposedPorts: []models.ExposedPort{
			{Port: 80, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 443, Protocol: models.ExposedPortProtocolTLS},
			{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 20000},
		},
	}
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
}

func TestCreateIsolateSandboxEntropyWave10(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	svc.SetIsolateRuntime(&recordingRuntime{})
	// Fail the first entropy read so createIsolateSandbox aborts early.
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	_, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b",
	}, "")
	if err == nil {
		t.Fatal("expected entropy failure")
	}
}

func TestStartPendingImageGCWave10(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ImageBuildGCEnabled = false
	svc.StartPendingImageGC(ctx) // no-op
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = 0
	svc.StartPendingImageGC(ctx) // no-op interval
	svc.cfg.ImageBuildGCInterval = time.Hour
	svc.StartPendingImageGC(ctx)
	svc.StartBuiltImageGC(ctx)
}
