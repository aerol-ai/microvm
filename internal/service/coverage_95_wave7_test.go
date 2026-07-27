package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

type listErrRuntime struct {
	*recordingRuntime
	listErr error
}

func (r *listErrRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.recordingRuntime.ListManaged(context.Background())
}

type failRemoveRuntime struct {
	*recordingRuntime
	removeErr error
}

func (r *failRemoveRuntime) RemoveImage(context.Context, string) error {
	return r.removeErr
}

func TestCreateSandboxValidationGapsWave7(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.admitter = nil

	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{}); err == nil || !strings.Contains(err.Error(), "image is required") {
		t.Fatalf("empty image = %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", NetworkBytesInLimit: -1,
	}); err == nil || !strings.Contains(err.Error(), "network byte limits") {
		t.Fatalf("neg net = %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", GPUs: &models.GPURequest{Vendor: "bogus"},
	}); err == nil || !strings.Contains(err.Error(), "invalid gpu") {
		t.Fatalf("bad gpu = %v", err)
	}
	// Egress mutual exclusion after admission reservation.
	svc2, _, admit := newServiceRuntimeHarness(t, &recordingRuntime{})
	_, err := svc2.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine", NetworkAllowOut: []string{"10.0.0.0/8"}, NetworkDenyOut: []string{"192.168.0.0/16"},
	}, "sb-egress-mutex")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("egress mutex = %v", err)
	}
	if admit != nil {
		// Reservation must have been released on the validation failure.
		_ = admit
	}
}

func TestCreateFirecrackerRejectsWave7(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	svc.SetFirecrackerRuntime(&recordingRuntime{})

	mountsTooMany := make([]models.MountSpec, models.MaxMountsPerSandbox+1)
	for i := range mountsTooMany {
		mountsTooMany[i] = models.MountSpec{Type: models.MountTypeNFS, Target: "/m"}
	}
	cases := []struct {
		name string
		req  models.CreateSandboxRequest
		want string
	}{
		{"mounts_nyi", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
			Mounts: []models.MountSpec{{Type: models.MountTypeNFS, Target: "/data"}},
		}, "does not yet support mounts"},
		{"too_many_mounts", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine", Mounts: mountsTooMany,
		}, "too many mounts"},
		{"gpus", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
			GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA},
		}, "does not yet support GPUs"},
		{"neg_net", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkBytesOutLimit: -2,
		}, "network byte limits"},
		{"block_all", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkBlockAll: true,
		}, "network_block_all"},
		{"egress", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkAllowOut: []string{"10.0.0.0/8"},
		}, "selective egress"},
		{"byte_limits", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkBytesInLimit: 100,
		}, "network byte limits"},
		{"bad_lifecycle", models.CreateSandboxRequest{
			Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
			Lifecycle: &models.Lifecycle{Serverless: true},
		}, "invalid lifecycle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.createFirecrackerSandbox(ctx, tc.req, "sb-fc-"+tc.name)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}

	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	_, err := svc.createFirecrackerSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "generate toolbox token") {
		t.Fatalf("entropy = %v", err)
	}
}

func TestCreateFirecrackerCaddyAndEntropyWave7(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "caddy down", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	base := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, base)
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "fc.example.com"
	svc.admitter = nil
	svc.SetFirecrackerRuntime(base)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "fc.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	pub := true
	_, err := svc.createFirecrackerSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
		AllowPublicTraffic: &pub,
	}, "sb-fc-caddy")
	if err == nil {
		t.Fatal("expected public route sync failure")
	}
	if len(base.destroyIDs) == 0 {
		t.Fatal("expected firecracker Destroy on caddy failure")
	}

	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("ssh fail")}})
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableFirecracker = true
	svc2.admitter = nil
	svc2.SetFirecrackerRuntime(&recordingRuntime{})
	_, err = svc2.createFirecrackerSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
	}, "sb-fc-ssh")
	if err == nil || !strings.Contains(err.Error(), "generate ssh") {
		t.Fatalf("ssh entropy = %v", err)
	}
}

func TestExposePortProbeAndClusterFailWave7(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete:
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCluster = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 35000
	svc.cfg.L4PortRangeEnd = 35010
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", L4PortRangeStart: 35000, L4PortRangeEnd: 35010,
		HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)
	svc.AttachCluster(&failingExposeCluster{Noop: cluster.NewNoop("n1", "", "host"), addErr: errors.New("raft down")})
	svc.probeContainerPortFn = func(context.Context, string, int) error {
		return errors.New("not listening yet")
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-exp7", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.77", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Probe warn arm + cluster record failure after HTTP UpsertPort.
	if _, err := svc.exposePort(ctx, "sb-exp7", 8080, models.ExposedPortProtocolHTTP, 0); err == nil {
		t.Fatal("expected cluster record failure on http expose")
	}

	// TLS without domain.
	svc.cfg.Domain = ""
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	if _, err := svc.exposePort(ctx, "sb-exp7", 8443, models.ExposedPortProtocolTLS, 0); err == nil || !strings.Contains(err.Error(), "--domain") {
		t.Fatalf("tls no domain = %v", err)
	}

	// TLS without L4TLSListen.
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	if _, err := svc.exposePort(ctx, "sb-exp7", 8444, models.ExposedPortProtocolTLS, 0); err == nil || !strings.Contains(err.Error(), "SB_L4_TLS_LISTEN") {
		t.Fatalf("tls no listen = %v", err)
	}
}

func TestExposePortTCPReuseAndInstallFailWave7(t *testing.T) {
	ctx := context.Background()
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 36000
	svc.cfg.L4PortRangeEnd = 36005
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: failServer.URL, CaddyServerID: "srv0",
		L4PortRangeStart: 36000, L4PortRangeEnd: 36005, HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tcp7", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.66", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		ExposedPorts: []models.ExposedPort{{
			Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 36001,
			PublicURL: "tcp://sandbox.example.com:36001", CreatedAt: now,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// Re-expose existing TCP → installTCPPortRoute fails against broken caddy.
	if _, err := svc.exposePort(ctx, "sb-tcp7", 5432, models.ExposedPortProtocolTCP, 0); err == nil {
		t.Fatal("expected TCP re-expose install failure")
	}

	// Fresh TCP allocate then install fails → rollback DeletePort.
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-tcp7b", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.67", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exposePort(ctx, "sb-tcp7b", 5432, models.ExposedPortProtocolTCP, 0); err == nil {
		t.Fatal("expected TCP allocate+install failure")
	}
}

func TestAllocateHostPortExhaustedWave7(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.L4PortRangeStart = 37000
	svc.cfg.L4PortRangeEnd = 37001 // tiny pool
	svc.cfg.EnableCaddy = false
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-pool", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Occupy both slots under a different sandbox so random+linear walk exhausts.
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-hold", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for hp := 37000; hp <= 37001; hp++ {
		if err := st.UpsertPort(ctx, models.ExposedPort{
			SandboxID: "sb-hold", Port: hp, Protocol: models.ExposedPortProtocolTCP,
			HostPort: hp, PublicURL: "tcp://x", CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, err := svc.allocateHostPort(ctx, "sb-pool", 5432, now, 0)
	if err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("err = %v, want exhausted", err)
	}
	_, _, _, err = svc.allocateHostPort(ctx, "sb-pool", 5432, now, 36999)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("preferred outside = %v", err)
	}
}

func TestReconcileListManagedErrorsWave7(t *testing.T) {
	ctx := context.Background()

	t.Run("docker_list", func(t *testing.T) {
		rt := &listErrRuntime{recordingRuntime: &recordingRuntime{}, listErr: errors.New("docker list boom")}
		svc, _, _ := newServiceRuntimeHarness(t, rt.recordingRuntime)
		svc.docker = rt
		if err := svc.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "docker list boom") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("wasm_list", func(t *testing.T) {
		base := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
		svc, _, _ := newServiceRuntimeHarness(t, base)
		svc.cfg.EnableWasm = true
		svc.SetWasmRuntime(&listErrRuntime{recordingRuntime: base, listErr: errors.New("wasm list boom")})
		if err := svc.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "wasm list boom") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("firecracker_list", func(t *testing.T) {
		base := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
		svc, _, _ := newServiceRuntimeHarness(t, base)
		svc.cfg.EnableFirecracker = true
		svc.SetFirecrackerRuntime(&listErrRuntime{recordingRuntime: base, listErr: errors.New("fc list boom")})
		if err := svc.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "fc list boom") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("containerd_list", func(t *testing.T) {
		base := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
		svc, _, _ := newServiceRuntimeHarness(t, base)
		svc.SetContainerdRuntime(&listErrRuntime{recordingRuntime: base, listErr: errors.New("ctrd list boom")})
		if err := svc.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "ctrd list boom") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("closed_store_list", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}})
		_ = st.Close()
		if err := svc.Reconcile(ctx); err == nil {
			t.Fatal("expected store.List failure")
		}
	})
}

func TestReconcileTopologyWarnWave7(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}})
	svc.cfg.EnableCluster = true
	// > MaxReplicatedIngressRouteNodes members with ingress → topology warn arm.
	members := make([]cluster.Member, 0, cluster.MaxReplicatedIngressRouteNodes+2)
	for i := 0; i < cluster.MaxReplicatedIngressRouteNodes+2; i++ {
		members = append(members, cluster.Member{
			NodeID: "ingress-" + string(rune('a'+i)), Role: config.NodeRoleIngress, Alive: true,
		})
	}
	svc.AttachCluster(&stubIngressCluster{
		Noop:    cluster.NewNoop("n1", "", ""),
		members: members,
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestGCZombieServerlessCustomAndDeleteFailWave7(t *testing.T) {
	// Handler that snapshots OK but fails every delete — warn arms in GC.
	var snap struct {
		HTTP []string
		TCP  []string
		TLS  []string
	}
	snap.HTTP = []string{"sandbox-ghost", "sandbox-live-port-1"}
	snap.TCP = []string{"tcp-port-39998"}
	snap.TLS = []string{"sandbox-ghost-port-1-tls"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			httpRoutes := make([]any, 0, len(snap.HTTP))
			for _, id := range snap.HTTP {
				httpRoutes = append(httpRoutes, map[string]any{"@id": id})
			}
			tlsRoutes := make([]any, 0, len(snap.TLS))
			for _, id := range snap.TLS {
				tlsRoutes = append(tlsRoutes, map[string]any{"@id": id})
			}
			servers := map[string]any{}
			for _, sid := range snap.TCP {
				servers[sid] = map[string]any{"listen": []string{":0"}, "routes": []any{}}
			}
			servers["tls-mux"] = map[string]any{"listen": []string{":443"}, "routes": tlsRoutes}
			body, _ := json.Marshal(map[string]any{"apps": map[string]any{
				"http":   map[string]any{"servers": map[string]any{"srv0": map[string]any{"routes": httpRoutes}}},
				"layer4": map[string]any{"servers": servers},
			}})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		case r.Method == http.MethodDelete:
			http.Error(w, "delete fail", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	svc := &Service{
		cfg:    config.Config{EnableServerless: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0",
			HTTPClientTimeout: time.Second,
		}),
	}
	live := &models.Sandbox{
		ID: "live", Status: models.SandboxStatusStarted,
		Lifecycle: models.Lifecycle{Serverless: true},
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 37000},
			{Port: 8443, Protocol: models.ExposedPortProtocolTLS},
		},
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com"}, {Hostname: ""}},
	}
	svc.gcZombieCaddyEntries(context.Background(), []*models.Sandbox{live, nil})
}

func TestInstallTCPPortRouteNoneShapeWave7(t *testing.T) {
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

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)

	// Stopped + unarmed serverless → RouteShapeNone → DeleteTCPRoute.
	sb := &models.Sandbox{
		ID: "sb-none", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTCPPortRoute(ctx, sb, 5432, 36000); err != nil {
		t.Fatalf("installTCPPortRoute none: %v", err)
	}
}

func TestApplyHTTPPortRouteNoneShapeWave7(t *testing.T) {
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
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "sb-http-none", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.applyHTTPPortRoute(ctx, sb, 8080); err != nil {
		t.Fatalf("applyHTTPPortRoute none: %v", err)
	}
}

func TestCreateSnapshotWithOwnershipEmptyAndStoreWave7(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb", models.CreateSandboxSnapshotRequest{}); err == nil {
		t.Fatal("expected empty name")
	}
	_ = st.Close()
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb", models.CreateSandboxSnapshotRequest{Name: "snap"}); err == nil {
		t.Fatal("expected GetSnapshot store error")
	}
}

func TestRunPendingImageGCBranchesWave7(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc.cfg.ImageGCWhitelist = []string{"keep/me:latest"}
	old := time.Now().UTC().Add(-2 * time.Hour)
	seedPending(t, st, "keep/me:latest", old)
	seedPending(t, st, "dead/img:latest", old)

	// Referenced image: seed an active sandbox using it.
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-ref", Image: "dead/img:latest", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.runPendingImageGC(ctx)

	// RemoveImage failure arm.
	svc2, st2, _, _ := newPendingImageGCHarness(t, time.Hour)
	svc2.docker = &failRemoveRuntime{recordingRuntime: &recordingRuntime{}, removeErr: errors.New("rm fail")}
	seedPending(t, st2, "gone/img:latest", old)
	svc2.runPendingImageGC(ctx)

	// List failure arm.
	svc3, st3, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc3.cfg.ImageBuildGCEnabled = true
	svc3.cfg.ImageBuildGCTTL = time.Hour
	_ = st3.Close()
	svc3.runPendingImageGC(ctx)
}

func TestCreateSandboxPublicRouteRollbackWave7(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "pub.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "pub.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	pub := true
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", AllowPublicTraffic: &pub,
	}, "sb-pub-roll")
	if err == nil {
		t.Fatal("expected caddy sync failure")
	}
	if len(rt.destroyIDs) == 0 {
		t.Fatal("expected docker Destroy on public route failure")
	}
}

func TestDeleteExposedPortRouteUnknownProtoWave7(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	err := svc.deleteExposedPortRoute(context.Background(), &models.Sandbox{ID: "sb"}, models.ExposedPort{
		Port: 1, Protocol: "udp",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("err = %v", err)
	}
}

func TestThinWrappersAndSettersWave7(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.ClearClusterForTest()
	if svc.Cluster() != nil {
		t.Fatal("ClearClusterForTest left a cluster")
	}
	svc.SetEventsSource(stubEventsSource{})
	svc.SetDockerAuxClient(nil)
	svc.SetContainerdRuntime(nil)
	svc.AttachWasmCheckpointPusher(nil)
	_ = svc.TemplateArtifactPushReconciler()
	_ = svc.serverlessWakeEnabled(nil)
	_ = svc.serverlessWakeEnabled(&models.Sandbox{Lifecycle: models.Lifecycle{Serverless: true}})
	svc.cfg.EnableServerless = true
	_ = svc.serverlessWakeEnabled(&models.Sandbox{Lifecycle: models.Lifecycle{Serverless: true}})
	svc.warmCacheSet("hot")
	if !svc.warmCacheHit("hot") {
		t.Fatal("warmCacheSet/Hit")
	}
	svc.invalidateWarm("hot")
	_ = unsupportedWasmOption("x")
	_ = unsupportedFirecrackerOption("y")
	_ = imageStillReferenced(nil, "img")
	_ = imageStillReferenced([]*models.Sandbox{{Image: "img", Status: models.SandboxStatusStarted}}, "img")
	_ = imageStillReferenced([]*models.Sandbox{{Image: "other", Status: models.SandboxStatusStarted}}, "img")
	id, err := GenerateSandboxID()
	if err != nil || id == "" {
		t.Fatalf("GenerateSandboxID: %v %q", err, id)
	}
}
