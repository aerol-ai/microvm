package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

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

func TestNilCaddyAndClusterSprayWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.caddy = nil
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-nil", Image: "a", Status: models.SandboxStatusStarted,
		ContainerIP: "10.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		CustomDomains: []models.CustomDomain{{Hostname: "h.example.com"}},
		ExposedPorts:  []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
	}
	_ = st.Create(ctx, sb)
	deny := false
	sb.AllowPublicTraffic = &deny
	_ = svc.deleteSandboxPublicRoutes(ctx, sb) // nil-caddy early return
	_ = svc.syncSandboxPublicRoute(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
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

func TestPublicTrafficCleanupStoreFailsWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	deny := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-pt16", AllowPublicTraffic: &deny, Status: models.SandboxStatusStarted,
		ExposedPorts:  []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CustomDomains: []models.CustomDomain{{Hostname: "h.example.com"}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(ctx, sb)
	_ = st.Close()
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
}

func TestWave35IsolateAndUsageGuards(t *testing.T) {
	ctx := context.Background()
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "bare-name"}); err == nil {
		t.Fatal("cluster isolate requires node-bound ref")
	}
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{Runtime: models.RuntimeDocker}); err != nil {
		t.Fatal(err)
	}

	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("self", "", "")}
	if _, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "bare-name",
	}, ""); err == nil {
		t.Fatal("unbound cluster isolate create")
	}
	bound := models.JSBundleRefForNode("sha256:abc", "other-node")
	if _, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: bound,
	}, ""); err == nil {
		t.Fatal("wrong-node isolate create")
	}

	if got := appendReservedSamples(nil, nil, time.Now(), time.Now().Add(time.Second)); len(got) != 0 {
		t.Fatalf("nil sandbox samples = %d", len(got))
	}
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb"}, time.Now(), time.Now()); len(got) != 0 {
		t.Fatalf("zero window samples = %d", len(got))
	}
	if allowPublicTrafficEnabled(nil) {
		t.Fatal("nil public flag")
	}
	if sandboxAllowsPublicTraffic(nil) {
		t.Fatal("nil sandbox public")
	}
	if (*Service)(nil).sandboxPublicURL("id", boolPtr(true)) != "" {
		t.Fatal("nil service public url")
	}
	if err := (*Service)(nil).syncSandboxPublicRoute(ctx, &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Service{}).createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "bare-name", Durability: models.DurabilityPassivatable,
	}, ""); err == nil {
		t.Fatal("passivatable isolate must fail")
	}
	pub := true
	if err := (&Service{}).enableSandboxPublicTraffic(ctx, &models.Sandbox{ID: "sb", AllowPublicTraffic: &pub}); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).enableSandboxPublicTraffic(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).cleanupPublicTrafficDisabledIngressState(ctx, &models.Sandbox{ID: "sb", AllowPublicTraffic: &pub}); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC()
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb", DiskGB: 1}, start, start); len(got) != 0 {
		t.Fatalf("zero-length window = %d", len(got))
	}
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb", DiskGB: 1}, start, start.Add(-time.Second)); len(got) != 0 {
		t.Fatalf("negative window = %d", len(got))
	}

	usage := newUsageService(&captureReporter{})
	usage.emitReservedUsageAt(ctx, nil, start)
	usage.emitReservedUsageAt(ctx, []*models.Sandbox{nil, {ID: "gone", Status: models.SandboxStatusDestroyed}}, start)
	future := &models.Sandbox{ID: "future", Status: models.SandboxStatusStarted, CreatedAt: start.Add(time.Hour)}
	usage.emitReservedUsageAt(ctx, []*models.Sandbox{future}, start)
	usage.emitNetworkUsage(ctx, &models.Sandbox{ID: "net"}, 0, 0, start)
	usage.emitNetworkUsage(ctx, &models.Sandbox{ID: "net"}, 8, 0, start)
}

func boolPtr(v bool) *bool { return &v }

func TestPublicTrafficCaddyErrorArms(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "example.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.test",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})

	deny := false
	sb := &models.Sandbox{
		ID: "sb-pub", ContainerIP: "10.0.0.9", AllowPublicTraffic: &deny,
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com"}},
		ExposedPorts:  []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// deleteSandboxPublicRoutes / cleanup with failing caddy — firstErr arms.
	_ = svc.deleteSandboxPublicRoutes(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)

	allow := false
	sb2 := &models.Sandbox{ID: "sb-en", ContainerIP: "10.0.0.8", AllowPublicTraffic: &allow}
	if err := st.Create(ctx, sb2); err != nil {
		t.Fatalf("Create sb2: %v", err)
	}
	if err := svc.enableSandboxPublicTraffic(ctx, sb2); err == nil {
		t.Fatal("expected enableSandboxPublicTraffic caddy failure")
	}
}

func TestPublicTrafficSyncNilAndDisabledWave8(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.syncSandboxPublicRoute(ctx, nil); err != nil {
		t.Fatalf("nil sandbox: %v", err)
	}
	deny := false
	sb := &models.Sandbox{ID: "sb-pt", AllowPublicTraffic: &deny, ContainerIP: "10.0.0.1"}
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatalf("disabled public: %v", err)
	}
	_ = svc.deleteSandboxPublicRoutes(ctx, nil)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, nil)
}
