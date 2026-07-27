package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type egressFailRuntime struct {
	*recordingRuntime
	applyErr         error
	applyEgressCalls int
	lastEgressIP     string
}

func (r *egressFailRuntime) ApplyEgressPolicy(ip string, _, _ []string) error {
	r.applyEgressCalls++
	r.lastEgressIP = ip
	return r.applyErr
}

type resizeFailRuntime struct {
	*recordingRuntime
	resizeErr error
}

func (r *resizeFailRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return r.resizeErr
}

type wave3ReconcileRuntime struct {
	fakeReconcileRuntime
	egressCalls            []string
	quotaBlockAllCalls     []string
	quotaBlockIngressCalls []string
	clearBlockEgressCalls  []string
}

func (r *wave3ReconcileRuntime) ApplyEgressPolicy(ip string, _, _ []string) error {
	r.egressCalls = append(r.egressCalls, ip)
	return nil
}

func (r *wave3ReconcileRuntime) ApplyNetworkBlockAll(ip string) error {
	r.quotaBlockAllCalls = append(r.quotaBlockAllCalls, ip)
	return r.fakeReconcileRuntime.ApplyNetworkBlockAll(ip)
}

func (r *wave3ReconcileRuntime) ApplyNetworkBlockIngress(ip string) error {
	r.quotaBlockIngressCalls = append(r.quotaBlockIngressCalls, ip)
	return nil
}

func (r *wave3ReconcileRuntime) ClearNetworkBlockEgress(ip string) error {
	r.clearBlockEgressCalls = append(r.clearBlockEgressCalls, ip)
	return nil
}

func TestStartSandboxEgressPolicyFailureWave3(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{
		startState: &models.SandboxRuntimeState{
			ContainerID: "ctr-egress-new",
			ContainerIP: "10.0.0.88",
			Status:      models.SandboxStatusStarted,
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, base)
	svc.docker = &egressFailRuntime{recordingRuntime: base, applyErr: errors.New("iptables egress failed")}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-egress-fail", Image: "alpine:3.20", Status: models.SandboxStatusStopped,
		Runtime: models.RuntimeDocker, ContainerID: "ctr-egress-old",
		NetworkAllowOut: []string{"10.0.0.0/8"},
		CPU:             1, MemoryMB: 256, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.StartSandbox(ctx, "sb-egress-fail")
	if err == nil || !strings.Contains(err.Error(), "apply egress policy on start") {
		t.Fatalf("StartSandbox() error = %v, want egress failure", err)
	}
	if base.stopRefs == nil || len(base.stopRefs) != 1 {
		t.Fatalf("runtime Stop refs = %v, want container stopped on egress failure", base.stopRefs)
	}
	got, err := st.Get(ctx, "sb-egress-fail")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != models.SandboxStatusError {
		t.Fatalf("status = %q, want error", got.Status)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 {
		t.Fatalf("admission not released: %+v", cap)
	}
}

func TestResizeSandboxRuntimeAndResizeErrorsWave3(t *testing.T) {
	ctx := context.Background()

	t.Run("runtimeForSandbox error restores admitter", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-resize-rt", Image: "mod.wasm", Status: models.SandboxStatusStarted,
			Runtime: models.RuntimeWasm, CPU: 2, MemoryMB: 1024,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		before := svc.Capacity()
		_, err := svc.ResizeSandbox(ctx, "sb-resize-rt", models.ResizeSandboxRequest{CPU: 4, MemoryMB: 2048})
		if err == nil || !strings.Contains(err.Error(), "driver not registered") {
			t.Fatalf("ResizeSandbox() error = %v, want runtime routing failure", err)
		}
		after := svc.Capacity()
		if after.ReservedCPU != 2 {
			t.Fatalf("admitter should restore sandbox CPU after runtime error: before=%+v after=%+v", before, after)
		}
	})

	t.Run("Resize error restores admitter", func(t *testing.T) {
		base := &recordingRuntime{}
		svc, st, adm := newServiceRuntimeHarness(t, base)
		svc.docker = &resizeFailRuntime{recordingRuntime: base, resizeErr: errors.New("docker resize failed")}
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-resize-fail", Image: "alpine", Status: models.SandboxStatusStarted,
			Runtime: models.RuntimeDocker, ContainerID: "ctr-resize",
			CPU: 1, MemoryMB: 512, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := adm.Admit("sb-resize-fail", capacity.Request{CPU: 1, MemoryMB: 512}); err != nil {
			t.Fatalf("Admit: %v", err)
		}
		_, err := svc.ResizeSandbox(ctx, "sb-resize-fail", models.ResizeSandboxRequest{CPU: 2, MemoryMB: 1024})
		if err == nil || !strings.Contains(err.Error(), "docker resize failed") {
			t.Fatalf("ResizeSandbox() error = %v, want resize failure", err)
		}
		if cap := svc.Capacity(); cap.ReservedCPU != 1 || cap.ReservedMemoryMB != 512 {
			t.Fatalf("admitter not restored after resize error: %+v", cap)
		}
	})
}

func TestReconcileStartedDockerAliveBranchWave3(t *testing.T) {
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: filepath.Join(t.TempDir(), "mounts"), CredDir: filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	rt := &wave3ReconcileRuntime{
		fakeReconcileRuntime: fakeReconcileRuntime{
			allowPushAllowedPorts: true,
			managed: map[string]*models.SandboxRuntimeState{
				"sb-alive": {
					SandboxID: "sb-alive", ContainerID: "ctr-alive", ContainerIP: "10.0.0.70",
					Status: models.SandboxStatusStarted,
				},
			},
		},
	}
	svc := &Service{
		cfg:    config.Config{ImageBuildGCEnabled: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: rt,
		caddy:  caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts: mgr,
		cipher: newTestCipher(t),
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-alive", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, ContainerID: "ctr-stale", ContainerIP: "10.0.0.7",
		NetworkAllowOut:      []string{"10.0.0.0/8"},
		NetworkBytesOutLimit: 100, NetworkBytesOut: 200,
		CPU: 1, MemoryMB: 512, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	sealed, err := svc.sealMounts([]models.MountSpec{{
		Type: "bogus", Target: "/data", Source: "bucket",
	}})
	if err != nil {
		t.Fatalf("sealMounts: %v", err)
	}
	if err := st.PutMounts(ctx, "sb-alive", sealed); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := rt.egressCalls; len(got) != 1 || got[0] != "10.0.0.70" {
		t.Fatalf("ApplyEgressPolicy calls = %v, want [10.0.0.70]", got)
	}
	if got := rt.quotaBlockAllCalls; len(got) != 1 || got[0] != "10.0.0.70" {
		t.Fatalf("quota egress block calls = %v, want [10.0.0.70]", got)
	}
	refreshed, err := st.Get(ctx, "sb-alive")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if refreshed.ContainerIP != "10.0.0.70" {
		t.Fatalf("container IP = %q, want runtime-managed IP", refreshed.ContainerIP)
	}
}

func TestInstallTLSPortRouteDisabledCaddyWave3(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = false
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.InternalL4WakeDir = shortSockDir(t)
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy:       false,
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	})

	direct := &models.Sandbox{
		ID: "tls-w3-direct", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.60",
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	if err := svc.installTLSPortRoute(ctx, direct, 8443); err != nil {
		t.Fatalf("direct installTLSPortRoute: %v", err)
	}

	wake := &models.Sandbox{
		ID: "tls-w3-wake", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	if _, err := svc.ensureTLSWakeListener("tls-w3-wake", 8443); err != nil {
		t.Fatalf("ensureTLSWakeListener: %v", err)
	}
	if err := svc.installTLSPortRoute(ctx, wake, 8443); err != nil {
		t.Fatalf("wake installTLSPortRoute: %v", err)
	}

	none := &models.Sandbox{
		ID: "tls-w3-none", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true},
	}
	if _, err := svc.ensureTLSWakeListener("tls-w3-none", 8443); err != nil {
		t.Fatalf("ensureTLSWakeListener(none): %v", err)
	}
	if err := svc.installTLSPortRoute(ctx, none, 8443); err != nil {
		t.Fatalf("none installTLSPortRoute: %v", err)
	}
	if _, ok := svc.l4WakeTLS[tlsWakeKey("tls-w3-none", 8443)]; ok {
		t.Fatal("none shape should close wake listener")
	}
}

func TestAddCustomDomainErrorBranchesWave3(t *testing.T) {
	ctx := context.Background()

	t.Run("store get failure after insert rolls back", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(ts.Close)

		svc, st := newCustomDomainsHarnessWithCaddy(t, ts)
		svc.cfg.EnableCluster = true
		svc.AttachCluster(&closeStoreAfterClusterCustomDomain{Noop: cluster.NewNoop("self", "http://self", ""), st: st})
		mustCreateSandboxRow(t, st, "sb-cd-get-fail")

		err := svc.AddCustomDomain(ctx, "sb-cd-get-fail", "api.acme.com", 0)
		if err == nil || !strings.Contains(err.Error(), "reload sandbox after custom-domain insert") {
			t.Fatalf("AddCustomDomain() error = %v, want reload failure", err)
		}
		domains, listErr := st.ListCustomDomains(ctx, "sb-cd-get-fail")
		if listErr == nil && len(domains) != 0 {
			t.Fatalf("domain row should be rolled back, got %+v", domains)
		}
	})

	t.Run("wasm custom domain sync failure rolls back", func(t *testing.T) {
		svc, st := newWasmCustomDomainsHarnessAllowClose(t)
		if _, err := svc.ExposePort(ctx, "sb-wasm-cd", 8080, "http"); err != nil {
			t.Fatalf("ExposePort: %v", err)
		}

		wasmRouteID := caddy.IngressCustomDomainHTTPRouteID("sb-wasm-cd", "api.acme.com")
		patchCounts := map[string]int{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/"):
				id := strings.TrimPrefix(r.URL.Path, "/id/")
				if id == wasmRouteID {
					patchCounts[id]++
					if patchCounts[id] >= 2 {
						http.Error(w, "wasm sync boom", http.StatusInternalServerError)
						return
					}
				}
				http.NotFound(w, r)
			case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/routes/"):
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(ts.Close)
		svc.cfg.CaddyAdminURL = ts.URL
		svc.caddy = caddy.New(svc.cfg)

		err := svc.AddCustomDomain(ctx, "sb-wasm-cd", "api.acme.com", 8080)
		if err == nil || !strings.Contains(err.Error(), "install wasm custom-domain route") {
			t.Fatalf("AddCustomDomain() error = %v, want wasm sync failure", err)
		}
		domains, listErr := st.ListCustomDomains(ctx, "sb-wasm-cd")
		if listErr == nil && len(domains) != 0 {
			t.Fatalf("domain row should be rolled back, got %+v", domains)
		}
	})
}

type closeStoreAfterClusterCustomDomain struct {
	*cluster.Noop
	st *storepkg.Store
}

func (c *closeStoreAfterClusterCustomDomain) AddCustomDomain(context.Context, string, string) error {
	if c.st != nil {
		_ = c.st.Close()
	}
	return nil
}

// newWasmCustomDomainsHarnessAllowClose is like newWasmCustomDomainsHarness but
// uses the allow-close store harness so AddCustomDomain rollback tests can
// close SQLite mid-flight.
func newWasmCustomDomainsHarnessAllowClose(t *testing.T) (*Service, *storepkg.Store) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "aerol.cloud"
	svc.cfg.CustomDomainVerifyPrefix = "_aerol-verify"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerol-verify="
	svc.cfg.ToolboxPort = 4321
	svc.SetWasmRuntime(wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil))
	svc.dnsResolver = &mockDNSResolver{
		records: map[string][]string{
			"_aerol-verify.api.acme.com": {"aerol-verify=api.acme.com"},
		},
	}
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.HTTPClientTimeout = time.Second
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-wasm-cd", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	return svc, st
}

func TestL4WakeLimitHelpersWave3(t *testing.T) {
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:    config.Config{L4WakeMaxPendingPerSandbox: 1, L4WakeMaxPendingGlobal: 2},
	}
	release, ok := svc.tryAcquireL4Pending("sb-l4")
	if !ok || release == nil {
		t.Fatal("first pending acquire should succeed")
	}
	_, ok = svc.tryAcquireL4Pending("sb-l4")
	if ok {
		t.Fatal("per-sandbox pending cap should reject second acquire")
	}
	release()
	svc.releaseL4Pending("sb-l4") // idempotent when already zero

	activeRelease, ok := svc.tryAcquireL4Active("sb-active")
	if !ok || activeRelease == nil {
		t.Fatal("active acquire should succeed")
	}
	activeRelease()
	svc.releaseL4Active("sb-active")
}
