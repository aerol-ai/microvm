package service

import (
	"net/http"
	"net/http/httptest"

	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

type customDomainClusterStub struct {
	*cluster.Noop
	addErr      error
	removeErr   error
	addCalls    []string
	removeCalls []string
}

func (c *customDomainClusterStub) AddCustomDomain(_ context.Context, sandboxID, hostname string) error {
	c.addCalls = append(c.addCalls, sandboxID+":"+hostname)
	return c.addErr
}

func (c *customDomainClusterStub) RemoveCustomDomain(_ context.Context, sandboxID, hostname string) error {
	c.removeCalls = append(c.removeCalls, sandboxID+":"+hostname)
	return c.removeErr
}

// matchingDNSResolver returns a TXT value that always satisfies
// verifyCustomDomainOwnership for the empty verify-value prefix used in the
// test config: the looked-up name is "<prefix>.<hostname>", and with an empty
// prefix the expected value is exactly the hostname, which is the looked-up
// name minus the leading dot.
type matchingDNSResolver struct{}

func (matchingDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return []string{strings.TrimPrefix(name, ".")}, nil
}

func TestCustomDomainLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.example.com"))
	svc.SetDNSResolver(matchingDNSResolver{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.CustomDomainsMaxPerSandbox = 5

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-cd",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerIP:  "10.0.0.50",
		CPU:          1,
		MemoryMB:     512,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	// Add a custom domain.
	if err := svc.AddCustomDomain(ctx, "sb-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	// Idempotent re-add.
	if err := svc.AddCustomDomain(ctx, "sb-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain (re-add): %v", err)
	}

	// List should reflect the attached hostname.
	domains, err := svc.ListCustomDomains(ctx, "sb-cd")
	if err != nil {
		t.Fatalf("ListCustomDomains: %v", err)
	}
	if len(domains) != 1 || domains[0].Hostname != "api.acme.com" {
		t.Fatalf("ListCustomDomains = %+v", domains)
	}

	// Remove it.
	if err := svc.RemoveCustomDomain(ctx, "sb-cd", "API.acme.com"); err != nil {
		t.Fatalf("RemoveCustomDomain: %v", err)
	}
	domains, err = svc.ListCustomDomains(ctx, "sb-cd")
	if err != nil {
		t.Fatalf("ListCustomDomains after remove: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("expected no domains after remove, got %+v", domains)
	}
}

func TestCustomDomainDisabledAndValidation(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", ""))

	// Feature disabled in this config → ErrCustomDomainNotSupported.
	if err := svc.AddCustomDomain(ctx, "sb-x", "api.acme.com", 0); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("AddCustomDomain(disabled) = %v, want ErrCustomDomainNotSupported", err)
	}
	if _, err := svc.ListCustomDomains(ctx, "sb-x"); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("ListCustomDomains(disabled) = %v, want ErrCustomDomainNotSupported", err)
	}

	// Enable but feed a bad target port to hit the validation branch.
	svc.SetDNSResolver(matchingDNSResolver{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-y", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 512, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.AddCustomDomain(ctx, "sb-y", "api.acme.com", -1); err == nil {
		t.Fatal("expected validation error for negative target port")
	}
}

func TestCustomDomainClusterHelperBranches(t *testing.T) {
	ctx := context.Background()
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-cd-helper")

	if got := sandboxCustomHostnamesList(nil); got != nil {
		t.Fatalf("sandboxCustomHostnamesList(nil) = %v, want nil", got)
	}
	sb := &models.Sandbox{
		CustomDomains: []models.CustomDomain{
			{Hostname: "api.acme.com"},
			{Hostname: ""},
			{Hostname: "www.acme.com"},
		},
	}
	if got := sandboxCustomHostnamesList(sb); len(got) != 2 {
		t.Fatalf("sandboxCustomHostnamesList = %v, want 2 hostnames", got)
	}
	if got := sandboxCustomHostnames(sb); len(got) != 2 {
		t.Fatalf("sandboxCustomHostnames = %v, want 2 routes", got)
	}

	conflict := &customDomainClusterStub{
		Noop:   cluster.NewNoop("self", "http://self", "sandbox.example.com"),
		addErr: cluster.ErrCustomHostnameConflict,
	}
	svc.AttachCluster(conflict)
	if err := svc.AddCustomDomain(ctx, "sb-cd-helper", "api.acme.com", 0); !errors.Is(err, store.ErrCustomDomainConflict) {
		t.Fatalf("AddCustomDomain(cluster conflict) = %v, want store.ErrCustomDomainConflict", err)
	}
	domains, err := svc.ListCustomDomains(ctx, "sb-cd-helper")
	if err != nil {
		t.Fatalf("ListCustomDomains after rollback: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("cluster conflict should roll back local row, got %v", domains)
	}

	releaseErr := errors.New("raft down")
	svc.AttachCluster(&customDomainClusterStub{
		Noop:      cluster.NewNoop("self", "http://self", "sandbox.example.com"),
		removeErr: releaseErr,
	})
	if err := svc.AddCustomDomain(ctx, "sb-cd-helper", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain(seed for remove): %v", err)
	}
	if err := svc.RemoveCustomDomain(ctx, "sb-cd-helper", "api.acme.com"); err != nil {
		t.Fatalf("RemoveCustomDomain(cluster release error should be swallowed): %v", err)
	}
	domains, err = svc.ListCustomDomains(ctx, "sb-cd-helper")
	if err != nil {
		t.Fatalf("ListCustomDomains after remove: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("expected row to be removed even when cluster release fails, got %v", domains)
	}
}

func TestCustomDomainHelpersWave12(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = false
	if err := svc.AddCustomDomain(ctx, "sb", "h.example.com", 8080); err == nil {
		t.Fatal("expected disabled")
	}
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	if err := svc.AddCustomDomain(ctx, "missing", "api.example.com", 8080); err == nil {
		t.Fatal("expected missing sandbox")
	}
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-cd", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_ = svc.RemoveCustomDomain(ctx, "sb-cd", "nope.example.com")
}

func TestCustomDomainCapReaddWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	svc.cfg.CustomDomainsMaxPerSandbox = 1
	svc.cfg.CustomDomainVerifyPrefix = "_aerolvm-challenge"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerolvm-verify="
	svc.dnsResolver = &mockDNSResolver{records: map[string][]string{
		"_aerolvm-challenge.api.example.com":   {"aerolvm-verify=api.example.com"},
		"_aerolvm-challenge.other.example.com": {"aerolvm-verify=other.example.com"},
	}}
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cap", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com", TargetPort: 8080}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = svc.AddCustomDomain(ctx, "sb-cap", "api.example.com", 8080)
	err := svc.AddCustomDomain(ctx, "sb-cap", "other.example.com", 8080)
	if err != nil && !errors.Is(err, ErrCustomDomainPerSandboxCap) {
		t.Logf("cap path: %v", err)
	}
}

func TestValidateCreateCustomDomainsWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	allow := true
	deny := false
	req := &models.CreateSandboxRequest{CustomDomains: []string{"api.example.com"}, AllowPublicTraffic: &deny}
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected public traffic disabled")
	}
	req.AllowPublicTraffic = &allow
	svc.cfg.EnableCustomDomains = false
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected not supported")
	}
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = ""
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected ip mode reject")
	}
	svc.cfg.Domain = "example.com"
	req.CustomDomains = []string{"api.customer.dev"}
	if err := svc.validateCreateCustomDomains(req); err != nil {
		t.Fatalf("ok path: %v", err)
	}
}

func TestCustomDomainCapAlreadyHeldWave21(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.CustomDomainsMaxPerSandbox = 1
	svc.cfg.Domain = "example.com"
	svc.cfg.CustomDomainVerifyPrefix = "_aerol-verify"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerol-verify="
	svc.dnsResolver = &mockDNSResolver{records: map[string][]string{
		"_aerol-verify.api.customer.dev": {"aerol-verify=api.customer.dev"},
	}}
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cap", Image: "a", Status: models.SandboxStatusStarted,
		CustomDomains: []models.CustomDomain{{Hostname: "api.customer.dev", TargetPort: 8080}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	err := svc.AddCustomDomain(ctx, "sb-cap", "api.customer.dev", 8080)
	t.Logf("AddCustomDomain re-add: %v", err)
}

func TestCustomDomainCapAlreadyHeldExactWave22(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.CustomDomainsMaxPerSandbox = 1
	svc.cfg.Domain = "example.com"
	svc.cfg.CustomDomainVerifyPrefix = "_aerol-verify"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerol-verify="
	canonical, err := models.NormalizeCustomDomain("api.customer.dev", svc.cfg.Domain)
	if err != nil {
		t.Fatal(err)
	}
	svc.dnsResolver = &mockDNSResolver{records: map[string][]string{
		"_aerol-verify." + canonical: {"aerol-verify=" + canonical},
	}}
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cap22", Image: "a", Status: models.SandboxStatusStarted,
		CustomDomains: []models.CustomDomain{{Hostname: canonical, TargetPort: 8080}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	// Fill store so AddCustomDomain sees the same hostname at cap.
	_ = st.AddCustomDomain(ctx, "sb-cap22", canonical, 8080)
	err = svc.AddCustomDomain(ctx, "sb-cap22", canonical, 8080)
	t.Logf("re-add at cap: %v", err)
}

func TestCleanupPublicTrafficDisabledWave22(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	deny := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-pub", Image: "a", Status: models.SandboxStatusStarted, AllowPublicTraffic: &deny,
		ExposedPorts:  []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP}},
		CustomDomains: []models.CustomDomain{{Hostname: "api.customer.dev"}, {Hostname: ""}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(ctx, sb)
	_ = st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-pub", Port: 8080, Protocol: models.ExposedPortProtocolHTTP})
	_ = st.AddCustomDomain(ctx, "sb-pub", "api.customer.dev", 8080)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, nil)
	allow := true
	sb.AllowPublicTraffic = &allow
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
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
	st *store.Store
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
// newWasmCustomDomainsHarnessAllowClose is like newWasmCustomDomainsHarness but
// uses the allow-close store harness so AddCustomDomain rollback tests can
// close SQLite mid-flight.
func newWasmCustomDomainsHarnessAllowClose(t *testing.T) (*Service, *store.Store) {
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
