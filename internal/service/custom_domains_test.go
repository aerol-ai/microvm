package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newCustomDomainsHarness builds a minimal Service wired with an enabled
// feature flag and a base domain so the validate/add/remove paths exercise
// the real branches. Caddy is disabled so UpsertSandboxRoute is a no-op —
// these tests assert on the service+store layer; the matcher shape is
// covered separately in pkg/caddy/custom_domains_test.go.

type mockDNSResolver struct {
	records map[string][]string
	err     error
}

func (m *mockDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if txts, ok := m.records[name]; ok {
		return txts, nil
	}
	// For testing, if it's not found, maybe return a default or error
	// return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	// We'll just return not found for exact matches
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func newCustomDomainsHarness(t *testing.T, cfgOverride func(*config.Config)) (*Service, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Config{
		EnableCustomDomains:           true,
		Domain:                        "aerol.cloud",
		CustomDomainsMaxPerSandbox:    models.MaxCustomDomainsPerSandbox,
		CustomDomainVerifyPrefix:      "_aerol-verify",
		CustomDomainVerifyValuePrefix: "aerol-verify=",
	}
	if cfgOverride != nil {
		cfgOverride(&cfg)
	}
	svc := &Service{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		}),
		dnsResolver: &mockDNSResolver{
			// TXT value is the hostname itself (proves zone control,
			// reusable across sandbox recreates) — not the sandbox ID.
			records: map[string][]string{
				"_aerol-verify.api.acme.com":   {"aerol-verify=api.acme.com"},
				"_aerol-verify.h0.acme.com":    {"aerol-verify=h0.acme.com"},
				"_aerol-verify.h1.acme.com":    {"aerol-verify=h1.acme.com"},
				"_aerol-verify.extra.acme.com": {"aerol-verify=extra.acme.com"},
			},
		},
	}
	return svc, st
}

func mustCreateSandboxRow(t *testing.T, st *store.Store, id string, exposed ...models.ExposedPort) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:           id,
		Image:        "test-image",
		Status:       models.SandboxStatusStarted,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
		Lifecycle:    models.Lifecycle{},
		ExposedPorts: exposed,
	}
	if err := st.Create(context.Background(), sandbox); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	for _, ep := range exposed {
		ep.SandboxID = id
		ep.CreatedAt = now
		if err := st.UpsertPort(context.Background(), ep); err != nil {
			t.Fatalf("store.UpsertPort: %v", err)
		}
	}
	got, err := st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	return got
}

func TestValidateCreateCustomDomains_DisabledRejects(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, func(c *config.Config) {
		c.EnableCustomDomains = false
	})
	req := models.CreateSandboxRequest{CustomDomains: []string{"api.acme.com"}}
	if err := svc.validateCreateCustomDomains(&req); !errors.Is(err, models.ErrCustomDomainNotSupported) {
		t.Fatalf("disabled: got %v, want ErrCustomDomainNotSupported", err)
	}
}

func TestValidateCreateCustomDomains_IPModeRejects(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, func(c *config.Config) {
		c.Domain = ""
	})
	req := models.CreateSandboxRequest{CustomDomains: []string{"api.acme.com"}}
	if err := svc.validateCreateCustomDomains(&req); !errors.Is(err, models.ErrCustomDomainNotSupported) {
		t.Fatalf("ip mode: got %v, want ErrCustomDomainNotSupported", err)
	}
}

func TestValidateCreateCustomDomains_EmptyIsFine(t *testing.T) {
	// Even when disabled, a request with no custom_domains must pass —
	// otherwise every existing CreateSandbox path would break in deployments
	// that haven't turned the feature on.
	svc, _ := newCustomDomainsHarness(t, func(c *config.Config) {
		c.EnableCustomDomains = false
		c.Domain = ""
	})
	req := models.CreateSandboxRequest{}
	if err := svc.validateCreateCustomDomains(&req); err != nil {
		t.Fatalf("empty: got %v, want nil", err)
	}
}

func TestValidateCreateCustomDomains_NormalizesAndDedupes(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	req := models.CreateSandboxRequest{CustomDomains: []string{"API.Acme.com", "api.acme.com."}}
	if err := svc.validateCreateCustomDomains(&req); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(req.CustomDomains) != 1 || req.CustomDomains[0] != "api.acme.com" {
		t.Fatalf("normalized=%v, want [api.acme.com]", req.CustomDomains)
	}
}

func TestValidateCreateCustomDomains_InvalidHostnameRejects(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	req := models.CreateSandboxRequest{CustomDomains: []string{"single-label"}}
	if err := svc.validateCreateCustomDomains(&req); !errors.Is(err, models.ErrCustomDomainInvalid) {
		t.Fatalf("got %v, want ErrCustomDomainInvalid", err)
	}
}

func TestValidateCreateCustomDomains_UnderBaseDomainRejects(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	req := models.CreateSandboxRequest{CustomDomains: []string{"x.aerol.cloud"}}
	if err := svc.validateCreateCustomDomains(&req); !errors.Is(err, models.ErrCustomDomainInvalid) {
		t.Fatalf("got %v, want ErrCustomDomainInvalid", err)
	}
}

func TestAddCustomDomain_DisabledRejects(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, func(c *config.Config) {
		c.EnableCustomDomains = false
	})
	mustCreateSandboxRow(t, st, "sb-1")
	err := svc.AddCustomDomain(context.Background(), "sb-1", "api.acme.com", 0)
	if !errors.Is(err, models.ErrCustomDomainNotSupported) {
		t.Fatalf("got %v, want ErrCustomDomainNotSupported", err)
	}
}

func TestAddCustomDomain_HappyPath(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	if err := svc.AddCustomDomain(context.Background(), "sb-1", "API.Acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	domains, err := svc.ListCustomDomains(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("ListCustomDomains: %v", err)
	}
	if len(domains) != 1 || domains[0].Hostname != "api.acme.com" {
		t.Fatalf("after add: %v", domains)
	}
	if domains[0].Status != models.CustomDomainPendingDNS {
		t.Fatalf("status=%v, want pending_dns", domains[0].Status)
	}
}

func TestAddCustomDomain_IronRuleRejectsTCPExposure(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1", models.ExposedPort{
		SandboxID: "sb-1",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  22001,
	})
	err := svc.AddCustomDomain(context.Background(), "sb-1", "api.acme.com", 0)
	if !errors.Is(err, models.ErrCustomDomainProtocolConflict) {
		t.Fatalf("got %v, want ErrCustomDomainProtocolConflict", err)
	}
}

func TestAddCustomDomain_IdempotentReadd(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	ctx := context.Background()
	if err := svc.AddCustomDomain(ctx, "sb-1", "api.acme.com", 0); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := svc.AddCustomDomain(ctx, "sb-1", "API.Acme.com.", 0); err != nil {
		t.Fatalf("idempotent re-add: %v", err)
	}
	domains, _ := svc.ListCustomDomains(ctx, "sb-1")
	if len(domains) != 1 {
		t.Fatalf("expected 1 row after idempotent re-add, got %d", len(domains))
	}
}

func TestAddCustomDomain_CrossSandboxConflict(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-a")
	mustCreateSandboxRow(t, st, "sb-b")
	ctx := context.Background()
	if err := svc.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := svc.AddCustomDomain(ctx, "sb-b", "api.acme.com", 0)
	if !errors.Is(err, store.ErrCustomDomainConflict) {
		t.Fatalf("got %v, want ErrCustomDomainConflict", err)
	}
}

func TestAddCustomDomain_PerSandboxCap(t *testing.T) {
	const perSandboxCap = 2
	svc, st := newCustomDomainsHarness(t, func(c *config.Config) {
		c.CustomDomainsMaxPerSandbox = perSandboxCap // exercise the SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX override path
	})
	mustCreateSandboxRow(t, st, "sb-1")
	ctx := context.Background()
	for i := range perSandboxCap {
		host := "h" + itoa(i) + ".acme.com"
		if err := svc.AddCustomDomain(ctx, "sb-1", host, 0); err != nil {
			t.Fatalf("add %d (%s): %v", i, host, err)
		}
	}
	err := svc.AddCustomDomain(ctx, "sb-1", "extra.acme.com", 0)
	if !errors.Is(err, models.ErrCustomDomainPerSandboxCap) {
		t.Fatalf("got %v, want ErrCustomDomainPerSandboxCap", err)
	}
}

func TestAddCustomDomain_MissingSandboxReturns404(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	err := svc.AddCustomDomain(context.Background(), "nope", "api.acme.com", 0)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRemoveCustomDomain_HappyPath(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	ctx := context.Background()
	if err := svc.AddCustomDomain(ctx, "sb-1", "api.acme.com", 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.RemoveCustomDomain(ctx, "sb-1", "API.Acme.com"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	domains, _ := svc.ListCustomDomains(ctx, "sb-1")
	if len(domains) != 0 {
		t.Fatalf("after remove: %v", domains)
	}
}

func TestRemoveCustomDomain_CrossSandboxReturns404(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-a")
	mustCreateSandboxRow(t, st, "sb-b")
	ctx := context.Background()
	if err := svc.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := svc.RemoveCustomDomain(ctx, "sb-b", "api.acme.com")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestSandboxCustomHostnames(t *testing.T) {
	if got := sandboxCustomHostnames(nil); got != nil {
		t.Fatalf("nil sandbox: got %v, want nil", got)
	}
	sb := &models.Sandbox{}
	if got := sandboxCustomHostnames(sb); got != nil {
		t.Fatalf("empty CustomDomains: got %v, want nil", got)
	}
	sb.CustomDomains = []models.CustomDomain{
		{Hostname: "api.acme.com", TargetPort: 3333},
		{Hostname: ""}, // tolerated but skipped
		{Hostname: "admin.acme.com"},
	}
	got := sandboxCustomHostnames(sb)
	if len(got) != 2 {
		t.Fatalf("len(got)=%d, want 2; got=%+v", len(got), got)
	}
	if got[0].Hostname != "api.acme.com" || got[0].TargetPort != 3333 {
		t.Fatalf("got[0]=%+v, want {api.acme.com, 3333}", got[0])
	}
	if got[1].Hostname != "admin.acme.com" || got[1].TargetPort != 0 {
		t.Fatalf("got[1]=%+v, want {admin.acme.com, 0}", got[1])
	}
}

func TestHasL4Exposure(t *testing.T) {
	if hasL4Exposure(nil) {
		t.Fatalf("nil sandbox: want false")
	}
	if hasL4Exposure(&models.Sandbox{ExposedPorts: []models.ExposedPort{{Protocol: models.ExposedPortProtocolHTTP}}}) {
		t.Fatalf("http-only: want false")
	}
	if !hasL4Exposure(&models.Sandbox{ExposedPorts: []models.ExposedPort{{Protocol: models.ExposedPortProtocolTCP}}}) {
		t.Fatalf("tcp: want true")
	}
	if !hasL4Exposure(&models.Sandbox{ExposedPorts: []models.ExposedPort{{Protocol: models.ExposedPortProtocolTLS}}}) {
		t.Fatalf("tls: want true")
	}
}

// fakeEvicter captures the hostnames the service hands to the negative cache
// so we can assert AddCustomDomain punches the cache on success.
type fakeEvicter struct {
	mu   sync.Mutex
	hits []string
}

func (f *fakeEvicter) EvictNegativeCache(host string) {
	f.mu.Lock()
	f.hits = append(f.hits, host)
	f.mu.Unlock()
}

func TestAddCustomDomain_EvictsNegativeCacheOnSuccess(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-1")
	evict := &fakeEvicter{}
	svc.AttachCustomDomainCacheEvicter(evict)
	t.Cleanup(func() { svc.AttachCustomDomainCacheEvicter(nil) })

	if err := svc.AddCustomDomain(context.Background(), "sb-1", "api.acme.com", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	evict.mu.Lock()
	defer evict.mu.Unlock()
	if len(evict.hits) != 1 || evict.hits[0] != "api.acme.com" {
		t.Fatalf("evict hits = %v, want [api.acme.com]", evict.hits)
	}
}

// itoa is a tiny stand-in so the cap test doesn't pull strconv in only for
// generating sequential hostnames. Test-local; not used elsewhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
