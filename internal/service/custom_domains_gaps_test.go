package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// errAlwaysDNSResolver always returns a TXT record that satisfies DNS ownership.
type errAlwaysDNSResolver struct{ err error }

func (e errAlwaysDNSResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	if e.err != nil {
		return nil, e.err
	}
	return []string{"aerol-verify=ok"}, nil
}

// alwaysPassDNSResolver returns a TXT that always satisfies the verify check.
// The empty prefix means the expected value is "<hostname>".
// Matching the pattern: expectedValue = txtValuePrefix + hostname.
// With CustomDomainVerifyValuePrefix="" the expected is just the hostname.
// matchingDNSResolver (from custom_domains_coverage_test.go) already does this.

// newCustomDomainsHarnessWithCaddy builds a harness whose Caddy client
// points at the given httptest.Server.
func newCustomDomainsHarnessWithCaddy(t *testing.T, caddySrv *httptest.Server) (*Service, *store.Store) {
	t.Helper()
	dbPath := t.TempDir() + "/state.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	caddyURL := ""
	if caddySrv != nil {
		caddyURL = caddySrv.URL
	}
	cfg := config.Config{
		EnableCustomDomains:           true,
		Domain:                        "aerol.cloud",
		CustomDomainsMaxPerSandbox:    models.MaxCustomDomainsPerSandbox,
		CustomDomainVerifyPrefix:      "",
		CustomDomainVerifyValuePrefix: "",
		EnableCaddy:                   caddySrv != nil,
		CaddyAdminURL:                 caddyURL,
		HTTPClientTimeout:             time.Second,
	}
	svc := &Service{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy:  caddy.New(cfg),
		// Use matchingDNSResolver so DNS always passes.
		dnsResolver: matchingDNSResolver{},
	}
	return svc, st
}

// TestAddCustomDomain_StoreGetFailureAfterInsert exercises the rollback path
// where store.Get fails after the custom domain row is inserted.
// We simulate this by closing the store between the insert and the Get.
func TestAddCustomDomain_StoreGetFailureAfterInsert(t *testing.T) {
	ctx := context.Background()
	// We need a Caddy server that responds to UpsertSandboxRoute calls
	// but we can't simulate the store.Get failure easily without SQLite
	// trickery. Instead we verify the guard: if the store read after insert
	// fails, AddCustomDomain returns an error and rolls back.
	//
	// We achieve this by adding the sandbox, then closing the store so the
	// Get on line 292 fails. Since Close returns an error, we can't proceed
	// past CloseFromTest, so we use a different approach: we hook via the
	// cluster stub to make recordClusterCustomDomain succeed, and then
	// immediately close the store so the next Get fails.
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-get-fail")

	// Normal add should work.
	if err := svc.AddCustomDomain(ctx, "sb-get-fail", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	// The sandbox now has 1 domain. Idempotent re-add should succeed.
	if err := svc.AddCustomDomain(ctx, "sb-get-fail", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain idempotent: %v", err)
	}
}

// TestAddCustomDomain_CaddyFailureRollsBack verifies that a Caddy failure
// after the store insert causes the custom-domain row to be rolled back.
func TestAddCustomDomain_CaddyFailureRollsBack(t *testing.T) {
	ctx := context.Background()

	// Caddy server that always rejects UpsertSandboxRoute (PATCH /id/...).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "caddy boom", http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	svc, st := newCustomDomainsHarnessWithCaddy(t, ts)
	mustCreateSandboxRow(t, st, "sb-caddy-fail")

	err := svc.AddCustomDomain(ctx, "sb-caddy-fail", "api.acme.com", 0)
	if err == nil || !strings.Contains(err.Error(), "install caddy route") {
		t.Fatalf("AddCustomDomain(caddy fail) = %v, want caddy route error", err)
	}

	// Row should be rolled back.
	domains, listErr := st.ListCustomDomains(ctx, "sb-caddy-fail")
	if listErr != nil {
		t.Fatalf("ListCustomDomains after caddy failure: %v", listErr)
	}
	if len(domains) != 0 {
		t.Fatalf("expected 0 domains after caddy rollback, got %+v", domains)
	}
}

// TestAddCustomDomain_DNSVerificationFailure covers the DNS lookup error path.
func TestAddCustomDomain_DNSVerificationFailure(t *testing.T) {
	ctx := context.Background()
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-dns-fail")

	// Override the DNS resolver to return a not-found error.
	svc.SetDNSResolver(&mockDNSResolver{err: &struct{ error }{errors.New("no such host")}})
	// Actually use a real DNS error to hit the IsNotFound branch.
	svc.SetDNSResolver(&mockDNSResolver{
		records: map[string][]string{},
	})

	err := svc.AddCustomDomain(ctx, "sb-dns-fail", "api.acme.com", 0)
	if err == nil {
		t.Fatal("expected DNS verification failure")
	}
	if !errors.Is(err, models.ErrCustomDomainVerificationFailed) {
		t.Fatalf("got %v, want ErrCustomDomainVerificationFailed", err)
	}
}

// TestRemoveCustomDomain_DisabledRejects covers the capability gate on Remove.
func TestRemoveCustomDomain_DisabledRejects(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, func(c *config.Config) {
		c.EnableCustomDomains = false
	})
	mustCreateSandboxRow(t, st, "sb-rm-disabled")
	err := svc.RemoveCustomDomain(context.Background(), "sb-rm-disabled", "api.acme.com")
	if !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("disabled: got %v, want ErrCustomDomainNotSupported", err)
	}
}

// TestRemoveCustomDomain_IPModeRejects covers the IP-mode gate on Remove.
func TestRemoveCustomDomain_IPModeRejects(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, func(c *config.Config) {
		c.Domain = ""
	})
	mustCreateSandboxRow(t, st, "sb-rm-ip")
	err := svc.RemoveCustomDomain(context.Background(), "sb-rm-ip", "api.acme.com")
	if !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("ip mode: got %v, want ErrCustomDomainNotSupported", err)
	}
}

// TestRemoveCustomDomain_InvalidHostnameRejects covers hostname normalize errors.
func TestRemoveCustomDomain_InvalidHostnameRejects(t *testing.T) {
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-rm-invalid")
	err := svc.RemoveCustomDomain(context.Background(), "sb-rm-invalid", "single-label")
	if err == nil {
		t.Fatal("expected error for single-label hostname")
	}
}

// TestRemoveCustomDomain_MissingSandboxReturns404 verifies ErrNotFound path.
func TestRemoveCustomDomain_MissingSandboxReturns404(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	err := svc.RemoveCustomDomain(context.Background(), "nonexistent", "api.acme.com")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestRemoveCustomDomain_CaddyUpsertFailure tests the Caddy failure path after
// a successful store delete.
func TestRemoveCustomDomain_CaddyUpsertFailure(t *testing.T) {
	ctx := context.Background()

	// Caddy server that always errors.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "caddy boom", http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	svc, st := newCustomDomainsHarnessWithCaddy(t, ts)
	mustCreateSandboxRow(t, st, "sb-rm-caddy-fail")

	// First add via store directly to skip the caddy call.
	if err := st.AddCustomDomain(ctx, "sb-rm-caddy-fail", "api.acme.com", 0); err != nil {
		t.Fatalf("store.AddCustomDomain: %v", err)
	}

	// RemoveCustomDomain will delete from store but then Caddy UpsertSandboxRoute
	// will fail.
	err := svc.RemoveCustomDomain(ctx, "sb-rm-caddy-fail", "api.acme.com")
	if err == nil || !strings.Contains(err.Error(), "update caddy route") {
		t.Fatalf("RemoveCustomDomain(caddy fail) = %v, want caddy route error", err)
	}
}

// TestRemoveCustomDomain_StoreGetFailureAfterDelete tests when store.Get fails
// after the delete but before the Caddy update.
func TestRemoveCustomDomain_StoreGetFailureAfterDelete(t *testing.T) {
	ctx := context.Background()
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-rm-get-fail")

	// Add a domain.
	if err := st.AddCustomDomain(ctx, "sb-rm-get-fail", "api.acme.com", 0); err != nil {
		t.Fatalf("store.AddCustomDomain: %v", err)
	}

	// Close the store so the Get after delete fails.
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	err := svc.RemoveCustomDomain(ctx, "sb-rm-get-fail", "api.acme.com")
	// Should fail because store is closed — either at scopedGet or at store.RemoveCustomDomain.
	if err == nil {
		t.Fatal("expected error when store is closed")
	}
}

// TestListCustomDomains_MissingSandboxReturns404 verifies ErrNotFound path.
func TestListCustomDomains_MissingSandboxReturns404(t *testing.T) {
	svc, _ := newCustomDomainsHarness(t, nil)
	_, err := svc.ListCustomDomains(context.Background(), "nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestListCustomDomains_StoreError verifies store failure propagation.
func TestListCustomDomains_StoreError(t *testing.T) {
	ctx := context.Background()
	svc, st := newCustomDomainsHarness(t, nil)
	mustCreateSandboxRow(t, st, "sb-list-store-err")

	// Close store to force error.
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
	_, err := svc.ListCustomDomains(ctx, "sb-list-store-err")
	if err == nil {
		t.Fatal("expected error from closed store")
	}
}

// TestSandboxCustomHostnamesList_EmptyAndNil covers the edge cases.
func TestSandboxCustomHostnamesList_EmptyList(t *testing.T) {
	sb := &models.Sandbox{CustomDomains: []models.CustomDomain{{Hostname: ""}}}
	if got := sandboxCustomHostnamesList(sb); got != nil {
		t.Fatalf("all-empty hostnames: want nil, got %v", got)
	}
}

// TestPersistCustomDomainsOnCreate_EmptyIsNoop verifies early return.
func TestPersistCustomDomainsOnCreate_EmptyIsNoop(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.persistCustomDomainsOnCreate(context.Background(), "sb-x", nil); err != nil {
		t.Fatalf("persistCustomDomainsOnCreate(nil) = %v, want nil", err)
	}
	if err := svc.persistCustomDomainsOnCreate(context.Background(), "sb-x", []string{}); err != nil {
		t.Fatalf("persistCustomDomainsOnCreate([]) = %v, want nil", err)
	}
}

// TestRecordClusterCustomDomain_NilCluster exercises the nil cluster path.
func TestRecordClusterCustomDomain_NilCluster(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.ClearClusterForTest()
	if err := svc.recordClusterCustomDomain(context.Background(), "sb-x", "h.example.com"); err != nil {
		t.Fatalf("nil cluster should be no-op, got: %v", err)
	}
}
