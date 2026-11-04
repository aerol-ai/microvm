package caddy

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestOnDemandIssuer (§5.10 PC-5): custom-domain certificates come from the
// configured issuer: public ACME by default, an internal ACME CA with its
// trusted root, or Caddy's own CA.
func TestOnDemandIssuer(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  config.Config
		want map[string]any
	}{
		"default":  {config.Config{}, map[string]any{"module": "acme"}},
		"acme":     {config.Config{TLSIssuer: config.TLSIssuerACME}, map[string]any{"module": "acme"}},
		"internal": {config.Config{TLSIssuer: config.TLSIssuerInternal}, map[string]any{"module": "internal"}},
		"step-ca": {config.Config{TLSACMECA: "https://ca.bank.internal/acme/acme/directory", TLSACMECARoot: "/etc/sandboxd/bank-root.pem"},
			map[string]any{"module": "acme", "ca": "https://ca.bank.internal/acme/acme/directory", "trusted_roots_pem_files": []any{"/etc/sandboxd/bank-root.pem"}}},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newFakeAutomationServer(t)
			client := New(tc.cfg)
			client.enabled, client.baseURL, client.httpClient = true, srv.URL, srv.Client
			if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 5, time.Minute); err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(srv.policies[0]["issuers"])
			want, _ := json.Marshal([]any{tc.want})
			if string(got) != string(want) {
				t.Fatalf("issuers = %s, want %s", got, want)
			}
			// A second start finds it in place and writes nothing.
			if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 5, time.Minute); err != nil {
				t.Fatal(err)
			}
			if len(srv.policies) != 1 || len(srv.issuerWrites) != 0 {
				t.Fatalf("not idempotent: %d policies, writes %v", len(srv.policies), srv.issuerWrites)
			}
		})
	}
}

// TestOnDemandIssuerReconciles: changing the settings repoints the existing
// policy on the next start, and unsetting them goes back to public ACME; an
// operator's extra fields survive when the issuer already matches.
func TestOnDemandIssuerReconciles(t *testing.T) {
	ctx := context.Background()
	srv := newFakeAutomationServer(t)
	srv.policies = []map[string]any{
		{"subjects": []any{"*.aerol.cloud"}, "issuers": []any{map[string]any{"module": "acme"}}},
		{"on_demand": true, "issuers": []any{map[string]any{"module": "acme", "email": "ops@bank.example"}}},
	}
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(srv.issuerWrites) != 0 {
		t.Fatalf("a matching issuer (plus an email) must be left alone: %v", srv.issuerWrites)
	}

	client.onDemandIssuer = TLSIssuer{CA: "https://ca.bank.internal/acme/acme/directory"}
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(srv.issuerWrites, []string{"PATCH 1"}) {
		t.Fatalf("writes = %v", srv.issuerWrites)
	}
	if iss := srv.policies[1]["issuers"].([]any)[0].(map[string]any); iss["ca"] != "https://ca.bank.internal/acme/acme/directory" {
		t.Fatalf("issuer = %v", iss)
	}
	if iss := srv.policies[0]["issuers"].([]any)[0].(map[string]any); iss["ca"] != nil {
		t.Fatalf("the wildcard policy must not be touched: %v", iss)
	}

	client.onDemandIssuer = TLSIssuer{}
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	if iss := srv.policies[1]["issuers"].([]any)[0].(map[string]any); iss["ca"] != nil || iss["module"] != "acme" {
		t.Fatalf("unset must go back to public ACME: %v", iss)
	}

	// A policy without issuers uses Caddy's public defaults: fine for the
	// default, created for an internal CA.
	delete(srv.policies[1], "issuers")
	srv.issuerWrites = nil
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err != nil || len(srv.issuerWrites) != 0 {
		t.Fatalf("default over Caddy's defaults: %v, %v", err, srv.issuerWrites)
	}
	client.onDemandIssuer = TLSIssuer{Internal: true}
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(srv.issuerWrites, []string{"PUT 1"}) {
		t.Fatalf("writes = %v", srv.issuerWrites)
	}

	// The admin API refusing the write is an error, not a silent mismatch:
	// an explicit null is a present key, so the PUT gets 409.
	srv.policies[1]["issuers"] = nil
	client.onDemandIssuer = TLSIssuer{CA: "https://ca.bank.internal/acme/acme/directory"}
	if err := client.EnsureOnDemandTLS(ctx, "http://x/ask", 5, time.Minute); err == nil {
		t.Fatal("a refused issuer write must fail")
	}
}

func TestTLSIssuerMatches(t *testing.T) {
	ca := TLSIssuer{CA: "https://ca/dir", TrustedRoot: "/r.pem"}
	for name, tc := range map[string]struct {
		i      TLSIssuer
		stored string
		want   bool
	}{
		"default vs none":       {TLSIssuer{}, ``, true},
		"default vs null":       {TLSIssuer{}, `null`, true},
		"ca vs none":            {ca, ``, false},
		"two issuers":           {TLSIssuer{}, `[{"module":"acme"},{"module":"zerossl"}]`, false},
		"bad json":              {TLSIssuer{}, `{`, false},
		"ca match":              {ca, `[{"module":"acme","ca":"https://ca/dir","trusted_roots_pem_files":["/r.pem"]}]`, true},
		"ca root differs":       {ca, `[{"module":"acme","ca":"https://ca/dir","trusted_roots_pem_files":["/other.pem"]}]`, false},
		"internal match":        {TLSIssuer{Internal: true}, `[{"module":"internal"}]`, true},
		"internal vs acme":      {TLSIssuer{Internal: true}, `[{"module":"acme"}]`, false},
		"default vs internal":   {TLSIssuer{}, `[{"module":"internal"}]`, false},
		"default ignores email": {TLSIssuer{}, `[{"module":"acme","email":"a@b"}]`, true},
	} {
		if got := tc.i.matches(json.RawMessage(tc.stored)); got != tc.want {
			t.Errorf("%s: matches = %v, want %v", name, got, tc.want)
		}
	}
}
