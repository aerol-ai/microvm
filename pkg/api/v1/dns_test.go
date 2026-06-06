package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestV1IngressDNS_ReturnsTargetWhenPublicHostSet(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.PublicHost = "ingress.example.com"
	})
	rr := do(t, env.mux, http.MethodGet, "/v1/ingress/dns", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got models.IngressTarget
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if got.Hostname != "ingress.example.com" {
		t.Fatalf("Hostname=%q, want ingress.example.com", got.Hostname)
	}
	if got.Source != models.IngressTargetSourceHostname {
		t.Fatalf("Source=%q, want hostname", got.Source)
	}
}

func TestV1IngressDNS_ReturnsUnknownWhenNoPublicHost(t *testing.T) {
	// Custom domains disabled and no public host set — the endpoint still
	// answers (it's not gated on EnableCustomDomains) but the Source signals
	// the caller that there's no usable target.
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.EnableCustomDomains = false
		c.Domain = ""
		c.PublicHost = ""
	})
	rr := do(t, env.mux, http.MethodGet, "/v1/ingress/dns", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got models.IngressTarget
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Source != models.IngressTargetSourceUnknown {
		t.Fatalf("Source=%q, want unknown", got.Source)
	}
}

func TestV1CustomDomainDNS_ReturnsRecordsAfterAttach(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.PublicHost = "ingress.example.com"
	})
	seedSandboxRowV1(t, env.store, "sb-1")
	if err := env.svc.AddCustomDomain(context.Background(), "sb-1", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	if err := env.svc.AddCustomDomain(context.Background(), "sb-1", "acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain apex: %v", err)
	}

	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1/custom-domains/dns", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got models.CustomDomainDNSRecords
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Target.Hostname != "ingress.example.com" {
		t.Fatalf("Target.Hostname=%q, want ingress.example.com", got.Target.Hostname)
	}
	// Two domains attached: api.acme.com (subdomain) → CNAME + TXT, and
	// acme.com (apex) → the three apex flattening candidates CNAME/ANAME/ALIAS
	// (caller picks one) + TXT. Total 6 records.
	if len(got.Records) != 6 {
		t.Fatalf("len(Records)=%d, want 6; got %+v", len(got.Records), got.Records)
	}

	cnames := 0
	anames := 0
	aliases := 0
	txts := 0
	for _, r := range got.Records {
		switch r.Type {
		case models.DNSRecordTypeCNAME:
			cnames++
			if r.Value != "ingress.example.com" {
				t.Fatalf("unexpected CNAME record %+v", r)
			}
		case models.DNSRecordTypeANAME:
			anames++
			if r.Value != "ingress.example.com" {
				t.Fatalf("unexpected ANAME record %+v", r)
			}
		case models.DNSRecordTypeALIAS:
			aliases++
			if r.Value != "ingress.example.com" {
				t.Fatalf("unexpected ALIAS record %+v", r)
			}
		case "TXT":
			txts++
			// Value is keyed to the hostname, not the sandbox ID — same
			// record works across sandbox recreates.
			wantValue := "aerol-verify=" + r.Hostname
			if r.Value != wantValue {
				t.Fatalf("TXT Value=%q, want %q (record=%+v)", r.Value, wantValue, r)
			}
		default:
			t.Fatalf("unexpected record %+v", r)
		}
	}

	// Subdomain CNAME + apex CNAME = 2; apex-only ANAME and ALIAS = 1 each;
	// one TXT per domain = 2.
	if cnames != 2 || anames != 1 || aliases != 1 || txts != 2 {
		t.Fatalf("expected 2 CNAME, 1 ANAME, 1 ALIAS, 2 TXT; got %d/%d/%d/%d",
			cnames, anames, aliases, txts)
	}
}

func TestV1CustomDomainDNS_EmptyRecordsWhenNoneAttached(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.PublicHost = "ingress.example.com"
	})
	seedSandboxRowV1(t, env.store, "sb-1")
	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1/custom-domains/dns", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got models.CustomDomainDNSRecords
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Records) != 0 {
		t.Fatalf("len(Records)=%d, want 0", len(got.Records))
	}
	if got.Target.Hostname != "ingress.example.com" {
		t.Fatalf("Target.Hostname=%q, want ingress.example.com — target should be returned even with no domains", got.Target.Hostname)
	}
}

func TestV1CustomDomainDNS_FeatureDisabledReturns412(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.EnableCustomDomains = false
	})
	seedSandboxRowV1(t, env.store, "sb-1")
	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-1/custom-domains/dns", nil)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d, want 412; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1CustomDomainDNS_SandboxNotFoundReturns404(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(c *config.Config) {
		c.PublicHost = "ingress.example.com"
	})
	rr := do(t, env.mux, http.MethodGet, "/v1/sandboxes/sb-missing/custom-domains/dns", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}
