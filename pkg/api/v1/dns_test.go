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
	if err := env.svc.AddCustomDomain(context.Background(), "sb-1", "api.acme.com"); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	if err := env.svc.AddCustomDomain(context.Background(), "sb-1", "acme.com"); err != nil {
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
	if len(got.Records) != 2 {
		t.Fatalf("len(Records)=%d, want 2; got %+v", len(got.Records), got.Records)
	}
	// Order matches insertion; both should be CNAME against the hostname target.
	for _, r := range got.Records {
		if r.Type != models.DNSRecordTypeCNAME || r.Value != "ingress.example.com" {
			t.Fatalf("unexpected record %+v", r)
		}
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
