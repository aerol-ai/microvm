package models

import (
	"strings"
	"testing"
)

func TestComposeDNSRecords_SubdomainCNAME(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"api.acme.com"}, target)
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	r := got[0]
	if r.Type != DNSRecordTypeCNAME || r.Name != "api" || r.Value != "ingress.example.com" || r.Hostname != "api.acme.com" {
		t.Fatalf("unexpected record: %+v", r)
	}
	if r.Notes == "" || !strings.Contains(r.Notes, "Cloudflare") {
		t.Fatalf("missing Cloudflare note: %q", r.Notes)
	}
}

func TestComposeDNSRecords_ApexCNAME(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"acme.com"}, target)
	if len(got) != 1 || got[0].Name != "@" || got[0].Type != DNSRecordTypeCNAME {
		t.Fatalf("apex should produce one CNAME with Name=@, got %+v", got)
	}
}

func TestComposeDNSRecords_DeepSubdomainUsesLeftmostLabel(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"a.b.c.acme.com"}, target)
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("expected Name=a for deep subdomain, got %+v", got)
	}
}

func TestComposeDNSRecords_IPv4ProducesA(t *testing.T) {
	target := IngressTarget{IPs: []string{"203.0.113.10"}, Source: IngressTargetSourceIPs}
	got := ComposeDNSRecords([]string{"api.acme.com"}, target)
	if len(got) != 1 || got[0].Type != DNSRecordTypeA || got[0].Value != "203.0.113.10" {
		t.Fatalf("expected single A record, got %+v", got)
	}
}

func TestComposeDNSRecords_IPv6ProducesAAAA(t *testing.T) {
	target := IngressTarget{IPs: []string{"2001:db8::1"}, Source: IngressTargetSourceIPs}
	got := ComposeDNSRecords([]string{"api.acme.com"}, target)
	if len(got) != 1 || got[0].Type != DNSRecordTypeAAAA {
		t.Fatalf("expected AAAA for IPv6, got %+v", got)
	}
}

func TestComposeDNSRecords_MixedIPv4AndIPv6(t *testing.T) {
	target := IngressTarget{IPs: []string{"203.0.113.10", "2001:db8::1"}, Source: IngressTargetSourceIPs}
	got := ComposeDNSRecords([]string{"acme.com"}, target)
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	if got[0].Type != DNSRecordTypeA || got[1].Type != DNSRecordTypeAAAA {
		t.Fatalf("expected [A, AAAA], got [%s, %s]", got[0].Type, got[1].Type)
	}
}

func TestComposeDNSRecords_MixedSourceEmitsBoth(t *testing.T) {
	target := IngressTarget{
		Hostname: "ingress.example.com",
		IPs:      []string{"203.0.113.10"},
		Source:   IngressTargetSourceMixed,
	}
	got := ComposeDNSRecords([]string{"api.acme.com"}, target)
	if len(got) != 2 {
		t.Fatalf("expected CNAME + A, got %d records: %+v", len(got), got)
	}
	if got[0].Type != DNSRecordTypeCNAME || got[1].Type != DNSRecordTypeA {
		t.Fatalf("expected [CNAME, A], got [%s, %s]", got[0].Type, got[1].Type)
	}
}

func TestComposeDNSRecords_MultipleHostnames(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"api.acme.com", "acme.com"}, target)
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	if got[0].Name != "api" || got[1].Name != "@" {
		t.Fatalf("expected [api, @], got [%s, %s]", got[0].Name, got[1].Name)
	}
}

func TestComposeDNSRecords_EmptyInputReturnsNil(t *testing.T) {
	if got := ComposeDNSRecords(nil, IngressTarget{Hostname: "x.example.com"}); got != nil {
		t.Fatalf("expected nil for empty hostnames, got %+v", got)
	}
	if got := ComposeDNSRecords([]string{"api.acme.com"}, IngressTarget{Source: IngressTargetSourceUnknown}); got != nil {
		t.Fatalf("expected nil for empty target, got %+v", got)
	}
}

func TestComposeDNSRecords_NormalizesHostname(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"  API.Acme.COM.  "}, target)
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].Hostname != "api.acme.com" || got[0].Name != "api" {
		t.Fatalf("expected normalized api.acme.com, got %+v", got[0])
	}
}
