package models

import (
	"strings"
	"testing"
)

// nonTXT filters out the always-emitted TXT verification record so tests
// focused on the CNAME/A/AAAA strategy don't have to re-count records every
// time the verification rule changes shape.
func nonTXT(recs []DNSRecord) []DNSRecord {
	out := make([]DNSRecord, 0, len(recs))
	for _, r := range recs {
		if r.Type == "TXT" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func TestComposeDNSRecords_SubdomainCNAME(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"api.acme.com"}, target, "_aerol-verify", "aerol-verify="))
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
	// Apex on a hostname ingress emits three flattening candidates
	// (CNAME/ANAME/ALIAS) at "@", all pointing at the same ingress host.
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"acme.com"}, target, "_aerol-verify", "aerol-verify="))
	wantTypes := []string{DNSRecordTypeCNAME, DNSRecordTypeANAME, DNSRecordTypeALIAS}
	if len(got) != len(wantTypes) {
		t.Fatalf("apex should produce %d flattening rows, got %d: %+v", len(wantTypes), len(got), got)
	}
	for i, r := range got {
		if r.Type != wantTypes[i] || r.Name != "@" || r.Value != "ingress.example.com" {
			t.Fatalf("row %d = %+v, want Type=%s Name=@ Value=ingress.example.com", i, r, wantTypes[i])
		}
	}
}

func TestComposeDNSRecords_ApexHostnameEmitsFlatteningAlternatives(t *testing.T) {
	// Each apex candidate must carry the pick-one guidance; the CNAME row
	// additionally keeps the Cloudflare gray-cloud warning.
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"acme.com"}, target, "_aerol-verify", "aerol-verify="))

	byType := make(map[string]DNSRecord, len(got))
	for _, r := range got {
		byType[r.Type] = r
	}
	for _, typ := range []string{DNSRecordTypeCNAME, DNSRecordTypeANAME, DNSRecordTypeALIAS} {
		r, ok := byType[typ]
		if !ok {
			t.Fatalf("missing %s apex row, got %+v", typ, got)
		}
		if !strings.Contains(r.Notes, "add only ONE") {
			t.Errorf("%s row missing pick-one note: %q", typ, r.Notes)
		}
	}
	// Only the CNAME row carries the gray-cloud proxy warning (Cloudflare
	// users add that row); ANAME/ALIAS rows must not.
	if !strings.Contains(byType[DNSRecordTypeCNAME].Notes, "gray cloud") {
		t.Errorf("apex CNAME row should keep the gray-cloud warning: %q", byType[DNSRecordTypeCNAME].Notes)
	}
	if strings.Contains(byType[DNSRecordTypeANAME].Notes, "gray cloud") {
		t.Errorf("ANAME row should not carry the gray-cloud warning: %q", byType[DNSRecordTypeANAME].Notes)
	}
}

func TestComposeDNSRecords_DeepSubdomainUsesFullPrefix(t *testing.T) {
	// DNS provider UIs (Cloudflare, Route 53, etc.) ask for the Name
	// relative to the managed zone. For host "a.b.c.acme.com" in zone
	// "acme.com", the correct Name is "a.b.c" — using just "a" would
	// create the wrong row.
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"a.b.c.acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 || got[0].Name != "a.b.c" {
		t.Fatalf("expected Name=a.b.c for deep subdomain, got %+v", got)
	}
}

func TestComposeDNSRecords_PublicSuffixApex(t *testing.T) {
	// example.co.uk is the zone root under the .co.uk public suffix —
	// the leftmost label "example" is NOT a subdomain. A naive
	// label-count heuristic would mis-render this as Name="example".
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"example.co.uk"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) == 0 {
		t.Fatal("expected apex flattening rows for example.co.uk, got none")
	}
	for _, r := range got {
		if r.Name != "@" {
			t.Fatalf("expected apex Name=@ for example.co.uk, got %+v", r)
		}
	}
}

func TestComposeDNSRecords_PublicSuffixSubdomain(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"api.example.co.uk"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 || got[0].Name != "api" {
		t.Fatalf("expected Name=api for api.example.co.uk, got %+v", got)
	}
}

func TestComposeDNSRecords_IPv4ProducesA(t *testing.T) {
	target := IngressTarget{IPs: []string{"203.0.113.10"}, Source: IngressTargetSourceIPs}
	got := nonTXT(ComposeDNSRecords([]string{"api.acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 || got[0].Type != DNSRecordTypeA || got[0].Value != "203.0.113.10" {
		t.Fatalf("expected single A record, got %+v", got)
	}
}

func TestComposeDNSRecords_IPv6ProducesAAAA(t *testing.T) {
	target := IngressTarget{IPs: []string{"2001:db8::1"}, Source: IngressTargetSourceIPs}
	got := nonTXT(ComposeDNSRecords([]string{"api.acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 || got[0].Type != DNSRecordTypeAAAA {
		t.Fatalf("expected AAAA for IPv6, got %+v", got)
	}
}

func TestComposeDNSRecords_MixedIPv4AndIPv6(t *testing.T) {
	target := IngressTarget{IPs: []string{"203.0.113.10", "2001:db8::1"}, Source: IngressTargetSourceIPs}
	got := nonTXT(ComposeDNSRecords([]string{"acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	if got[0].Type != DNSRecordTypeA || got[1].Type != DNSRecordTypeAAAA {
		t.Fatalf("expected [A, AAAA], got [%s, %s]", got[0].Type, got[1].Type)
	}
}

func TestComposeDNSRecords_MixedSourceSubdomainPrefersCNAME(t *testing.T) {
	// CNAME and A/AAAA cannot coexist at the same owner name (RFC 1034
	// §3.6.2); DNS providers reject the second row. For subdomains we
	// pick CNAME because it survives ingress IP changes.
	target := IngressTarget{
		Hostname: "ingress.example.com",
		IPs:      []string{"203.0.113.10"},
		Source:   IngressTargetSourceMixed,
	}
	got := nonTXT(ComposeDNSRecords([]string{"api.acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 {
		t.Fatalf("expected single record, got %d: %+v", len(got), got)
	}
	if got[0].Type != DNSRecordTypeCNAME || got[0].Value != "ingress.example.com" {
		t.Fatalf("expected single CNAME to ingress.example.com, got %+v", got[0])
	}
}

func TestComposeDNSRecords_MixedSourceApexPrefersIPs(t *testing.T) {
	// At the apex we prefer A/AAAA over CNAME because CNAME-at-apex
	// depends on provider-specific flattening (ALIAS / ANAME / alias
	// records) and many providers reject it outright.
	target := IngressTarget{
		Hostname: "ingress.example.com",
		IPs:      []string{"203.0.113.10", "2001:db8::1"},
		Source:   IngressTargetSourceMixed,
	}
	got := nonTXT(ComposeDNSRecords([]string{"acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 2 {
		t.Fatalf("expected A + AAAA at apex, got %d records: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Type == DNSRecordTypeCNAME {
			t.Fatalf("apex must not emit CNAME alongside A/AAAA, got %+v", r)
		}
		if r.Name != "@" {
			t.Fatalf("apex Name=%q, want @", r.Name)
		}
	}
}

func TestComposeDNSRecords_MultipleHostnames(t *testing.T) {
	// Subdomain → 1 CNAME (Name=api); apex → 3 flattening rows (Name=@).
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"api.acme.com", "acme.com"}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 4 {
		t.Fatalf("want 4 records (1 subdomain + 3 apex), got %d: %+v", len(got), got)
	}
	if got[0].Name != "api" || got[0].Type != DNSRecordTypeCNAME {
		t.Fatalf("expected first row CNAME api, got %+v", got[0])
	}
	for _, r := range got[1:] {
		if r.Name != "@" {
			t.Fatalf("expected apex rows at @, got %+v", r)
		}
	}
}

func TestComposeDNSRecords_EmptyInputReturnsNil(t *testing.T) {
	if got := ComposeDNSRecords(nil, IngressTarget{Hostname: "x.example.com"}, "_aerol-verify", "aerol-verify="); got != nil {
		t.Fatalf("expected nil for empty hostnames, got %+v", got)
	}
	if got := ComposeDNSRecords([]string{"api.acme.com"}, IngressTarget{Source: IngressTargetSourceUnknown}, "_aerol-verify", "aerol-verify="); got != nil {
		t.Fatalf("expected nil for empty target, got %+v", got)
	}
}

func TestComposeDNSRecords_NormalizesHostname(t *testing.T) {
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := nonTXT(ComposeDNSRecords([]string{"  API.Acme.COM.  "}, target, "_aerol-verify", "aerol-verify="))
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].Hostname != "api.acme.com" || got[0].Name != "api" {
		t.Fatalf("expected normalized api.acme.com, got %+v", got[0])
	}
}

func TestComposeDNSRecords_IncludesTXTRecord(t *testing.T) {
	// TXT value is the hostname itself (not a sandbox ID) so the record
	// proves zone control, can be provisioned before any sandbox exists,
	// and survives sandbox recreates.
	target := IngressTarget{Hostname: "ingress.example.com", Source: IngressTargetSourceHostname}
	got := ComposeDNSRecords([]string{"api.acme.com"}, target, "_aerol-verify", "aerol-verify=")

	txtFound := false
	for _, r := range got {
		if r.Type == "TXT" {
			txtFound = true
			if r.Name != "_aerol-verify.api" {
				t.Errorf("TXT Name = %q, want _aerol-verify.api", r.Name)
			}
			if r.Value != "aerol-verify=api.acme.com" {
				t.Errorf("TXT Value = %q, want aerol-verify=api.acme.com", r.Value)
			}
		}
	}
	if !txtFound {
		t.Fatal("expected TXT record for ownership verification, none found")
	}
}
