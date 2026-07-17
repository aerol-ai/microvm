package models

import "testing"

func TestDNSRecordName_ApexRoot(t *testing.T) {
	if got := dnsRecordName("acme.com"); got != "@" {
		t.Fatalf("dnsRecordName(acme.com) = %q, want @", got)
	}
}

func TestDNSRecordName_PublicSuffixSubdomain(t *testing.T) {
	if got := dnsRecordName("api.example.co.uk"); got != "api" {
		t.Fatalf("dnsRecordName(api.example.co.uk) = %q, want api", got)
	}
}

func TestDNSRecordName_SingleLabelHost(t *testing.T) {
	if got := dnsRecordName("localhost"); got != "@" {
		t.Fatalf("dnsRecordName(localhost) = %q, want @", got)
	}
}
