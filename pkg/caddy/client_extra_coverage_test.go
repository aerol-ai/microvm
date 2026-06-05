package caddy

import (
	"context"
	"strings"
	"testing"
)

// Covers the pure accessors / ID generators and the delete helpers that the
// existing table tests skipped.

func TestClientAccessors(t *testing.T) {
	c := &Client{
		domain:        "sandbox.example.com",
		publicHost:    "203.0.113.10",
		l4TLSListen:   ":443",
		l4TLSFallback: "127.0.0.1:8443",
	}
	if c.L4TLSListen() != ":443" {
		t.Fatalf("L4TLSListen = %q", c.L4TLSListen())
	}
	if c.L4TLSFallback() != "127.0.0.1:8443" {
		t.Fatalf("L4TLSFallback = %q", c.L4TLSFallback())
	}
	if got := c.SNIHost("abc", 3000); got != "abc-3000.sandbox.example.com" {
		t.Fatalf("SNIHost = %q", got)
	}
	// Domain mode: PublicHost returns the base domain.
	if got := c.PublicHost(); got != "sandbox.example.com" {
		t.Fatalf("PublicHost(domain mode) = %q", got)
	}

	// IP mode: SNIHost empty, PublicHost falls back to the IP.
	ip := &Client{publicHost: "203.0.113.10"}
	if got := ip.SNIHost("abc", 3000); got != "" {
		t.Fatalf("SNIHost(ip mode) = %q, want empty", got)
	}
	if got := ip.PublicHost(); got != "203.0.113.10" {
		t.Fatalf("PublicHost(ip mode) = %q", got)
	}
}

func TestExportedRouteIDs(t *testing.T) {
	if SandboxRouteID("abc") == "" {
		t.Fatal("SandboxRouteID empty")
	}
	if !strings.Contains(PortRouteID("abc", 3000), "3000") {
		t.Fatalf("PortRouteID = %q", PortRouteID("abc", 3000))
	}
	if !strings.Contains(WakePortRouteID("abc", 3000), "wake") {
		t.Fatalf("WakePortRouteID = %q", WakePortRouteID("abc", 3000))
	}
	if !strings.Contains(InFluxSandboxRouteID("abc"), "abc") {
		t.Fatalf("InFluxSandboxRouteID = %q", InFluxSandboxRouteID("abc"))
	}
	if !strings.Contains(InFluxPortRouteID("abc", 3000), "3000") {
		t.Fatalf("InFluxPortRouteID = %q", InFluxPortRouteID("abc", 3000))
	}
	if !strings.Contains(IngressSandboxSNIRouteID("abc"), "ingress-sni") {
		t.Fatalf("IngressSandboxSNIRouteID = %q", IngressSandboxSNIRouteID("abc"))
	}
	if !strings.Contains(IngressPortSNIRouteID("abc", 3000), "ingress-sni") {
		t.Fatalf("IngressPortSNIRouteID = %q", IngressPortSNIRouteID("abc", 3000))
	}
	// Hostname is hashed: same input → same ID, different host → different ID.
	a := IngressCustomDomainSNIRouteID("abc", "API.acme.com")
	b := IngressCustomDomainSNIRouteID("abc", "api.acme.com")
	if a != b {
		t.Fatalf("case-insensitive hostname should hash equal: %q vs %q", a, b)
	}
	if a == IngressCustomDomainSNIRouteID("abc", "other.acme.com") {
		t.Fatal("distinct hostnames must yield distinct IDs")
	}
}

func TestDeleteHelpers_Disabled(t *testing.T) {
	// Disabled client short-circuits every delete to nil with no admin call.
	c := &Client{enabled: false}
	ctx := context.Background()
	if err := c.DeleteRouteByID(ctx, "rt"); err != nil {
		t.Fatalf("DeleteRouteByID(disabled) = %v", err)
	}
	if err := c.DeleteTCPServer(ctx, "tcp-port-1"); err != nil {
		t.Fatalf("DeleteTCPServer(disabled) = %v", err)
	}
	if err := c.DeleteInFluxPortRoute(ctx, "abc", 3000); err != nil {
		t.Fatalf("DeleteInFluxPortRoute(disabled) = %v", err)
	}
	// Empty IDs are also no-ops even when enabled.
	c.enabled = true
	if err := c.DeleteRouteByID(ctx, ""); err != nil {
		t.Fatalf("DeleteRouteByID(empty) = %v", err)
	}
	if err := c.DeleteTCPServer(ctx, ""); err != nil {
		t.Fatalf("DeleteTCPServer(empty) = %v", err)
	}
}

func TestDeleteHelpers_AgainstFakeCaddy(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}

	// DeleteRouteByID against an existing route.
	fake.routes["rt-1"] = map[string]any{"@id": "rt-1"}
	if err := client.DeleteRouteByID(ctx, "rt-1"); err != nil {
		t.Fatalf("DeleteRouteByID: %v", err)
	}
	if _, ok := fake.routes["rt-1"]; ok {
		t.Fatal("route rt-1 should be deleted")
	}

	// DeleteInFluxPortRoute issues a DELETE (not-found tolerated).
	if err := client.DeleteInFluxPortRoute(ctx, "abc", 3000); err != nil {
		t.Fatalf("DeleteInFluxPortRoute: %v", err)
	}

	// DeleteTCPServer against an existing l4 server.
	fake.l4Servers["tcp-port-31000"] = map[string]any{}
	if err := client.DeleteTCPServer(ctx, "tcp-port-31000"); err != nil {
		t.Fatalf("DeleteTCPServer: %v", err)
	}
	if _, ok := fake.l4Servers["tcp-port-31000"]; ok {
		t.Fatal("l4 server should be deleted")
	}
	// DeleteTCPServer on a missing server tolerates 404.
	if err := client.DeleteTCPServer(ctx, "tcp-port-99999"); err != nil {
		t.Fatalf("DeleteTCPServer(missing): %v", err)
	}
}
