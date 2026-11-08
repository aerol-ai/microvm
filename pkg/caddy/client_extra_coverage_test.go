package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestUpsertHelpers_AgainstFakeCaddy(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}

	// InFlux route upserts
	if err := client.UpsertInFluxSandboxRoute(ctx, "abc"); err != nil {
		t.Fatalf("UpsertInFluxSandboxRoute: %v", err)
	}
	if err := client.UpsertInFluxPortRoute(ctx, "abc", 8080); err != nil {
		t.Fatalf("UpsertInFluxPortRoute: %v", err)
	}

	// PortRoute with retry
	if err := client.UpsertPortRouteWithRetry(ctx, "abc", "10.0.0.1", 8080, 0); err != nil {
		t.Fatalf("UpsertPortRouteWithRetry: %v", err)
	}

	// Layer4 checks
	if err := client.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err != nil {
		t.Fatalf("EnsureLayer4: %v", err)
	}

	// TCP route upsert and delete
	if err := client.UpsertTCPRoute(ctx, "abc", "10.0.0.1", 1234, 1234); err != nil {
		t.Fatalf("UpsertTCPRoute: %v", err)
	}
	if err := client.UpsertTCPProxyRoute(ctx, "abc", 1235, 1235, "10.0.0.1", 1235); err != nil {
		t.Fatalf("UpsertTCPProxyRoute: %v", err)
	}
	if err := client.DeleteTCPRoute(ctx, 1234); err != nil {
		t.Fatalf("DeleteTCPRoute: %v", err)
	}

	// SNI routes
	if err := client.UpsertSNIPassthroughRoute(ctx, "abc", "sni.host", "peer.host", 443); err != nil {
		t.Fatalf("UpsertSNIPassthroughRoute: %v", err)
	}
	if err := client.UpsertTLSSNIRoute(ctx, "abc", "sni.host", "10.0.0.1", 443); err != nil {
		t.Fatalf("UpsertTLSSNIRoute: %v", err)
	}
	if err := client.UpsertWakeTLSSNIRoute(ctx, "abc", "sni.host", "/tmp/sock", 443); err != nil {
		t.Fatalf("UpsertWakeTLSSNIRoute: %v", err)
	}

	// Wake routes
	if err := client.UpsertWakeTCPRoute(ctx, "abc", 1234, 1234, "127.0.0.1:9090"); err != nil {
		t.Fatalf("UpsertWakeTCPRoute: %v", err)
	}
}

func TestUpsertHelpers_ErrorPaths(t *testing.T) {

	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	client := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}

	if err := client.UpsertSNIPassthroughRoute(ctx, "abc", "sni.host", "peer.host", 443); err == nil {
		t.Error("UpsertSNIPassthroughRoute: expected error on 500")
	}
	if err := client.UpsertTLSSNIRoute(ctx, "abc", "sni.host", "10.0.0.1", 443); err == nil {
		t.Error("UpsertTLSSNIRoute: expected error on 500")
	}
	if err := client.UpsertWakeTLSSNIRoute(ctx, "abc", "sni.host", "/tmp/sock", 443); err == nil {
		t.Error("UpsertWakeTLSSNIRoute: expected error on 500")
	}
	if err := client.UpsertWakeTCPRoute(ctx, "abc", 1234, 1234, "127.0.0.1:9090"); err == nil {
		t.Error("UpsertWakeTCPRoute: expected error on 500")
	}
	if err := client.UpsertTCPRoute(ctx, "abc", "10.0.0.1", 1234, 1234); err == nil {
		t.Error("UpsertTCPRoute: expected error on 500")
	}
	if err := client.UpsertTCPProxyRoute(ctx, "abc", 1235, 1235, "10.0.0.1", 1235); err == nil {
		t.Error("UpsertTCPProxyRoute: expected error on 500")
	}
	if err := client.DeleteTCPRoute(ctx, 1234); err == nil {
		t.Error("DeleteTCPRoute: expected error on 500")
	}
	if err := client.EnsureLayer4(ctx, ":443", "127.0.0.1:8443"); err == nil {
		t.Error("EnsureLayer4: expected error on 500")
	}
	if err := client.EnsureLayer4(ctx, ":443", ""); err == nil {
		t.Error("EnsureLayer4: expected error when fallback missing")
	}
	// Test EnsureOnDemandTLS error
	if err := client.EnsureOnDemandTLS(ctx, "http://ask", 10, 0); err == nil {
		t.Error("EnsureOnDemandTLS: expected error on 500")
	}
}

func TestPingAndSnapshot(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "config") {
			w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()
	client := &Client{enabled: true, baseURL: ts.URL, httpClient: ts.Client()}

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	if _, err := client.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
}

// UpsertFencedPortRoute writes a 503 + Retry-After under the port route's own
// @id and host matcher, so it replaces the proxy route in place. It is a
// no-op when Caddy is off or in IP mode, like UpsertPortRoute.
func TestUpsertFencedPortRoute(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	for _, off := range []*Client{
		{enabled: false, domain: "d.test", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client},
		{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client},
	} {
		if err := off.UpsertFencedPortRoute(ctx, "abc", 8080); err != nil {
			t.Fatalf("UpsertFencedPortRoute (off) = %v", err)
		}
	}
	if len(fake.routes) != 0 {
		t.Fatalf("a disabled or IP-mode client wrote routes: %v", fake.routes)
	}

	client := &Client{enabled: true, domain: "d.test", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
	if err := client.UpsertPortRoute(ctx, "abc", "10.0.0.1", 8080); err != nil {
		t.Fatal(err)
	}
	if err := client.UpsertFencedPortRoute(ctx, "abc", 8080); err != nil {
		t.Fatalf("UpsertFencedPortRoute: %v", err)
	}
	route, ok := fake.routes[PortRouteID("abc", 8080)]
	if !ok || len(fake.routes) != 1 {
		t.Fatalf("routes = %v, want only the port route, rewritten in place", fake.routes)
	}
	body, _ := json.Marshal(route)
	for _, want := range []string{`"static_response"`, `"status_code":503`, `"Retry-After":["2"]`, `"abc-8080.d.test"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("fenced route %s lacks %s", body, want)
		}
	}
	if strings.Contains(string(body), "reverse_proxy") {
		t.Fatalf("fenced route still proxies: %s", body)
	}
}

// UpsertFencedSandboxRoute writes the 503 under the root route's own @id and
// under each custom hostname's route id, so each replaces its live route in
// place. In IP mode the root route is a path route (as UpsertSandboxRoute
// writes it) and custom hostnames do not exist; a disabled client writes
// nothing.
func TestUpsertFencedSandboxRoute(t *testing.T) {
	ctx := context.Background()
	fake := newFakeCaddy(t)
	off := &Client{enabled: false, domain: "d.test", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
	if err := off.UpsertFencedSandboxRoute(ctx, "abc", []string{"app.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(fake.routes) != 0 {
		t.Fatalf("a disabled client wrote routes: %v", fake.routes)
	}

	client := &Client{enabled: true, domain: "d.test", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
	customs := []CustomHostnameRoute{{Hostname: "app.example.com"}, {Hostname: "api.example.com", TargetPort: 8080}}
	if err := client.UpsertSandboxRoute(ctx, "abc", "10.0.0.1", 2280, customs); err != nil {
		t.Fatal(err)
	}
	if err := client.UpsertFencedSandboxRoute(ctx, "abc", []string{"App.Example.com", " api.example.com", ""}); err != nil {
		t.Fatalf("UpsertFencedSandboxRoute: %v", err)
	}
	if len(fake.routes) != 3 {
		t.Fatalf("routes = %v, want the root and the two custom-domain routes, rewritten in place", fake.routes)
	}
	for id, host := range map[string]string{
		SandboxRouteID("abc"): "abc.d.test",
		IngressCustomDomainHTTPRouteID("abc", "app.example.com"): "app.example.com",
		IngressCustomDomainHTTPRouteID("abc", "api.example.com"): "api.example.com",
	} {
		body, _ := json.Marshal(fake.routes[id])
		for _, want := range []string{`"static_response"`, `"status_code":503`, `"Retry-After":["2"]`, `"` + host + `"`} {
			if !strings.Contains(string(body), want) {
				t.Fatalf("fenced route %s = %s, lacks %s", id, body, want)
			}
		}
		if strings.Contains(string(body), "reverse_proxy") {
			t.Fatalf("fenced route %s still proxies: %s", id, body)
		}
	}

	ipFake := newFakeCaddy(t)
	ip := &Client{enabled: true, serverID: "srv0", baseURL: ipFake.URL, httpClient: ipFake.Client}
	if err := ip.UpsertFencedSandboxRoute(ctx, "abc", []string{"app.example.com"}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(ipFake.routes[SandboxRouteID("abc")])
	if len(ipFake.routes) != 1 || !strings.Contains(string(body), `"/abc/*"`) || !strings.Contains(string(body), `"status_code":503`) {
		t.Fatalf("IP mode: routes = %v (root %s), want only the root path route as a 503", ipFake.routes, body)
	}
}

// The fenced TCP server keeps its listener and closes each connection; the
// fenced TLS route keeps its SNI matcher and closes. Neither proxies.
func TestUpsertFencedTCPAndTLSRoutes(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	bodies := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies[r.Method+" "+r.URL.Path] = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	off := &Client{enabled: false, domain: "d.test", baseURL: srv.URL, httpClient: srv.Client()}
	if err := off.UpsertFencedTCPRoute(ctx, "abc", 5432, 40001); err != nil {
		t.Fatal(err)
	}
	if err := off.UpsertFencedTLSSNIRoute(ctx, "abc", "abc-6379.d.test", 6379); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 0 {
		t.Fatalf("a disabled client wrote %v", bodies)
	}
	c := &Client{enabled: true, domain: "d.test", baseURL: srv.URL, httpClient: srv.Client()}
	if err := c.UpsertFencedTCPRoute(ctx, "abc", 5432, 0); err == nil {
		t.Fatal("host port 0 must be refused, like UpsertTCPRoute")
	}
	if err := c.UpsertFencedTCPRoute(ctx, "abc", 5432, 40001); err != nil {
		t.Fatal(err)
	}
	tcp := bodies["POST /config/apps/layer4/servers/tcp-port-40001"]
	for _, want := range []string{`"listen":[":40001"]`, `"@id":"sandbox-abc-port-5432-tcp"`, `"handler":"close"`} {
		if !strings.Contains(tcp, want) {
			t.Fatalf("fenced tcp server %s lacks %s", tcp, want)
		}
	}
	if err := c.UpsertFencedTLSSNIRoute(ctx, "abc", "abc-6379.d.test", 6379); err != nil {
		t.Fatal(err)
	}
	tls := bodies["PATCH /id/sandbox-abc-port-6379-tls"]
	for _, want := range []string{`"sni":["abc-6379.d.test"]`, `"handler":"close"`} {
		if !strings.Contains(tls, want) {
			t.Fatalf("fenced tls route %s lacks %s", tls, want)
		}
	}
	for _, b := range []string{tcp, tls} {
		if strings.Contains(b, `"proxy"`) {
			t.Fatalf("a fenced route still proxies: %s", b)
		}
	}
}

// The fenced TCP writer reports a refused write and an unreachable admin API
// like UpsertTCPRoute does, so the fence retries on the next check.
func TestUpsertFencedTCPRouteErrors(t *testing.T) {
	ctx := context.Background()
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer refuse.Close()
	c := &Client{enabled: true, domain: "d.test", baseURL: refuse.URL, httpClient: refuse.Client()}
	if err := c.UpsertFencedTCPRoute(ctx, "abc", 5432, 40001); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a 500 from the admin API = %v, want an error naming it", err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	c = &Client{enabled: true, domain: "d.test", baseURL: gone.URL, httpClient: gone.Client()}
	if err := c.UpsertFencedTCPRoute(ctx, "abc", 5432, 40001); err == nil {
		t.Fatal("an unreachable admin API must be an error")
	}
}
