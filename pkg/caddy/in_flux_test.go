package caddy

import (
	"context"
	"net/http"
	"testing"
)

// TestInFluxRouteRespondsWith503 confirms UpsertInFluxSandboxRoute installs
// a static_response handler with status 503 and a Retry-After header. This
// is what clients see during the orphan window so they retry instead of
// treating the Caddy fallback 404 as "sandbox does not exist".
func TestInFluxRouteRespondsWith503(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}

	if err := client.UpsertInFluxSandboxRoute(context.Background(), "sb-1"); err != nil {
		t.Fatalf("UpsertInFluxSandboxRoute: %v", err)
	}
	route, ok := fake.routes["sandbox-sb-1-in-flux"]
	if !ok {
		t.Fatalf("in-flux route missing; routes=%+v", fake.routes)
	}
	handlers, _ := route["handle"].([]any)
	if len(handlers) != 1 {
		t.Fatalf("expected one handler, got %d", len(handlers))
	}
	h, _ := handlers[0].(map[string]any)
	if h["handler"] != "static_response" {
		t.Fatalf("handler = %v, want static_response", h["handler"])
	}
	if got := h["status_code"]; got != float64(503) {
		t.Fatalf("status_code = %v, want 503", got)
	}
	headers, _ := h["headers"].(map[string]any)
	retryAfter, _ := headers["Retry-After"].([]any)
	if len(retryAfter) != 1 || retryAfter[0] != "2" {
		t.Fatalf("Retry-After header = %v, want [\"2\"]", retryAfter)
	}
}

// TestInFluxRouteIDsHaveDistinctSuffix asserts the in-flux @ids do not
// collide with the live route @ids. Without this, the reconciler would
// overwrite live routes when applying in-flux for the same sandbox.
func TestInFluxRouteIDsHaveDistinctSuffix(t *testing.T) {
	if InFluxSandboxRouteID("sb-1") == sandboxRouteID("sb-1") {
		t.Fatalf("in-flux and live sandbox route IDs collided: %s", InFluxSandboxRouteID("sb-1"))
	}
	if InFluxPortRouteID("sb-1", 3000) == portRouteID("sb-1", 3000) {
		t.Fatalf("in-flux and live port route IDs collided: %s", InFluxPortRouteID("sb-1", 3000))
	}
}

// TestInFluxPortRouteMatchInDomainMode verifies the per-port in-flux route
// matches on the sub-domain hostname operators use for HTTP/TLS exposures.
// caddy-l4's SNI mux falls through to the local HTTPS listener for any host
// that doesn't have a passthrough route, so an HTTP route registered for
// that host captures in-flux traffic without a separate L4 entry.
func TestInFluxPortRouteMatchInDomainMode(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}

	if err := client.UpsertInFluxPortRoute(context.Background(), "sb-1", 3000); err != nil {
		t.Fatalf("UpsertInFluxPortRoute: %v", err)
	}
	route := fake.routes["sandbox-sb-1-port-3000-in-flux"]
	matches, _ := route["match"].([]any)
	if len(matches) != 1 {
		t.Fatalf("match shape = %+v", matches)
	}
	m, _ := matches[0].(map[string]any)
	hosts, _ := m["host"].([]any)
	if len(hosts) != 1 || hosts[0] != "sb-1-3000.sandbox.example.com" {
		t.Fatalf("host match = %v, want [sb-1-3000.sandbox.example.com]", hosts)
	}
}

// TestDeleteInFluxRouteIs404Safe — when the reconciler transitions a
// placement from in-flux to healthy, it deletes the in-flux route. A missing
// route should not produce an error: the desired post-condition (route
// absent) is already satisfied.
func TestDeleteInFluxRouteIs404Safe(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}

	if err := client.DeleteInFluxSandboxRoute(context.Background(), "missing"); err != nil {
		t.Fatalf("DeleteInFluxSandboxRoute on absent route = %v, want nil", err)
	}
	if len(fake.records) != 1 || fake.records[0].Method != http.MethodDelete {
		t.Fatalf("expected single DELETE, got %+v", fake.records)
	}
}
