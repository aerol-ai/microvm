package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Custom hostnames now install their own per-hostname routes (one route per
// hostname, keyed by IngressCustomDomainHTTPRouteID) so each can dial a
// different in-container port. The default sandbox-{id} route's host matcher
// stops carrying customs; this test pins both invariants.
func TestUpsertSandboxRouteWithCustomHostnames(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		domain:     "aerol.cloud",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}

	customs := []CustomHostnameRoute{
		{Hostname: "api.acme.com", TargetPort: 3333},
		{Hostname: "ADMIN.Acme.com"}, // TargetPort=0 → falls back to toolbox port
	}
	if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280, customs); err != nil {
		t.Fatalf("UpsertSandboxRoute() error = %v", err)
	}

	// Default route matches ONLY abc.aerol.cloud — it must not carry the
	// custom hostnames anymore, otherwise a port-targeted custom domain
	// would race the default route for the same match.
	defaultRoute, ok := fake.routes["sandbox-abc"]
	if !ok {
		t.Fatalf("default sandbox route not inserted; routes=%+v", fake.routes)
	}
	matches, _ := defaultRoute["match"].([]any)
	match, _ := matches[0].(map[string]any)
	hostsRaw, _ := match["host"].([]any)
	if len(hostsRaw) != 1 || hostsRaw[0].(string) != "abc.aerol.cloud" {
		t.Fatalf("default route host matcher = %v, want [abc.aerol.cloud]", hostsRaw)
	}

	// api.acme.com → its own route, dialing 10.0.0.2:3333.
	apiID := IngressCustomDomainHTTPRouteID("abc", "api.acme.com")
	apiRoute, ok := fake.routes[apiID]
	if !ok {
		t.Fatalf("per-hostname route %q missing; routes=%+v", apiID, fake.routes)
	}
	dial := mustDialFromRoute(t, apiRoute)
	if dial != "10.0.0.2:3333" {
		t.Fatalf("api.acme.com dial = %q, want 10.0.0.2:3333", dial)
	}

	// admin.acme.com (lowercased) → its own route, dialing the toolbox port
	// because TargetPort=0 is the "use toolbox" sentinel.
	adminID := IngressCustomDomainHTTPRouteID("abc", "admin.acme.com")
	adminRoute, ok := fake.routes[adminID]
	if !ok {
		t.Fatalf("per-hostname route %q missing; routes=%+v", adminID, fake.routes)
	}
	if dial := mustDialFromRoute(t, adminRoute); dial != "10.0.0.2:2280" {
		t.Fatalf("admin.acme.com dial = %q, want 10.0.0.2:2280", dial)
	}
}

// In IP mode (no domain) the matcher must remain path-based and the
// per-hostname custom routes must NOT be installed — the service layer
// rejects custom domains in IP-mode deployments via 412, but a
// defense-in-depth check inside the Caddy helper keeps us from publishing
// a host matcher with no wildcard fallback if a stray nil-base call slips
// through.
func TestUpsertSandboxRouteIPModeIgnoresCustomHostnames(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		publicHost: "203.0.113.10",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	customs := []CustomHostnameRoute{{Hostname: "api.acme.com", TargetPort: 3333}}
	if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280, customs); err != nil {
		t.Fatalf("UpsertSandboxRoute() error = %v", err)
	}
	route := fake.routes["sandbox-abc"]
	matches, _ := route["match"].([]any)
	if match, _ := matches[0].(map[string]any); match["host"] != nil {
		t.Fatalf("IP mode must not set host matcher: %#v", route)
	}
	// No per-hostname routes in IP mode either.
	if _, ok := fake.routes[IngressCustomDomainHTTPRouteID("abc", "api.acme.com")]; ok {
		t.Fatalf("per-hostname route must not be installed in IP mode")
	}
}

func TestDeleteCustomDomainHTTPRoute(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		domain:     "aerol.cloud",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	customs := []CustomHostnameRoute{{Hostname: "api.acme.com", TargetPort: 3333}}
	if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280, customs); err != nil {
		t.Fatalf("UpsertSandboxRoute() error = %v", err)
	}
	if err := client.DeleteCustomDomainHTTPRoute(context.Background(), "abc", "api.acme.com"); err != nil {
		t.Fatalf("DeleteCustomDomainHTTPRoute() error = %v", err)
	}
	if _, ok := fake.routes[IngressCustomDomainHTTPRouteID("abc", "api.acme.com")]; ok {
		t.Fatalf("per-hostname route should be deleted")
	}
}

func TestUpsertCustomDomainHTTPRouteWithDial(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		domain:     "aerol.cloud",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	wantDial := "127.0.0.1:54321"
	if err := client.UpsertCustomDomainHTTPRouteWithDial(context.Background(), "sb-wasm", "api.acme.com", wantDial); err != nil {
		t.Fatalf("UpsertCustomDomainHTTPRouteWithDial() error = %v", err)
	}
	routeID := IngressCustomDomainHTTPRouteID("sb-wasm", "api.acme.com")
	route, ok := fake.routes[routeID]
	if !ok {
		t.Fatalf("route %q missing; routes=%+v", routeID, fake.routes)
	}
	if dial := mustDialFromRoute(t, route); dial != wantDial {
		t.Fatalf("dial = %q, want %q", dial, wantDial)
	}
}

func mustDialFromRoute(t *testing.T, route map[string]any) string {
	t.Helper()
	handlers, _ := route["handle"].([]any)
	if len(handlers) == 0 {
		t.Fatalf("route has no handlers: %#v", route)
	}
	rp, _ := handlers[0].(map[string]any)
	upstreams, _ := rp["upstreams"].([]any)
	if len(upstreams) == 0 {
		t.Fatalf("route has no upstreams: %#v", route)
	}
	up, _ := upstreams[0].(map[string]any)
	dial, _ := up["dial"].(string)
	return dial
}

// EnsureOnDemandTLS — fresh Caddy, no apps/tls. PUT installs the on_demand
// leaf and POST appends the catch-all policy.
func TestEnsureOnDemandTLS_FreshCaddy(t *testing.T) {
	srv := newFakeAutomationServer(t)
	defer srv.Close()
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}

	if err := client.EnsureOnDemandTLS(context.Background(), "http://127.0.0.1:21213/internal/tls-ask", 5, time.Minute); err != nil {
		t.Fatalf("EnsureOnDemandTLS() error = %v", err)
	}

	// On-demand block written.
	if srv.onDemand == nil {
		t.Fatalf("on_demand leaf not written")
	}
	if got, ok := onDemandEndpoint(srv); !ok || got != "http://127.0.0.1:21213/internal/tls-ask" {
		t.Fatalf("on_demand = %v, want the http permission module with the ask URL", srv.onDemand)
	}
	if _, ok := srv.onDemand["ask"]; ok {
		t.Fatalf("on_demand still sets the deprecated ask: %v", srv.onDemand)
	}
	if _, ok := srv.onDemand["rate_limit"]; ok {
		t.Fatalf("rate_limit must not be written; deployed Caddy rejects that field: %v", srv.onDemand)
	}

	// Catch-all policy appended.
	if len(srv.policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(srv.policies))
	}
	if v, _ := srv.policies[0]["on_demand"].(bool); !v {
		t.Fatalf("policy[0] is not on-demand: %v", srv.policies[0])
	}
}

// onlyInternalIssuers mirrors Caddy's exception: a policy issued only by
// Caddy's own CA puts no load on public ACME, so it needs no permission.
func onlyInternalIssuers(p map[string]any) bool {
	issuers, _ := p["issuers"].([]any)
	if len(issuers) == 0 {
		return false
	}
	for _, raw := range issuers {
		if m, _ := raw.(map[string]any); m["module"] != "internal" {
			return false
		}
	}
	return true
}

// onDemandEndpoint is the ask URL the fake holds, from the http permission
// module.
func onDemandEndpoint(f *fakeAutomationServer) (string, bool) {
	perm, _ := f.onDemand["permission"].(map[string]any)
	if perm["module"] != "http" {
		return "", false
	}
	endpoint, ok := perm["endpoint"].(string)
	return endpoint, ok
}

// EnsureOnDemandTLS — second boot. on_demand leaf is replaced (so config
// changes take effect) but the catch-all policy is NOT duplicated. Against a
// Caddy that already holds on_demand, as after any restart: the client used
// to PUT it, which Caddy answers 409.
func TestEnsureOnDemandTLS_Idempotent(t *testing.T) {
	srv := newFakeAutomationServer(t)
	defer srv.Close()
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}

	if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask-old", 3, 2*time.Minute); err != nil {
		t.Fatalf("first call error = %v", err)
	}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 7, 30*time.Second); err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if len(srv.policies) != 1 {
		t.Fatalf("policy duplicated on second call: %d", len(srv.policies))
	}
	if got, _ := onDemandEndpoint(srv); got != "http://x/ask" {
		t.Fatalf("second call did not replace on_demand leaf: %v", srv.onDemand)
	}
}

// EnsureOnDemandTLS — pre-existing wildcard policy from the Caddyfile is
// preserved, and the on-demand catch-all lands AT THE END so the wildcard
// matches first.
func TestEnsureOnDemandTLS_PreservesWildcard(t *testing.T) {
	srv := newFakeAutomationServer(t)
	defer srv.Close()
	srv.policies = []map[string]any{
		// Looks like a wildcard policy installed by the Caddyfile.
		{"subjects": []any{"*.aerol.cloud"}, "issuers": []any{map[string]any{"module": "acme"}}},
	}
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 5, time.Minute); err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(srv.policies) != 2 {
		t.Fatalf("expected 2 policies (wildcard + on-demand), got %d", len(srv.policies))
	}
	if _, ok := srv.policies[1]["on_demand"]; !ok {
		t.Fatalf("on-demand policy not appended last; policies=%+v", srv.policies)
	}
}

// EnsureOnDemandTLS — input validation rejects bad caller arguments.
func TestEnsureOnDemandTLS_RejectsBadInput(t *testing.T) {
	client := &Client{enabled: true, baseURL: "http://unused", httpClient: http.DefaultClient}
	if err := client.EnsureOnDemandTLS(context.Background(), "", 5, time.Minute); err == nil {
		t.Fatalf("expected error for empty askURL")
	}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x", 0, time.Minute); err == nil {
		t.Fatalf("expected error for zero burst")
	}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x", 5, 0); err == nil {
		t.Fatalf("expected error for zero interval")
	}
}

// EnsureOnDemandTLS — Caddy disabled is a no-op (mirrors every other
// helper).
// A Caddy that resumed its saved config after a restart already holds
// on_demand and the on-demand policy. The next sandboxd start must still
// write the current ask URL: it used to PUT on_demand, which Caddy answers
// 409 "key already exists", so the boot logged a failure and kept the old URL.
func TestEnsureOnDemandTLS_AfterRestart(t *testing.T) {
	srv := newFakeAutomationServer(t)
	defer srv.Close()
	srv.onDemand = map[string]any{"permission": map[string]any{"module": "http", "endpoint": "http://old-ingress:21213/internal/tls-ask"}}
	srv.policies = []map[string]any{{"on_demand": true}}
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}

	if err := client.EnsureOnDemandTLS(context.Background(), "http://new-ingress:21213/internal/tls-ask", 5, time.Minute); err != nil {
		t.Fatalf("EnsureOnDemandTLS after a restart: %v", err)
	}
	if got, _ := onDemandEndpoint(srv); got != "http://new-ingress:21213/internal/tls-ask" {
		t.Fatalf("on_demand = %v, want the new ask URL", srv.onDemand)
	}
	if len(srv.policies) != 1 {
		t.Fatalf("policy duplicated: %d", len(srv.policies))
	}
}

func TestEnsureOnDemandTLS_Disabled(t *testing.T) {
	client := &Client{enabled: false}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x", 5, time.Minute); err != nil {
		t.Fatalf("disabled path must return nil, got %v", err)
	}
}

// fakeAutomationServer is a stripped-down Caddy admin emulator covering
// only the apps/tls/automation/* paths EnsureOnDemandTLS touches. It keeps
// the two Caddy rules the client broke against for months: PUT only creates
// (409 once a key exists), and since Caddy 2.10 an on-demand policy needs
// on_demand.permission (the deprecated "ask" is converted too late).
type fakeAutomationServer struct {
	URL    string
	Client *http.Client

	mu           sync.Mutex
	policies     []map[string]any
	onDemand     map[string]any
	issuerWrites []string // "PATCH 0", "PUT 1"
	server       *httptest.Server
}

func newFakeAutomationServer(t *testing.T) *fakeAutomationServer {
	t.Helper()
	f := &fakeAutomationServer{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/config/apps/tls/automation/on_demand":
			switch {
			case r.Method == http.MethodPut && f.onDemand != nil:
				http.Error(w, `{"error":"[/config/apps/tls/automation/on_demand] key already exists: on_demand"}`, http.StatusConflict)
				return
			case r.Method != http.MethodPost && r.Method != http.MethodPut:
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(r.Body)
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			f.onDemand = v
			w.WriteHeader(http.StatusOK)
		case "/config/apps/tls/automation/policies":
			switch r.Method {
			case http.MethodGet:
				if f.policies == nil {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(f.policies)
			case http.MethodPost:
				body, _ := io.ReadAll(r.Body)
				var p map[string]any
				if err := json.Unmarshal(body, &p); err != nil {
					http.Error(w, "decode", http.StatusBadRequest)
					return
				}
				if on, _ := p["on_demand"].(bool); on && !onlyInternalIssuers(p) {
					if _, ok := f.onDemand["permission"]; !ok {
						http.Error(w, `{"error":"loading new config: ... provisioning automation policy 0: on-demand TLS cannot be enabled without a permission module to prevent abuse"}`, http.StatusInternalServerError)
						return
					}
				}
				f.policies = append(f.policies, p)
				w.WriteHeader(http.StatusOK)
			default:
				http.Error(w, "method", http.StatusMethodNotAllowed)
			}
		default:
			// policies/<n>/issuers, with the admin API's semantics: PATCH
			// replaces an existing key, PUT creates a missing one.
			var idx int
			if _, err := fmt.Sscanf(r.URL.Path, "/config/apps/tls/automation/policies/%d/issuers", &idx); err != nil || idx >= len(f.policies) {
				http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
				return
			}
			_, exists := f.policies[idx]["issuers"]
			switch {
			case r.Method == http.MethodPatch && !exists:
				http.Error(w, "key does not exist", http.StatusNotFound)
				return
			case r.Method == http.MethodPut && exists:
				http.Error(w, "key already exists", http.StatusConflict)
				return
			case r.Method != http.MethodPatch && r.Method != http.MethodPut:
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			var issuers []any
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &issuers); err != nil {
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			f.policies[idx]["issuers"] = issuers
			f.issuerWrites = append(f.issuerWrites, fmt.Sprintf("%s %d", r.Method, idx))
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(f.server.Close)
	f.URL = strings.TrimRight(f.server.URL, "/")
	f.Client = &http.Client{}
	return f
}

func (f *fakeAutomationServer) Close() { f.server.Close() }
