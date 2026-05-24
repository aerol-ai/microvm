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
	"time"
)

// upsertSandboxRouteWithCustomHostnames verifies that the custom-hostnames
// slice flows into the route's host matcher alongside the default
// {id}.{domain} hostname. Order in the matcher is the default first then
// the customs — the test checks the set, not the order.
func TestUpsertSandboxRouteWithCustomHostnames(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		domain:     "aerol.cloud",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}

	customs := []string{"api.acme.com", "ADMIN.Acme.com"}
	if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280, customs); err != nil {
		t.Fatalf("UpsertSandboxRoute() error = %v", err)
	}

	route, ok := fake.routes["sandbox-abc"]
	if !ok {
		t.Fatalf("route not inserted; routes=%+v", fake.routes)
	}
	matches, ok := route["match"].([]any)
	if !ok || len(matches) == 0 {
		t.Fatalf("missing match: %#v", route)
	}
	match, _ := matches[0].(map[string]any)
	hostsRaw, _ := match["host"].([]any)
	got := map[string]struct{}{}
	for _, h := range hostsRaw {
		s, _ := h.(string)
		got[s] = struct{}{}
	}
	want := []string{"abc.aerol.cloud", "api.acme.com", "admin.acme.com"}
	if len(got) != len(want) {
		t.Fatalf("host matcher set %v, want %v", got, want)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Fatalf("expected host %q in matcher, got %v", w, got)
		}
	}
}

// In IP mode (no domain) the matcher must remain path-based even when
// custom hostnames are passed — the service layer rejects custom domains
// in IP-mode deployments via 412, but a defense-in-depth check inside the
// Caddy helper keeps us from publishing a host matcher with no wildcard
// fallback if a stray nil-base call slips through.
func TestUpsertSandboxRouteIPModeIgnoresCustomHostnames(t *testing.T) {
	fake := newFakeCaddy(t)
	client := &Client{
		enabled:    true,
		publicHost: "203.0.113.10",
		serverID:   "srv0",
		baseURL:    fake.URL,
		httpClient: fake.Client,
	}
	if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280, []string{"api.acme.com"}); err != nil {
		t.Fatalf("UpsertSandboxRoute() error = %v", err)
	}
	route := fake.routes["sandbox-abc"]
	matches, _ := route["match"].([]any)
	if match, _ := matches[0].(map[string]any); match["host"] != nil {
		t.Fatalf("IP mode must not set host matcher: %#v", route)
	}
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
	if got := srv.onDemand["ask"]; got != "http://127.0.0.1:21213/internal/tls-ask" {
		t.Fatalf("ask = %v", got)
	}
	rl, _ := srv.onDemand["rate_limit"].(map[string]any)
	if rl["burst"].(float64) != 5 {
		t.Fatalf("burst = %v", rl["burst"])
	}
	if rl["interval"] != "1m0s" {
		t.Fatalf("interval = %v", rl["interval"])
	}

	// Catch-all policy appended.
	if len(srv.policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(srv.policies))
	}
	if v, _ := srv.policies[0]["on_demand"].(bool); !v {
		t.Fatalf("policy[0] is not on-demand: %v", srv.policies[0])
	}
}

// EnsureOnDemandTLS — second boot. on_demand leaf is replaced (so config
// changes take effect) but the catch-all policy is NOT duplicated.
func TestEnsureOnDemandTLS_Idempotent(t *testing.T) {
	srv := newFakeAutomationServer(t)
	defer srv.Close()
	client := &Client{enabled: true, baseURL: srv.URL, httpClient: srv.Client}

	if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 3, 2*time.Minute); err != nil {
		t.Fatalf("first call error = %v", err)
	}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x/ask", 7, 30*time.Second); err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if len(srv.policies) != 1 {
		t.Fatalf("policy duplicated on second call: %d", len(srv.policies))
	}
	rl := srv.onDemand["rate_limit"].(map[string]any)
	if rl["burst"].(float64) != 7 {
		t.Fatalf("second call did not replace on_demand leaf: %v", rl)
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
func TestEnsureOnDemandTLS_Disabled(t *testing.T) {
	client := &Client{enabled: false}
	if err := client.EnsureOnDemandTLS(context.Background(), "http://x", 5, time.Minute); err != nil {
		t.Fatalf("disabled path must return nil, got %v", err)
	}
}

// fakeAutomationServer is a stripped-down Caddy admin emulator covering
// only the apps/tls/automation/* paths EnsureOnDemandTLS touches.
type fakeAutomationServer struct {
	URL    string
	Client *http.Client

	mu       sync.Mutex
	policies []map[string]any
	onDemand map[string]any
	server   *httptest.Server
}

func newFakeAutomationServer(t *testing.T) *fakeAutomationServer {
	t.Helper()
	f := &fakeAutomationServer{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/config/apps/tls/automation/on_demand":
			if r.Method != http.MethodPut {
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
				f.policies = append(f.policies, p)
				w.WriteHeader(http.StatusOK)
			default:
				http.Error(w, "method", http.StatusMethodNotAllowed)
			}
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	f.URL = strings.TrimRight(f.server.URL, "/")
	f.Client = &http.Client{}
	return f
}

func (f *fakeAutomationServer) Close() { f.server.Close() }
