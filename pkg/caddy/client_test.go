package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestClientURLAndEnabledCases(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new_trims_base_url_and_uses_enabled_flag",
			run: func(t *testing.T) {
				client := New(config.Config{
					CaddyAdminURL:     "http://127.0.0.1:2019/",
					CaddyServerID:     "srv0",
					EnableCaddy:       true,
					HTTPClientTimeout: time.Second,
				})
				if client.baseURL != "http://127.0.0.1:2019" || !client.Enabled() {
					t.Fatalf("unexpected client config: %+v", client)
				}
			},
		},
		{
			name: "sandbox_public_url_domain_mode",
			run: func(t *testing.T) {
				client := &Client{domain: "sandbox.example.com", publicHost: "203.0.113.10"}
				if got := client.SandboxPublicURL("abc"); got != "https://abc.sandbox.example.com" {
					t.Fatalf("SandboxPublicURL() = %q", got)
				}
			},
		},
		{
			name: "sandbox_public_url_ip_mode",
			run: func(t *testing.T) {
				client := &Client{publicHost: "203.0.113.10"}
				if got := client.SandboxPublicURL("abc"); got != "http://203.0.113.10/abc/" {
					t.Fatalf("SandboxPublicURL() = %q", got)
				}
			},
		},
		{
			name: "port_public_url_domain_mode",
			run: func(t *testing.T) {
				client := &Client{domain: "sandbox.example.com", publicHost: "203.0.113.10"}
				if got := client.PortPublicURL("abc", 3000); got != "https://abc-3000.sandbox.example.com" {
					t.Fatalf("PortPublicURL() = %q", got)
				}
			},
		},
		{
			name: "port_public_url_ip_mode",
			run: func(t *testing.T) {
				client := &Client{publicHost: "203.0.113.10"}
				if got := client.PortPublicURL("abc", 3000); got != "http://203.0.113.10/abc/proxy/3000/" {
					t.Fatalf("PortPublicURL() = %q", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestAllowTLSDomainCases(t *testing.T) {
	client := &Client{domain: "sandbox.example.com"}
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "allow_base_domain", host: "sandbox.example.com", want: true},
		{name: "allow_subdomain", host: "https://abc.sandbox.example.com/", want: true},
		{name: "reject_other_domain", host: "other.example.com", want: false},
		{name: "reject_blank_host", host: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := client.AllowTLSDomain(tc.host); got != tc.want {
				t.Fatalf("AllowTLSDomain(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestPingCases(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "ping_skips_when_disabled",
			run: func(t *testing.T) {
				client := &Client{enabled: false}
				if err := client.Ping(context.Background()); err != nil {
					t.Fatalf("Ping() error = %v", err)
				}
			},
		},
		{
			name: "ping_success_when_enabled",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/config/" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer server.Close()

				client := &Client{enabled: true, baseURL: server.URL, httpClient: server.Client()}
				if err := client.Ping(context.Background()); err != nil {
					t.Fatalf("Ping() error = %v", err)
				}
			},
		},
		{
			name: "ping_returns_error_on_bad_status",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadGateway)
				}))
				defer server.Close()

				client := &Client{enabled: true, baseURL: server.URL, httpClient: server.Client()}
				if err := client.Ping(context.Background()); err == nil {
					t.Fatalf("expected Ping() error")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestRouteCases(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "delete_sandbox_route_success",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.routes["sandbox-abc"] = map[string]any{"@id": "sandbox-abc"}

				client := &Client{enabled: true, serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.DeleteSandboxRoute(context.Background(), "abc"); err != nil {
					t.Fatalf("DeleteSandboxRoute() error = %v", err)
				}
				if len(fake.records) != 1 {
					t.Fatalf("expected 1 admin call, got %d: %+v", len(fake.records), fake.records)
				}
				rec := fake.records[0]
				if rec.Method != http.MethodDelete || rec.Path != "/id/sandbox-abc" {
					t.Fatalf("unexpected request: %+v", rec)
				}
				if _, exists := fake.routes["sandbox-abc"]; exists {
					t.Fatalf("route should be removed")
				}
			},
		},
		{
			name: "delete_port_route_not_found_is_ignored",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.DeletePortRoute(context.Background(), "abc", 3000); err != nil {
					t.Fatalf("DeletePortRoute() error = %v", err)
				}
				if len(fake.records) != 1 || fake.records[0].Method != http.MethodDelete {
					t.Fatalf("unexpected request sequence: %+v", fake.records)
				}
			},
		},
		{
			name: "upsert_sandbox_route_inserts_when_missing",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)

				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280); err != nil {
					t.Fatalf("UpsertSandboxRoute() error = %v", err)
				}
				if len(fake.records) != 2 {
					t.Fatalf("expected PATCH+PUT, got: %+v", fake.records)
				}
				if fake.records[0].Method != http.MethodPatch || fake.records[0].Path != "/id/sandbox-abc" {
					t.Fatalf("unexpected first call: %+v", fake.records[0])
				}
				if fake.records[1].Method != http.MethodPut || fake.records[1].Path != "/config/apps/http/servers/srv0/routes/0" {
					t.Fatalf("unexpected second call: %+v", fake.records[1])
				}
				route, ok := fake.routes["sandbox-abc"]
				if !ok {
					t.Fatalf("route was not inserted; routes=%+v", fake.routes)
				}
				assertRouteHostMatch(t, route, "abc.sandbox.example.com")
				assertRouteDial(t, route, "10.0.0.2:2280")
			},
		},
		{
			name: "upsert_sandbox_route_patches_when_present",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.routes["sandbox-abc"] = map[string]any{"@id": "sandbox-abc", "stale": true}

				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.5", 2280); err != nil {
					t.Fatalf("UpsertSandboxRoute() error = %v", err)
				}
				if len(fake.records) != 1 {
					t.Fatalf("expected single PATCH, got: %+v", fake.records)
				}
				if fake.records[0].Method != http.MethodPatch || fake.records[0].Path != "/id/sandbox-abc" {
					t.Fatalf("unexpected call: %+v", fake.records[0])
				}
				route := fake.routes["sandbox-abc"]
				if _, ok := route["stale"]; ok {
					t.Fatalf("PATCH should have replaced stale fields: %+v", route)
				}
				assertRouteDial(t, route, "10.0.0.5:2280")
			},
		},
		{
			name: "upsert_sandbox_route_ip_builds_path_match",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, publicHost: "203.0.113.10", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280); err != nil {
					t.Fatalf("UpsertSandboxRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc"]
				if !ok {
					t.Fatalf("route missing; routes=%+v", fake.routes)
				}
				assertRoutePathMatch(t, route, []string{"/abc", "/abc/*"})
			},
		},
		{
			name: "upsert_port_route_builds_host_match",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertPortRoute(context.Background(), "abc", "10.0.0.2", 3000); err != nil {
					t.Fatalf("UpsertPortRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-port-3000"]
				if !ok {
					t.Fatalf("port route missing; routes=%+v", fake.routes)
				}
				assertRouteField(t, route, "@id", "sandbox-abc-port-3000")
				assertRouteHostMatch(t, route, "abc-3000.sandbox.example.com")
				assertRouteDial(t, route, "10.0.0.2:3000")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

type requestRecord struct {
	Method string
	Path   string
}

// fakeCaddy emulates the slice of the Caddy admin API the client touches:
// PATCH/DELETE /id/<routeID> work against a routeID-keyed map; PUT to
// /routes/0 inserts a route by its @id. That's enough to verify the per-@id
// hot path without modeling the full config tree.
type fakeCaddy struct {
	URL     string
	Client  *http.Client
	records []requestRecord
	routes  map[string]map[string]any
}

func newFakeCaddy(t *testing.T) *fakeCaddy {
	t.Helper()
	fake := &fakeCaddy{routes: map[string]map[string]any{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.records = append(fake.records, requestRecord{Method: r.Method, Path: r.URL.Path})
		switch {
		case strings.HasPrefix(r.URL.Path, "/id/"):
			routeID := strings.TrimPrefix(r.URL.Path, "/id/")
			switch r.Method {
			case http.MethodPatch:
				if _, ok := fake.routes[routeID]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				route, err := decodeRoute(r.Body)
				if err != nil {
					t.Fatalf("decode patch body: %v", err)
				}
				fake.routes[routeID] = route
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				if _, ok := fake.routes[routeID]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				delete(fake.routes, routeID)
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected method %s for %s", r.Method, r.URL.Path)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			route, err := decodeRoute(r.Body)
			if err != nil {
				t.Fatalf("decode insert body: %v", err)
			}
			id, _ := route["@id"].(string)
			if id == "" {
				t.Fatalf("inserted route missing @id: %+v", route)
			}
			fake.routes[id] = route
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	fake.URL = server.URL
	fake.Client = server.Client()
	return fake
}

func decodeRoute(body io.Reader) (map[string]any, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var route map[string]any
	if err := json.Unmarshal(data, &route); err != nil {
		return nil, err
	}
	return route, nil
}

func assertRouteField(t *testing.T, body map[string]any, key, want string) {
	t.Helper()
	if got, _ := body[key].(string); got != want {
		t.Fatalf("route field %s = %q, want %q", key, got, want)
	}
}

func assertRouteHostMatch(t *testing.T, body map[string]any, want string) {
	t.Helper()
	matches, ok := body["match"].([]any)
	if !ok || len(matches) == 0 {
		t.Fatalf("missing match field: %#v", body)
	}
	match, _ := matches[0].(map[string]any)
	hosts, ok := match["host"].([]any)
	if !ok || len(hosts) == 0 {
		t.Fatalf("missing host match: %#v", body)
	}
	if got, _ := hosts[0].(string); got != want {
		t.Fatalf("host match = %q, want %q", got, want)
	}
}

func assertRoutePathMatch(t *testing.T, body map[string]any, want []string) {
	t.Helper()
	matches, ok := body["match"].([]any)
	if !ok || len(matches) == 0 {
		t.Fatalf("missing match field: %#v", body)
	}
	match, _ := matches[0].(map[string]any)
	paths, ok := match["path"].([]any)
	if !ok || len(paths) != len(want) {
		t.Fatalf("unexpected path match: %#v", body)
	}
	for i, item := range want {
		if got, _ := paths[i].(string); got != item {
			t.Fatalf("path match[%d] = %q, want %q", i, got, item)
		}
	}
}

func assertRouteDial(t *testing.T, body map[string]any, want string) {
	t.Helper()
	handles, ok := body["handle"].([]any)
	if !ok || len(handles) == 0 {
		t.Fatalf("missing handle field: %#v", body)
	}
	handle, _ := handles[0].(map[string]any)
	upstreams, ok := handle["upstreams"].([]any)
	if !ok || len(upstreams) == 0 {
		t.Fatalf("missing upstreams field: %#v", body)
	}
	upstream, _ := upstreams[0].(map[string]any)
	if got, _ := upstream["dial"].(string); got != want {
		t.Fatalf("dial = %q, want %q", got, want)
	}
}
