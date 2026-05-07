package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestClientURLAndEnabledCases(t *testing.T) {
	// 5 cases
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
	// 4 cases
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
	// 3 cases
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
	// 5 cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "delete_sandbox_route_success",
			run: func(t *testing.T) {
				fallback := []map[string]any{{
					"handle": []map[string]any{{
						"handler": "static_response",
						"body":    "Sandbox not found",
					}},
					"terminal": true,
				}}
				requests := captureRouteRequests(t, append([]map[string]any{{"@id": "sandbox-abc"}}, fallback...))

				client := &Client{enabled: true, serverID: "srv0", baseURL: requests.URL, httpClient: requests.Client}
				if err := client.DeleteSandboxRoute(context.Background(), "abc"); err != nil {
					t.Fatalf("DeleteSandboxRoute() error = %v", err)
				}
				if len(requests.Records) != 2 || requests.Records[0].Method != http.MethodGet || requests.Records[1].Method != http.MethodPut {
					t.Fatalf("unexpected request sequence: %+v", requests.Records)
				}
				if len(requests.Routes) != 1 {
					t.Fatalf("expected one route after delete, got %d", len(requests.Routes))
				}
				assertRouteBoolField(t, requests.Routes[0], "terminal", true)
				assertRouteStaticResponse(t, requests.Routes[0], "Sandbox not found")
				if requests.Records[0].Path != "/config/apps/http/servers/srv0/routes" || requests.Records[1].Path != "/config/apps/http/servers/srv0/routes" {
					t.Fatalf("unexpected request paths: %+v", requests.Records)
				}
			},
		},
		{
			name: "delete_port_route_not_found_is_ignored",
			run: func(t *testing.T) {
				requests := captureRouteRequests(t, []map[string]any{{"@id": "sandbox-other-port-3000"}})

				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: requests.URL, httpClient: requests.Client}
				if err := client.DeletePortRoute(context.Background(), "abc", 3000); err != nil {
					t.Fatalf("DeletePortRoute() error = %v", err)
				}
				if len(requests.Records) != 1 || requests.Records[0].Method != http.MethodGet {
					t.Fatalf("unexpected request sequence: %+v", requests.Records)
				}
			},
		},
		{
			name: "upsert_sandbox_route_domain_builds_host_match",
			run: func(t *testing.T) {
				fallback := map[string]any{
					"handle": []map[string]any{{
						"handler": "static_response",
						"body":    "Sandbox not found",
					}},
					"terminal": true,
				}
				requests := captureRouteRequests(t, []map[string]any{fallback})

				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: requests.URL, httpClient: requests.Client}
				if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280); err != nil {
					t.Fatalf("UpsertSandboxRoute() error = %v", err)
				}
				if len(requests.Records) != 2 || requests.Records[0].Method != http.MethodGet || requests.Records[1].Method != http.MethodPut {
					t.Fatalf("unexpected request sequence: %+v", requests.Records)
				}
				if len(requests.Routes) != 2 {
					t.Fatalf("expected two routes after upsert, got %d", len(requests.Routes))
				}
				assertRouteField(t, requests.Routes[0], "@id", "sandbox-abc")
				assertRouteHostMatch(t, requests.Routes[0], "abc.sandbox.example.com")
				assertRouteDial(t, requests.Routes[0], "10.0.0.2:2280")
				assertRouteStaticResponse(t, requests.Routes[1], "Sandbox not found")
			},
		},
		{
			name: "upsert_sandbox_route_ip_builds_path_match",
			run: func(t *testing.T) {
				requests := captureRouteRequests(t, nil)

				client := &Client{enabled: true, publicHost: "203.0.113.10", serverID: "srv0", baseURL: requests.URL, httpClient: requests.Client}
				if err := client.UpsertSandboxRoute(context.Background(), "abc", "10.0.0.2", 2280); err != nil {
					t.Fatalf("UpsertSandboxRoute() error = %v", err)
				}
				if len(requests.Routes) != 1 {
					t.Fatalf("expected one route after upsert, got %d", len(requests.Routes))
				}
				assertRoutePathMatch(t, requests.Routes[0], []string{"/abc", "/abc/*"})
			},
		},
		{
			name: "upsert_port_route_builds_host_match",
			run: func(t *testing.T) {
				requests := captureRouteRequests(t, nil)

				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: requests.URL, httpClient: requests.Client}
				if err := client.UpsertPortRoute(context.Background(), "abc", "10.0.0.2", 3000); err != nil {
					t.Fatalf("UpsertPortRoute() error = %v", err)
				}
				if len(requests.Routes) != 1 {
					t.Fatalf("expected one route after upsert, got %d", len(requests.Routes))
				}
				assertRouteField(t, requests.Routes[0], "@id", "sandbox-abc-port-3000")
				assertRouteHostMatch(t, requests.Routes[0], "abc-3000.sandbox.example.com")
				assertRouteDial(t, requests.Routes[0], "10.0.0.2:3000")
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

type capturedRequests struct {
	URL     string
	Client  *http.Client
	Records []requestRecord
	Routes  []map[string]any
}

func captureRouteRequests(t *testing.T, initialRoutes []map[string]any) *capturedRequests {
	t.Helper()
	result := &capturedRequests{Routes: cloneRoutes(initialRoutes)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record := requestRecord{Method: r.Method, Path: r.URL.Path}
		if r.Method == http.MethodPut {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			if err := json.Unmarshal(data, &result.Routes); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
		}
		result.Records = append(result.Records, record)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(result.Routes); err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	result.URL = server.URL
	result.Client = server.Client()
	return result
}

func assertRouteField(t *testing.T, body map[string]any, key, want string) {
	t.Helper()
	if got, _ := body[key].(string); got != want {
		t.Fatalf("route field %s = %q, want %q", key, got, want)
	}
}

func assertRouteBoolField(t *testing.T, body map[string]any, key string, want bool) {
	t.Helper()
	if got, _ := body[key].(bool); got != want {
		t.Fatalf("route field %s = %v, want %v", key, got, want)
	}
}

func cloneRoutes(routes []map[string]any) []map[string]any {
	if len(routes) == 0 {
		return nil
	}
	data, err := json.Marshal(routes)
	if err != nil {
		panic(err)
	}
	var cloned []map[string]any
	if err := json.Unmarshal(data, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func assertRouteStaticResponse(t *testing.T, body map[string]any, want string) {
	t.Helper()
	handles, ok := body["handle"].([]any)
	if !ok || len(handles) == 0 {
		t.Fatalf("missing handle field: %#v", body)
	}
	handle, _ := handles[0].(map[string]any)
	if got, _ := handle["body"].(string); got != want {
		t.Fatalf("static response body = %q, want %q", got, want)
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
