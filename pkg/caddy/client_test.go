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
			name: "upsert_sandbox_route_to_peer_uses_ip_mode_path",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, publicHost: "203.0.113.10", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertSandboxRouteToPeer(context.Background(), "abc", "10.0.0.9"); err != nil {
					t.Fatalf("UpsertSandboxRouteToPeer() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc"]
				if !ok {
					t.Fatalf("route missing; routes=%+v", fake.routes)
				}
				assertRoutePathMatch(t, route, []string{"/abc", "/abc/*"})
				assertRouteDial(t, route, "10.0.0.9:80")
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
		{
			name: "upsert_wake_http_port_route_dials_ingress_and_rewrites",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertWakeHTTPPortRoute(context.Background(), "abc", "127.0.0.1:21213", 3000); err != nil {
					t.Fatalf("UpsertWakeHTTPPortRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-port-3000-wake"]
				if !ok {
					t.Fatalf("wake route missing; routes=%+v", fake.routes)
				}
				assertRouteField(t, route, "@id", "sandbox-abc-port-3000-wake")
				assertRouteHostMatch(t, route, "abc-3000.sandbox.example.com")
				// handle[0] = rewrite to /__ingress/http/abc/3000{path}
				// handle[1] = reverse_proxy to the ingress addr
				handles, ok := route["handle"].([]any)
				if !ok || len(handles) != 2 {
					t.Fatalf("wake route should have two handlers, got: %#v", route["handle"])
				}
				rewrite, _ := handles[0].(map[string]any)
				if rewrite["handler"] != "rewrite" {
					t.Fatalf("first handler should be rewrite, got %v", rewrite["handler"])
				}
				if uri, _ := rewrite["uri"].(string); uri != "/__ingress/http/abc/3000{http.request.uri.path}" {
					t.Fatalf("unexpected rewrite uri: %q", uri)
				}
				rp, _ := handles[1].(map[string]any)
				if rp["handler"] != "reverse_proxy" {
					t.Fatalf("second handler should be reverse_proxy, got %v", rp["handler"])
				}
				upstreams, _ := rp["upstreams"].([]any)
				if len(upstreams) == 0 {
					t.Fatalf("missing upstreams: %#v", rp)
				}
				upstream, _ := upstreams[0].(map[string]any)
				if dial, _ := upstream["dial"].(string); dial != "127.0.0.1:21213" {
					t.Fatalf("expected dial=127.0.0.1:21213, got %q", dial)
				}
			},
		},
		{
			name: "delete_wake_http_port_route_removes_route",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertWakeHTTPPortRoute(context.Background(), "abc", "127.0.0.1:21213", 3000); err != nil {
					t.Fatalf("UpsertWakeHTTPPortRoute() error = %v", err)
				}
				if err := client.DeleteWakeHTTPPortRoute(context.Background(), "abc", 3000); err != nil {
					t.Fatalf("DeleteWakeHTTPPortRoute() error = %v", err)
				}
				if _, ok := fake.routes["sandbox-abc-port-3000-wake"]; ok {
					t.Fatalf("wake route should be deleted; routes=%+v", fake.routes)
				}
			},
		},
		{
			name: "wake_http_port_route_skipped_when_path_mode",
			run: func(t *testing.T) {
				// Path mode (no domain configured) doesn't install per-port
				// HTTP routes — wake-aware variant must follow the same rule
				// to avoid leaking an unmatched dial entry.
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertWakeHTTPPortRoute(context.Background(), "abc", "127.0.0.1:21213", 3000); err != nil {
					t.Fatalf("UpsertWakeHTTPPortRoute() error = %v", err)
				}
				if _, ok := fake.routes["sandbox-abc-port-3000-wake"]; ok {
					t.Fatalf("wake route should not exist in path mode; routes=%+v", fake.routes)
				}
			},
		},
		{
			// UpsertPortRouteWithRetry must preserve the byte-for-byte
			// shape of UpsertPortRoute and only add the load_balancing
			// block. The shape is consumed by the bypass-on path which
			// flips between this method and UpsertPortRoute on every
			// warm/cold transition — divergent fields would leak across
			// shapes via Caddy's PATCH overlay.
			name: "upsert_port_route_with_retry_adds_load_balancing",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertPortRouteWithRetry(context.Background(), "abc", "10.0.0.2", 3000, 2*time.Second); err != nil {
					t.Fatalf("UpsertPortRouteWithRetry() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-port-3000"]
				if !ok {
					t.Fatalf("port route missing; routes=%+v", fake.routes)
				}
				assertRouteField(t, route, "@id", "sandbox-abc-port-3000")
				assertRouteHostMatch(t, route, "abc-3000.sandbox.example.com")
				assertRouteDial(t, route, "10.0.0.2:3000")

				handle := route["handle"].([]any)[0].(map[string]any)
				lb, ok := handle["load_balancing"].(map[string]any)
				if !ok {
					t.Fatalf("load_balancing missing in handle: %+v", handle)
				}
				if got := lb["try_duration"]; got != "2s" {
					t.Fatalf("try_duration = %v, want %q", got, "2s")
				}
				if got := lb["try_interval"]; got != "100ms" {
					t.Fatalf("try_interval = %v, want %q", got, "100ms")
				}
			},
		},
		{
			// UpsertPortRoute MUST NOT acquire load_balancing implicitly
			// — that would change the non-serverless surface's retry
			// behavior, which the plan explicitly scopes out.
			name: "upsert_port_route_has_no_load_balancing",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, domain: "sandbox.example.com", serverID: "srv0", baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertPortRoute(context.Background(), "abc", "10.0.0.2", 3000); err != nil {
					t.Fatalf("UpsertPortRoute() error = %v", err)
				}
				route := fake.routes["sandbox-abc-port-3000"]
				handle := route["handle"].([]any)[0].(map[string]any)
				if _, present := handle["load_balancing"]; present {
					t.Fatalf("non-retry UpsertPortRoute leaked load_balancing block: %+v", handle)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestL4Cases(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "ensure_layer4_creates_app_and_tls_mux",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.EnsureLayer4(context.Background(), ":443", "127.0.0.1:8443"); err != nil {
					t.Fatalf("EnsureLayer4() error = %v", err)
				}
				if !fake.layer4Exists {
					t.Fatalf("layer4 app should exist after ensure")
				}
				if _, ok := fake.l4Servers[tlsMuxServerID]; !ok {
					t.Fatalf("tls-mux server should exist after ensure; servers=%+v", fake.l4Servers)
				}
			},
		},
		{
			name: "ensure_layer4_seeds_fallback_route",
			run: func(t *testing.T) {
				// Regression test for the TLS-SNI default-on path: caddy-l4 has
				// to forward unmatched SNI (the API host, on-demand validation,
				// stray probes) to the relocated HTTPS listener. If this
				// fallback route is missing, every non-sandbox SNI connection
				// drops, including the API itself — the symptom would be "site
				// works locally, dies when SB_L4_TLS_LISTEN is set".
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.EnsureLayer4(context.Background(), ":443", "127.0.0.1:8443"); err != nil {
					t.Fatalf("EnsureLayer4() error = %v", err)
				}
				server, ok := fake.l4Servers[tlsMuxServerID]
				if !ok {
					t.Fatalf("tls-mux server missing")
				}
				route := firstL4Route(t, server)
				assertRouteField(t, route, "@id", tlsFallbackRouteID)
				assertL4Dial(t, route, "127.0.0.1:8443")
			},
		},
		{
			name: "ensure_layer4_rejects_listen_without_fallback",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.EnsureLayer4(context.Background(), ":443", ""); err == nil {
					t.Fatalf("EnsureLayer4 should reject empty fallback when listen is set")
				}
			},
		},
		{
			name: "ensure_layer4_skips_tls_mux_when_listen_empty",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.EnsureLayer4(context.Background(), "", ""); err != nil {
					t.Fatalf("EnsureLayer4() error = %v", err)
				}
				if !fake.layer4Exists {
					t.Fatalf("layer4 app should exist even without tls listen")
				}
				if _, ok := fake.l4Servers[tlsMuxServerID]; ok {
					t.Fatalf("tls-mux must not be created when listen is empty")
				}
			},
		},
		{
			name: "ensure_layer4_is_idempotent",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.EnsureLayer4(context.Background(), ":443", "127.0.0.1:8443"); err != nil {
					t.Fatalf("first EnsureLayer4() error = %v", err)
				}
				puts1 := countMethod(fake.records, http.MethodPut)
				if err := client.EnsureLayer4(context.Background(), ":443", "127.0.0.1:8443"); err != nil {
					t.Fatalf("second EnsureLayer4() error = %v", err)
				}
				puts2 := countMethod(fake.records, http.MethodPut)
				if puts2 != puts1 {
					t.Fatalf("idempotent ensure should not PUT again, got %d → %d", puts1, puts2)
				}
			},
		},
		{
			name: "upsert_tcp_route_creates_server_with_route",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertTCPRoute(context.Background(), "abc", "10.0.0.5", 5432, 37412); err != nil {
					t.Fatalf("UpsertTCPRoute() error = %v", err)
				}
				server, ok := fake.l4Servers["tcp-port-37412"]
				if !ok {
					t.Fatalf("tcp server missing; servers=%+v", fake.l4Servers)
				}
				assertL4Listen(t, server, ":37412")
				route := firstL4Route(t, server)
				assertRouteField(t, route, "@id", "sandbox-abc-port-5432-tcp")
				assertL4Dial(t, route, "10.0.0.5:5432")
			},
		},
		{
			name: "upsert_tcp_route_replaces_existing_server",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertTCPRoute(context.Background(), "abc", "10.0.0.5", 5432, 37412); err != nil {
					t.Fatalf("first UpsertTCPRoute error = %v", err)
				}
				if err := client.UpsertTCPRoute(context.Background(), "abc", "10.0.0.9", 5432, 37412); err != nil {
					t.Fatalf("second UpsertTCPRoute error = %v", err)
				}
				server := fake.l4Servers["tcp-port-37412"]
				route := firstL4Route(t, server)
				assertL4Dial(t, route, "10.0.0.9:5432")
			},
		},
		{
			name: "upsert_wake_tcp_route_targets_l4_wake_proxy_with_proxy_protocol",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertWakeTCPRoute(context.Background(), "abc", 5432, 37412, "127.0.0.1:21214"); err != nil {
					t.Fatalf("UpsertWakeTCPRoute() error = %v", err)
				}
				server, ok := fake.l4Servers["tcp-port-37412"]
				if !ok {
					t.Fatalf("wake tcp server missing; servers=%+v", fake.l4Servers)
				}
				assertL4Listen(t, server, ":37412")
				route := firstL4Route(t, server)
				assertRouteField(t, route, "@id", "sandbox-abc-port-5432-tcp")
				assertL4Dial(t, route, "127.0.0.1:21214")
				assertL4ProxyProtocol(t, route, "v1")
			},
		},
		{
			name: "delete_tcp_route_removes_server",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.l4Servers["tcp-port-37412"] = map[string]any{"listen": []any{":37412"}}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.DeleteTCPRoute(context.Background(), 37412); err != nil {
					t.Fatalf("DeleteTCPRoute() error = %v", err)
				}
				if _, ok := fake.l4Servers["tcp-port-37412"]; ok {
					t.Fatalf("tcp server should be removed")
				}
			},
		},
		{
			name: "delete_tcp_route_swallows_404",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.DeleteTCPRoute(context.Background(), 99999); err != nil {
					t.Fatalf("DeleteTCPRoute() should swallow 404, got %v", err)
				}
			},
		},
		{
			name: "upsert_tcp_proxy_route_targets_owner_host_port",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertTCPProxyRoute(context.Background(), "abc", 5432, 37412, "10.0.0.9", 37412); err != nil {
					t.Fatalf("UpsertTCPProxyRoute() error = %v", err)
				}
				server, ok := fake.l4Servers["tcp-port-37412"]
				if !ok {
					t.Fatalf("tcp proxy server missing; servers=%+v", fake.l4Servers)
				}
				route := firstL4Route(t, server)
				assertRouteField(t, route, "@id", "sandbox-abc-port-5432-tcp")
				assertL4Dial(t, route, "10.0.0.9:37412")
			},
		},
		{
			name: "upsert_tls_sni_route_inserts_when_missing",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				fake.l4Servers[tlsMuxServerID] = map[string]any{
					"listen": []any{":443"},
					"routes": []any{},
				}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertTLSSNIRoute(context.Background(), "abc", "abc-5432.sandbox.example.com", "10.0.0.5", 5432); err != nil {
					t.Fatalf("UpsertTLSSNIRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-port-5432-tls"]
				if !ok {
					t.Fatalf("tls route should be inserted; routes=%+v", fake.routes)
				}
				assertL4SNI(t, route, "abc-5432.sandbox.example.com")
				assertL4Dial(t, route, "10.0.0.5:5432")
				assertHasTLSTerminator(t, route)
			},
		},
		{
			name: "upsert_tls_sni_route_patches_when_present",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				fake.l4Servers[tlsMuxServerID] = map[string]any{"listen": []any{":443"}, "routes": []any{}}
				fake.routes["sandbox-abc-port-5432-tls"] = map[string]any{"@id": "sandbox-abc-port-5432-tls", "stale": true}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertTLSSNIRoute(context.Background(), "abc", "abc-5432.sandbox.example.com", "10.0.0.7", 5432); err != nil {
					t.Fatalf("UpsertTLSSNIRoute() error = %v", err)
				}
				route := fake.routes["sandbox-abc-port-5432-tls"]
				if _, ok := route["stale"]; ok {
					t.Fatalf("PATCH should have replaced stale fields: %+v", route)
				}
				assertL4Dial(t, route, "10.0.0.7:5432")
				assertHasTLSTerminator(t, route)
			},
		},
		{
			name: "upsert_wake_tls_sni_route_targets_unix_socket",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				fake.l4Servers[tlsMuxServerID] = map[string]any{"listen": []any{":443"}, "routes": []any{}}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertWakeTLSSNIRoute(context.Background(), "abc", "abc-5432.sandbox.example.com", "/run/sandboxd/l4wake/abc-5432.sock", 5432); err != nil {
					t.Fatalf("UpsertWakeTLSSNIRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-port-5432-tls"]
				if !ok {
					t.Fatalf("wake tls route should be inserted; routes=%+v", fake.routes)
				}
				assertL4SNI(t, route, "abc-5432.sandbox.example.com")
				assertL4Dial(t, route, "unix//run/sandboxd/l4wake/abc-5432.sock")
				assertHasTLSTerminator(t, route)
			},
		},
		{
			name: "delete_tls_sni_route_removes_by_id",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.routes["sandbox-abc-port-5432-tls"] = map[string]any{"@id": "sandbox-abc-port-5432-tls"}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.DeleteTLSSNIRoute(context.Background(), "abc", 5432); err != nil {
					t.Fatalf("DeleteTLSSNIRoute() error = %v", err)
				}
				if _, ok := fake.routes["sandbox-abc-port-5432-tls"]; ok {
					t.Fatalf("tls route should be removed")
				}
			},
		},
		{
			name: "upsert_sni_passthrough_route_does_not_terminate_tls",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				fake.l4Servers[tlsMuxServerID] = map[string]any{"listen": []any{":443"}, "routes": []any{}}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				if err := client.UpsertSNIPassthroughRoute(context.Background(), "sandbox-abc-ingress-sni", "abc.sandbox.example.com", "10.0.0.9", 443); err != nil {
					t.Fatalf("UpsertSNIPassthroughRoute() error = %v", err)
				}
				route, ok := fake.routes["sandbox-abc-ingress-sni"]
				if !ok {
					t.Fatalf("passthrough route should be inserted; routes=%+v", fake.routes)
				}
				assertL4SNI(t, route, "abc.sandbox.example.com")
				assertL4Dial(t, route, "10.0.0.9:443")
				assertNoTLSTerminator(t, route)
			},
		},
		{
			name: "snapshot_collects_http_l4_tcp_and_tls_ids",
			run: func(t *testing.T) {
				fake := newFakeCaddy(t)
				fake.layer4Exists = true
				fake.routes["sandbox-abc"] = map[string]any{"@id": "sandbox-abc"}
				fake.routes["sandbox-abc-port-3000"] = map[string]any{"@id": "sandbox-abc-port-3000"}
				fake.routes["unrelated"] = map[string]any{"@id": "unrelated"}
				fake.l4Servers["tcp-port-37412"] = map[string]any{
					"listen": []any{":37412"},
					"routes": []any{map[string]any{"@id": "sandbox-abc-port-5432-tcp"}},
				}
				fake.l4Servers["tcp-port-38001"] = map[string]any{
					"listen": []any{":38001"},
					"routes": []any{map[string]any{"@id": "sandbox-xyz-port-6379-tcp"}},
				}
				fake.l4Servers[tlsMuxServerID] = map[string]any{
					"listen": []any{":443"},
					"routes": []any{
						map[string]any{"@id": "sandbox-abc-port-5432-tls"},
						map[string]any{"@id": "stranger"},
					},
				}
				client := &Client{enabled: true, baseURL: fake.URL, httpClient: fake.Client}
				snap, err := client.Snapshot(context.Background())
				if err != nil {
					t.Fatalf("Snapshot() error = %v", err)
				}
				assertContainsAll(t, "HTTPRouteIDs", snap.HTTPRouteIDs, "sandbox-abc", "sandbox-abc-port-3000")
				assertExcludes(t, "HTTPRouteIDs", snap.HTTPRouteIDs, "unrelated")
				assertContainsAll(t, "L4TCPServerIDs", snap.L4TCPServerIDs, "tcp-port-37412", "tcp-port-38001")
				assertContainsAll(t, "L4TLSRouteIDs", snap.L4TLSRouteIDs, "sandbox-abc-port-5432-tls")
				assertExcludes(t, "L4TLSRouteIDs", snap.L4TLSRouteIDs, "stranger")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestPublicEndpointHelpers(t *testing.T) {
	t.Run("tcp_endpoint_uses_127_in_local_mode", func(t *testing.T) {
		// --local writes SB_PUBLIC_HOST=127.0.0.1 and no SB_DOMAIN.
		client := &Client{publicHost: "127.0.0.1"}
		if got := client.TCPPublicEndpoint(37412); got != "tcp://127.0.0.1:37412" {
			t.Fatalf("TCPPublicEndpoint() = %q", got)
		}
	})
	t.Run("tcp_endpoint_uses_public_host_in_ip_mode", func(t *testing.T) {
		client := &Client{publicHost: "203.0.113.10"}
		if got := client.TCPPublicEndpoint(37412); got != "tcp://203.0.113.10:37412" {
			t.Fatalf("TCPPublicEndpoint() = %q", got)
		}
	})
	t.Run("tcp_endpoint_uses_domain_in_domain_mode", func(t *testing.T) {
		client := &Client{domain: "sandbox.example.com", publicHost: "203.0.113.10"}
		if got := client.TCPPublicEndpoint(37412); got != "tcp://sandbox.example.com:37412" {
			t.Fatalf("TCPPublicEndpoint() = %q", got)
		}
	})
	t.Run("tls_endpoint_requires_domain_and_listen", func(t *testing.T) {
		client := &Client{domain: "sandbox.example.com", publicHost: "203.0.113.10"}
		if got := client.TLSPublicEndpoint("abc", 5432, ":443"); got != "tls://abc-5432.sandbox.example.com:443" {
			t.Fatalf("TLSPublicEndpoint() = %q", got)
		}
		if got := client.TLSPublicEndpoint("abc", 5432, ""); got != "" {
			t.Fatalf("TLSPublicEndpoint() with empty listen = %q, want empty", got)
		}
		ipClient := &Client{publicHost: "203.0.113.10"}
		if got := ipClient.TLSPublicEndpoint("abc", 5432, ":443"); got != "" {
			t.Fatalf("TLSPublicEndpoint() in IP mode = %q, want empty", got)
		}
	})
}

func countMethod(records []requestRecord, method string) int {
	count := 0
	for _, rec := range records {
		if rec.Method == method {
			count++
		}
	}
	return count
}

func assertL4Listen(t *testing.T, server map[string]any, want string) {
	t.Helper()
	listens, ok := server["listen"].([]any)
	if !ok || len(listens) == 0 {
		t.Fatalf("missing listen: %#v", server)
	}
	if got, _ := listens[0].(string); got != want {
		t.Fatalf("listen = %q, want %q", got, want)
	}
}

func firstL4Route(t *testing.T, server map[string]any) map[string]any {
	t.Helper()
	routes, ok := server["routes"].([]any)
	if !ok || len(routes) == 0 {
		t.Fatalf("server has no routes: %#v", server)
	}
	route, _ := routes[0].(map[string]any)
	if route == nil {
		t.Fatalf("first route not an object: %#v", routes[0])
	}
	return route
}

func assertL4Dial(t *testing.T, route map[string]any, want string) {
	t.Helper()
	handles, ok := route["handle"].([]any)
	if !ok || len(handles) == 0 {
		t.Fatalf("missing handle: %#v", route)
	}
	// TLS-terminating SNI routes have [tls, proxy]; raw-TCP routes have just
	// [proxy]. Walk the chain and pick the first handler that carries an
	// upstreams list — that's the one with the dial target.
	var handle map[string]any
	for _, h := range handles {
		hm, _ := h.(map[string]any)
		if hm == nil {
			continue
		}
		if _, hasUpstreams := hm["upstreams"]; hasUpstreams {
			handle = hm
			break
		}
	}
	if handle == nil {
		t.Fatalf("no handler with upstreams in chain: %#v", route)
	}
	upstreams, ok := handle["upstreams"].([]any)
	if !ok || len(upstreams) == 0 {
		t.Fatalf("missing upstreams: %#v", route)
	}
	upstream, _ := upstreams[0].(map[string]any)
	dials, ok := upstream["dial"].([]any)
	if !ok || len(dials) == 0 {
		t.Fatalf("missing dial entries: %#v", route)
	}
	if got, _ := dials[0].(string); got != want {
		t.Fatalf("dial = %q, want %q", got, want)
	}
}

func assertL4ProxyProtocol(t *testing.T, route map[string]any, want string) {
	t.Helper()
	handles, ok := route["handle"].([]any)
	if !ok || len(handles) == 0 {
		t.Fatalf("missing handle: %#v", route)
	}
	for _, h := range handles {
		hm, _ := h.(map[string]any)
		if hm == nil {
			continue
		}
		if _, hasUpstreams := hm["upstreams"]; !hasUpstreams {
			continue
		}
		if got, _ := hm["proxy_protocol"].(string); got != want {
			t.Fatalf("proxy_protocol = %q, want %q", got, want)
		}
		return
	}
	t.Fatalf("no proxy handler in chain: %#v", route)
}

// assertHasTLSTerminator walks the route's handler chain and asserts that a
// "tls" handler appears before any "proxy" handler. Catches the regression
// where someone removes TLS termination from UpsertTLSSNIRoute and the
// route silently becomes passthrough — which would expose the user's
// containers to the requirement of holding their own cert again.
func assertHasTLSTerminator(t *testing.T, route map[string]any) {
	t.Helper()
	handles, ok := route["handle"].([]any)
	if !ok || len(handles) < 2 {
		t.Fatalf("expected handler chain of length >= 2 for terminated TLS, got %#v", route)
	}
	sawTLS := false
	for _, h := range handles {
		hm, _ := h.(map[string]any)
		if hm == nil {
			continue
		}
		handler, _ := hm["handler"].(string)
		if handler == "tls" {
			sawTLS = true
			continue
		}
		if handler == "proxy" {
			if !sawTLS {
				t.Fatalf("proxy handler appears before tls in chain: %#v", route)
			}
			return
		}
	}
	if !sawTLS {
		t.Fatalf("no tls handler in chain (TLS-SNI route must terminate, not passthrough): %#v", route)
	}
	t.Fatalf("no proxy handler after tls: %#v", route)
}

func assertNoTLSTerminator(t *testing.T, route map[string]any) {
	t.Helper()
	handles, ok := route["handle"].([]any)
	if !ok || len(handles) == 0 {
		t.Fatalf("missing handler chain: %#v", route)
	}
	for _, h := range handles {
		hm, _ := h.(map[string]any)
		if hm == nil {
			continue
		}
		if handler, _ := hm["handler"].(string); handler == "tls" {
			t.Fatalf("passthrough route must not terminate TLS: %#v", route)
		}
	}
}

func assertL4SNI(t *testing.T, route map[string]any, want string) {
	t.Helper()
	matches, ok := route["match"].([]any)
	if !ok || len(matches) == 0 {
		t.Fatalf("missing match: %#v", route)
	}
	match, _ := matches[0].(map[string]any)
	tlsBlock, _ := match["tls"].(map[string]any)
	snis, ok := tlsBlock["sni"].([]any)
	if !ok || len(snis) == 0 {
		t.Fatalf("missing sni list: %#v", route)
	}
	if got, _ := snis[0].(string); got != want {
		t.Fatalf("sni = %q, want %q", got, want)
	}
}

func assertContainsAll(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s missing %q; got %v", label, w, got)
		}
	}
}

func assertExcludes(t *testing.T, label string, got []string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		for _, g := range got {
			if g == u {
				t.Fatalf("%s should not include %q; got %v", label, u, got)
			}
		}
	}
}

type requestRecord struct {
	Method string
	Path   string
}

// fakeCaddy emulates the slice of the Caddy admin API the client touches:
// PATCH/DELETE /id/<routeID> work against a routeID-keyed map; PUT to
// /config/apps/http/servers/srv0/routes/0 inserts a route by its @id; and
// the layer4 surface mirrors the same shape — PATCH/DELETE /id/<routeID>
// for tls-mux SNI routes plus PUT/DELETE on /config/apps/layer4/servers/<id>
// for whole-server lifecycle. That's enough to verify the per-@id hot path
// and the L4 server CRUD without modeling the full config tree.
type fakeCaddy struct {
	URL          string
	Client       *http.Client
	records      []requestRecord
	routes       map[string]map[string]any
	l4Servers    map[string]map[string]any
	layer4Exists bool
}

func newFakeCaddy(t *testing.T) *fakeCaddy {
	t.Helper()
	fake := &fakeCaddy{
		routes:    map[string]map[string]any{},
		l4Servers: map[string]map[string]any{},
	}
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
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/layer4":
			if !fake.layer4Exists {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"servers": fake.l4Servers})
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/layer4":
			fake.layer4Exists = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			id := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			if _, ok := fake.l4Servers[id]; !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(fake.l4Servers[id])
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/") && strings.HasSuffix(r.URL.Path, "/routes/0"):
			// PUT /config/apps/layer4/servers/<id>/routes/0 — array insert at index 0.
			rest := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			serverID := strings.TrimSuffix(rest, "/routes/0")
			server, ok := fake.l4Servers[serverID]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			route, err := decodeRoute(r.Body)
			if err != nil {
				t.Fatalf("decode l4 insert body: %v", err)
			}
			id, _ := route["@id"].(string)
			if id != "" {
				fake.routes[id] = route
			}
			routes, _ := server["routes"].([]any)
			server["routes"] = append([]any{route}, routes...)
			fake.l4Servers[serverID] = server
			w.WriteHeader(http.StatusOK)
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			// POST /config/apps/layer4/servers/<id> — create or replace server
			// (Caddy admin's "set or replace object" for a map-child path).
			// PUT is also accepted here because EnsureLayer4 PUTs the tls-mux
			// server when first creating it (guarded by pathExists).
			rest := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			body, err := decodeRoute(r.Body)
			if err != nil {
				t.Fatalf("decode l4 server body: %v", err)
			}
			fake.l4Servers[rest] = body
			fake.layer4Exists = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			id := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			if _, ok := fake.l4Servers[id]; !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			delete(fake.l4Servers, id)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			snapshot := map[string]any{"apps": map[string]any{
				"http": map[string]any{
					"servers": map[string]any{
						"srv0": map[string]any{"routes": fakeRoutesSlice(fake.routes)},
					},
				},
				"layer4": map[string]any{"servers": fake.l4Servers},
			}}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(snapshot)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	fake.URL = server.URL
	fake.Client = server.Client()
	return fake
}

// fakeRoutesSlice flattens the routeID-keyed map into the slice shape Caddy's
// /config/ endpoint actually returns. Order is not stable; tests that need a
// specific shape should match by @id, not slice index.
func fakeRoutesSlice(routes map[string]map[string]any) []any {
	out := make([]any, 0, len(routes))
	for _, r := range routes {
		out = append(out, r)
	}
	return out
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
