package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestValidateMaskRequestHost(t *testing.T) {
	cases := []struct {
		name    string
		mask    string
		wantErr bool
	}{
		{"empty_ok", "", false},
		{"whitespace_only_ok", "   ", false},
		{"plain_host", "localhost", false},
		{"fqdn", "app.internal", false},
		{"host_with_port", "app.internal:8080", false},
		{"crlf_rejected", "evil\r\nX-Injected: 1", true},
		{"newline_rejected", "evil\napp", true},
		{"tab_rejected", "ev\til", true},
		{"space_rejected", "two words", true},
		{"too_long", string(make([]byte, maxMaskRequestHostLen+1)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMaskRequestHost(tc.mask)
			if tc.wantErr && err == nil {
				t.Fatalf("validateMaskRequestHost(%q) = nil, want error", tc.mask)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateMaskRequestHost(%q) = %v, want nil", tc.mask, err)
			}
		})
	}
}

// maskCapturingCaddy records the body of every inserted HTTP route so a test
// can assert the Host-rewrite block the service asked Caddy to install.
type maskCapturingCaddy struct {
	mu     sync.Mutex
	routes map[string]map[string]any
}

func (c *maskCapturingCaddy) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// upsertRoute first PATCHes /id/<routeID>; a 404 there makes it fall
		// through to PUT routes/0 (insert). Return 404 for the PATCH so the
		// fresh-route insert path runs and we capture the body.
		if r.Method == http.MethodPatch {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// The HTTP port-route install path PUTs the full route body to the
		// routes/0 insert position; everything else (best-effort wake-route
		// deletes) is a 200 no-op for this fake.
		if r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0" {
			var route map[string]any
			if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
				t.Fatalf("decode route: %v", err)
			}
			id, _ := route["@id"].(string)
			c.mu.Lock()
			c.routes[id] = route
			c.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (c *maskCapturingCaddy) hostRewrite(t *testing.T, routeID string) (string, bool) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	route, ok := c.routes[routeID]
	if !ok {
		return "", false
	}
	handles, _ := route["handle"].([]any)
	if len(handles) == 0 {
		return "", false
	}
	handle, _ := handles[0].(map[string]any)
	headers, ok := handle["headers"].(map[string]any)
	if !ok {
		return "", false
	}
	set, _ := headers["request"].(map[string]any)["set"].(map[string]any)
	hosts, _ := set["Host"].([]any)
	if len(hosts) == 0 {
		return "", false
	}
	host, _ := hosts[0].(string)
	return host, true
}

func newMaskRouteSvc(t *testing.T) (*Service, *maskCapturingCaddy) {
	t.Helper()
	fake := &maskCapturingCaddy{routes: map[string]map[string]any{}}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)
	svc := &Service{
		cfg:    config.Config{ToolboxPort: 2280},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			Domain:            "example.test",
			EnableCaddy:       true,
			HTTPClientTimeout: 5 * time.Second,
		}),
	}
	return svc, fake
}

func TestExposedPortRouteCarriesMaskRequestHost(t *testing.T) {
	svc, fake := newMaskRouteSvc(t)
	sandbox := &models.Sandbox{
		ID:              "sb-mask",
		Status:          models.SandboxStatusStarted,
		Runtime:         models.RuntimeDocker,
		ContainerIP:     "10.0.0.2",
		MaskRequestHost: "localhost",
	}
	port := models.ExposedPort{SandboxID: sandbox.ID, Port: 3000, Protocol: models.ExposedPortProtocolHTTP}
	if err := svc.upsertExposedPortRoute(context.Background(), sandbox, port); err != nil {
		t.Fatalf("upsertExposedPortRoute: %v", err)
	}
	routeID := caddy.PortRouteID(sandbox.ID, 3000)
	got, ok := fake.hostRewrite(t, routeID)
	if !ok {
		t.Fatalf("route %q missing Host rewrite; routes=%+v", routeID, fake.routes)
	}
	if got != "localhost" {
		t.Fatalf("Host rewrite = %q, want %q", got, "localhost")
	}
}

func TestExposedPortRouteOmitsHostRewriteWhenUnset(t *testing.T) {
	svc, fake := newMaskRouteSvc(t)
	sandbox := &models.Sandbox{
		ID:          "sb-plain",
		Status:      models.SandboxStatusStarted,
		Runtime:     models.RuntimeDocker,
		ContainerIP: "10.0.0.2",
	}
	port := models.ExposedPort{SandboxID: sandbox.ID, Port: 3000, Protocol: models.ExposedPortProtocolHTTP}
	if err := svc.upsertExposedPortRoute(context.Background(), sandbox, port); err != nil {
		t.Fatalf("upsertExposedPortRoute: %v", err)
	}
	routeID := caddy.PortRouteID(sandbox.ID, 3000)
	if _, ok := fake.hostRewrite(t, routeID); ok {
		t.Fatalf("route %q unexpectedly carries a Host rewrite", routeID)
	}
}
