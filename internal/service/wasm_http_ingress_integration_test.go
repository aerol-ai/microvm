package service

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
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

type recordingHTTPRouteCaddy struct {
	routes map[string]map[string]any
}

func newRecordingHTTPRouteCaddy(t *testing.T) (*recordingHTTPRouteCaddy, *httptest.Server, *caddy.Client) {
	t.Helper()
	rec := &recordingHTTPRouteCaddy{routes: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			switch r.Method {
			case http.MethodPatch:
				if _, ok := rec.routes[id]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				var route map[string]any
				if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
					t.Fatalf("decode patch: %v", err)
				}
				rec.routes[id] = route
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				delete(rec.routes, id)
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			var route map[string]any
			if err := json.Unmarshal(body, &route); err != nil {
				t.Fatalf("unmarshal route: %v", err)
			}
			id, _ := route["@id"].(string)
			if id == "" {
				t.Fatal("route missing @id")
			}
			rec.routes[id] = route
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	cfg := config.Config{
		EnableCaddy:       true,
		CaddyAdminURL:     srv.URL,
		CaddyServerID:     "srv0",
		Domain:            "sandbox.example.com",
		HTTPClientTimeout: time.Second,
	}
	return rec, srv, caddy.New(cfg)
}

func routeDial(t *testing.T, route map[string]any) string {
	t.Helper()
	handlers, _ := route["handle"].([]any)
	rp, _ := handlers[0].(map[string]any)
	upstreams, _ := rp["upstreams"].([]any)
	up, _ := upstreams[0].(map[string]any)
	dial, _ := up["dial"].(string)
	return dial
}

func TestWasmHTTPIngressIntegration(t *testing.T) {
	ctx := context.Background()
	rec, srv, caddyClient := newRecordingHTTPRouteCaddy(t)
	defer srv.Close()

	driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.CaddyAdminURL = srv.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.HTTPClientTimeout = time.Second
	svc.caddy = caddyClient
	svc.SetWasmRuntime(driver)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-wasm-ingress",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeWasm,
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	sandbox, err := st.Get(ctx, "sb-wasm-ingress")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if _, err := svc.ExposePort(ctx, "sb-wasm-ingress", 8080, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}

	wantDial, err := svc.wasmHTTPDial(ctx, "sb-wasm-ingress", 8080)
	if err != nil {
		t.Fatalf("wasmHTTPDial: %v", err)
	}

	routeID := caddy.PortRouteID("sb-wasm-ingress", 8080)
	route, ok := rec.routes[routeID]
	if !ok {
		t.Fatalf("preview route %q missing; have %v", routeID, rec.routes)
	}
	if dial := routeDial(t, route); dial != wantDial {
		t.Fatalf("preview dial = %q want %q", dial, wantDial)
	}

	if err := svc.installWasmCustomDomainHTTPRoute(ctx, sandbox, "api.customer.com", 8080); err != nil {
		t.Fatalf("installWasmCustomDomainHTTPRoute: %v", err)
	}
	cdID := caddy.IngressCustomDomainHTTPRouteID("sb-wasm-ingress", "api.customer.com")
	cdRoute, ok := rec.routes[cdID]
	if !ok {
		t.Fatalf("custom domain route %q missing", cdID)
	}
	if dial := routeDial(t, cdRoute); dial != wantDial {
		t.Fatalf("custom domain dial = %q want %q", dial, wantDial)
	}
}
