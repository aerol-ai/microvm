package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

type applyInFluxCaddyFake struct {
	mu     sync.Mutex
	routes map[string]map[string]any
}

func newApplyInFluxCaddyFake(routeIDs ...string) *applyInFluxCaddyFake {
	routes := make(map[string]map[string]any, len(routeIDs))
	for _, routeID := range routeIDs {
		routes[routeID] = map[string]any{"@id": routeID}
	}
	return &applyInFluxCaddyFake{routes: routes}
}

func (f *applyInFluxCaddyFake) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/id/"):
			routeID := strings.TrimPrefix(r.URL.Path, "/id/")
			switch r.Method {
			case http.MethodDelete:
				f.mu.Lock()
				defer f.mu.Unlock()
				if _, ok := f.routes[routeID]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				delete(f.routes, routeID)
				w.WriteHeader(http.StatusOK)
			case http.MethodPatch:
				var route map[string]any
				if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
					t.Fatalf("decode patched route: %v", err)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if _, ok := f.routes[routeID]; !ok {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				f.routes[routeID] = route
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			var route map[string]any
			if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
				t.Fatalf("decode inserted route: %v", err)
			}
			routeID, _ := route["@id"].(string)
			if routeID == "" {
				t.Fatal("inserted route missing @id")
			}
			f.mu.Lock()
			f.routes[routeID] = route
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
}

func (f *applyInFluxCaddyFake) hasRoute(routeID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.routes[routeID]
	return ok
}

func TestApplyInFluxRouteIPModeDeletesLiveRoutesAndSkipsTCP(t *testing.T) {
	fake := newApplyInFluxCaddyFake(
		"sandbox-flux-ip",
		"sandbox-flux-ip-port-3000",
		"sandbox-flux-ip-port-5432",
		"sandbox-flux-ip-port-8443",
	)
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		cfg:    config.Config{CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: time.Second},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(config.Config{CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}

	placement := cluster.Placement{
		SandboxID: "flux-ip",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			5432: {Protocol: models.ExposedPortProtocolTCP},
			8443: {Protocol: models.ExposedPortProtocolTLS},
		},
	}

	if err := svc.applyInFluxRoute(context.Background(), placement); err != nil {
		t.Fatalf("applyInFluxRoute() error = %v", err)
	}

	for _, routeID := range []string{
		"sandbox-flux-ip",
		"sandbox-flux-ip-port-3000",
		"sandbox-flux-ip-port-8443",
	} {
		if fake.hasRoute(routeID) {
			t.Fatalf("live route %q still present after in-flux apply", routeID)
		}
	}
	if !fake.hasRoute("sandbox-flux-ip-port-5432") {
		t.Fatal("tcp live route should be untouched by applyInFluxRoute")
	}
	for _, routeID := range []string{
		caddy.InFluxSandboxRouteID("flux-ip"),
		caddy.InFluxPortRouteID("flux-ip", 3000),
		caddy.InFluxPortRouteID("flux-ip", 8443),
	} {
		if !fake.hasRoute(routeID) {
			t.Fatalf("expected in-flux route %q to be installed", routeID)
		}
	}
	if fake.hasRoute(caddy.InFluxPortRouteID("flux-ip", 5432)) {
		t.Fatal("tcp in-flux route should not be installed")
	}
}

func TestApplyInFluxRouteDomainModeUsesIngressRouteIDs(t *testing.T) {
	fake := newApplyInFluxCaddyFake(
		"sandbox-flux-domain",
		"sandbox-flux-domain-port-3000",
		caddy.IngressSandboxSNIRouteID("flux-domain"),
		caddy.IngressPortSNIRouteID("flux-domain", 3000),
		caddy.IngressPortSNIRouteID("flux-domain", 8443),
	)
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		cfg:    config.Config{Domain: "example.test", CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: time.Second},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(config.Config{Domain: "example.test", CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}

	placement := cluster.Placement{
		SandboxID: "flux-domain",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			5432: {Protocol: models.ExposedPortProtocolTCP},
			8443: {Protocol: models.ExposedPortProtocolTLS},
		},
	}

	if err := svc.applyInFluxRoute(context.Background(), placement); err != nil {
		t.Fatalf("applyInFluxRoute() error = %v", err)
	}

	for _, routeID := range []string{
		caddy.IngressSandboxSNIRouteID("flux-domain"),
		caddy.IngressPortSNIRouteID("flux-domain", 3000),
		caddy.IngressPortSNIRouteID("flux-domain", 8443),
	} {
		if fake.hasRoute(routeID) {
			t.Fatalf("domain ingress route %q still present after in-flux apply", routeID)
		}
	}
	for _, routeID := range []string{
		"sandbox-flux-domain",
		"sandbox-flux-domain-port-3000",
	} {
		if !fake.hasRoute(routeID) {
			t.Fatalf("path-mode route %q should be untouched in domain mode", routeID)
		}
	}
	for _, routeID := range []string{
		caddy.InFluxSandboxRouteID("flux-domain"),
		caddy.InFluxPortRouteID("flux-domain", 3000),
		caddy.InFluxPortRouteID("flux-domain", 8443),
	} {
		if !fake.hasRoute(routeID) {
			t.Fatalf("expected in-flux route %q to be installed", routeID)
		}
	}
	if fake.hasRoute(caddy.InFluxPortRouteID("flux-domain", 5432)) {
		t.Fatal("tcp in-flux route should not be installed in domain mode")
	}
}

func TestGCClusterIngressRoutesUsesStoreRows(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := st.Close(); closeErr != nil {
			t.Fatalf("store.Close() error = %v", closeErr)
		}
	})

	if err := st.Create(ctx, &models.Sandbox{
		ID:        "live",
		Image:     "alpine:3.20",
		Status:    models.SandboxStatusStarted,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("store.Create() error = %v", err)
	}

	fake := newGCCaddyFake()
	fake.httpRouteIDs["sandbox-live"] = struct{}{}
	fake.httpRouteIDs["sandbox-zombie"] = struct{}{}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			EnableCaddy:       true,
			HTTPClientTimeout: time.Second,
		}),
	}

	if err := svc.gcClusterIngressRoutes(ctx); err != nil {
		t.Fatalf("gcClusterIngressRoutes() error = %v", err)
	}

	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, []string{"sandbox-live"}) {
		t.Fatalf("cluster ingress gc http routes = %v, want [sandbox-live]", got)
	}
}

func TestStartReconcileLoopRunsPeriodicReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ReconcileInterval = 10 * time.Millisecond

	if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-reconcile-loop"); err != nil {
		t.Fatalf("CreateSandboxWithID() error = %v", err)
	}

	svc.StartReconcileLoop(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := st.Get(ctx, "sb-reconcile-loop")
		if errors.Is(err, storepkg.ErrNotFound) {
			return
		}
		if err != nil {
			t.Fatalf("store.Get() error = %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic reconcile did not delete sandbox missing from runtime")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
