package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// gcCaddyFake emulates the slice of the Caddy admin API that
// gcZombieCaddyEntries actually exercises: GET /config/ for the snapshot
// shape, DELETE /id/<routeID> for HTTP and TLS routes, and DELETE
// /config/apps/layer4/servers/<serverID> for raw-TCP servers. The fake stores
// state in plain maps so each test seeds a known starting world and asserts
// what's left after Reconcile's GC pass.
type gcCaddyFake struct {
	mu             sync.Mutex
	httpRouteIDs   map[string]struct{}
	l4TCPServerIDs map[string]struct{}
	l4TLSRouteIDs  map[string]struct{}
}

func newGCCaddyFake() *gcCaddyFake {
	return &gcCaddyFake{
		httpRouteIDs:   map[string]struct{}{},
		l4TCPServerIDs: map[string]struct{}{},
		l4TLSRouteIDs:  map[string]struct{}{},
	}
}

func (f *gcCaddyFake) configBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	httpRoutes := make([]any, 0, len(f.httpRouteIDs))
	for id := range f.httpRouteIDs {
		httpRoutes = append(httpRoutes, map[string]any{"@id": id})
	}
	tlsRoutes := make([]any, 0, len(f.l4TLSRouteIDs))
	for id := range f.l4TLSRouteIDs {
		tlsRoutes = append(tlsRoutes, map[string]any{"@id": id})
	}
	servers := map[string]any{}
	for sid := range f.l4TCPServerIDs {
		servers[sid] = map[string]any{"listen": []string{":0"}, "routes": []any{}}
	}
	servers["tls-mux"] = map[string]any{
		"listen": []string{":443"},
		"routes": tlsRoutes,
	}
	cfg := map[string]any{"apps": map[string]any{
		"http": map[string]any{
			"servers": map[string]any{
				"srv0": map[string]any{"routes": httpRoutes},
			},
		},
		"layer4": map[string]any{"servers": servers},
	}}
	body, _ := json.Marshal(cfg)
	return body
}

func (f *gcCaddyFake) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(f.configBody())
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.httpRouteIDs[id]; ok {
				delete(f.httpRouteIDs, id)
				w.WriteHeader(http.StatusOK)
				return
			}
			if _, ok := f.l4TLSRouteIDs[id]; ok {
				delete(f.l4TLSRouteIDs, id)
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			sid := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.l4TCPServerIDs[sid]; !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			delete(f.l4TCPServerIDs, sid)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
}

func (f *gcCaddyFake) keys(target map[string]struct{}) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(target))
	for k := range target {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestGCZombieCaddyEntries(t *testing.T) {
	fake := newGCCaddyFake()

	// Live sandbox: HTTP toolbox route, one HTTP exposure on :3000, one TCP
	// exposure on :5432 with host_port=37412, one TLS exposure on :6379.
	// All four MUST survive the GC pass.
	live := &models.Sandbox{
		ID:     "abc",
		Status: models.SandboxStatusStarted,
		ExposedPorts: []models.ExposedPort{
			{SandboxID: "abc", Port: 3000, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: time.Now().UTC()},
			{SandboxID: "abc", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 37412, CreatedAt: time.Now().UTC()},
			{SandboxID: "abc", Port: 6379, Protocol: models.ExposedPortProtocolTLS, CreatedAt: time.Now().UTC()},
		},
	}
	// Stopped sandbox: keep its toolbox @id in the expected set so the GC
	// doesn't preemptively drop it (Start re-upserts on the way back up).
	stopped := &models.Sandbox{ID: "stp", Status: models.SandboxStatusStopped}
	// Destroyed sandboxes are excluded — anything in caddy bearing their
	// @id is by definition zombie.
	destroyed := &models.Sandbox{ID: "ded", Status: models.SandboxStatusDestroyed}

	// Live entries that match the expected set.
	fake.httpRouteIDs["sandbox-abc"] = struct{}{}
	fake.httpRouteIDs["sandbox-abc-port-3000"] = struct{}{}
	fake.httpRouteIDs["sandbox-stp"] = struct{}{}
	fake.l4TCPServerIDs["tcp-port-37412"] = struct{}{}
	fake.l4TLSRouteIDs["sandbox-abc-port-6379-tls"] = struct{}{}

	// Zombies that must be deleted.
	fake.httpRouteIDs["sandbox-ded"] = struct{}{}                       // destroyed sandbox
	fake.httpRouteIDs["sandbox-ghost-port-8080"] = struct{}{}           // sandbox row no longer in DB
	fake.l4TCPServerIDs["tcp-port-39999"] = struct{}{}                  // host port reservation lost
	fake.l4TLSRouteIDs["sandbox-ded-port-6379-tls"] = struct{}{}        // destroyed sandbox's TLS route
	fake.l4TLSRouteIDs["sandbox-ghost-port-1234-tls"] = struct{}{}      // unrelated TLS route

	// Non-matching prefixes — must not be touched.
	fake.httpRouteIDs["unrelated-route"] = struct{}{}                   // no "sandbox-" prefix
	fake.l4TCPServerIDs["operator-managed-server"] = struct{}{}         // no "tcp-port-" prefix

	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	caddyClient := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: 5 * time.Second,
	})

	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddyClient,
	}
	svc.gcZombieCaddyEntries(context.Background(), []*models.Sandbox{live, stopped, destroyed})

	wantHTTP := []string{"sandbox-abc", "sandbox-abc-port-3000", "sandbox-stp", "unrelated-route"}
	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, wantHTTP) {
		t.Fatalf("http routes after gc: got %v, want %v", got, wantHTTP)
	}
	wantTCP := []string{"operator-managed-server", "tcp-port-37412"}
	if got := fake.keys(fake.l4TCPServerIDs); !equalSorted(got, wantTCP) {
		t.Fatalf("tcp servers after gc: got %v, want %v", got, wantTCP)
	}
	wantTLS := []string{"sandbox-abc-port-6379-tls"}
	if got := fake.keys(fake.l4TLSRouteIDs); !equalSorted(got, wantTLS) {
		t.Fatalf("tls routes after gc: got %v, want %v", got, wantTLS)
	}
}

func TestGCZombieCaddyEntriesNoOpWhenCaddyDisabled(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	caddyClient := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	})
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddyClient,
	}
	svc.gcZombieCaddyEntries(context.Background(), nil)
	if called {
		t.Fatalf("disabled caddy should never reach the admin API")
	}
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
