package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// routeStore is a fake Caddy admin: real route lists and /id/ resolution,
// plus a count of mutating calls (each is a full reload in real Caddy).
type routeStore struct {
	mu     sync.Mutex
	lists  map[string][]map[string]any // routes path → routes
	writes int
}

func (s *routeStore) findByID(id string) (string, int) {
	for path, routes := range s.lists {
		for i, r := range routes {
			if r["@id"] == id {
				return path, i
			}
		}
	}
	return "", -1
}

func (s *routeStore) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodGet {
			s.writes++
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			path, i := s.findByID(id)
			if i < 0 {
				http.NotFound(w, r)
				return
			}
			switch r.Method {
			case http.MethodPatch:
				var route map[string]any
				_ = json.Unmarshal(body, &route)
				s.lists[path][i] = route
			case http.MethodDelete:
				s.lists[path] = append(s.lists[path][:i], s.lists[path][i+1:]...)
			}
		case r.Method == http.MethodGet:
			routes, ok := s.lists[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(routes)
		case r.Method == http.MethodPut:
			slash := strings.LastIndex(r.URL.Path, "/")
			path, idxStr := r.URL.Path[:slash], r.URL.Path[slash+1:]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				t.Errorf("bad insert path %s", r.URL.Path)
				return
			}
			var route map[string]any
			_ = json.Unmarshal(body, &route)
			routes := s.lists[path]
			routes = append(routes[:idx], append([]map[string]any{route}, routes[idx:]...)...)
			s.lists[path] = routes
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	})
}

func (s *routeStore) ids(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.lists[path] {
		id, _ := r["@id"].(string)
		out = append(out, id)
	}
	return out
}

const (
	httpRoutes = "/config/apps/http/servers/srv0/routes"
	muxRoutes  = "/config/apps/layer4/servers/tls-mux/routes"
)

func newStaticClient(t *testing.T) (*Client, *routeStore) {
	t.Helper()
	store := &routeStore{lists: map[string][]map[string]any{
		httpRoutes: {
			// The real Caddyfile shape: the apex site, then the *.<domain>
			// "Sandbox not found" site. Both carry host matchers; there is no
			// matcher-less catch-all to insert "before".
			{"@id": "apex", "match": []any{map[string]any{"host": []any{"sandbox.test"}}}},
			{"@id": "catch-all", "match": []any{map[string]any{"host": []any{"*.sandbox.test"}}}},
		},
		muxRoutes: {{"@id": tlsFallbackRouteID}},
	}}
	srv := httptest.NewServer(store.handler(t))
	t.Cleanup(srv.Close)
	c := New(config.Config{
		EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", Domain: "sandbox.test",
		L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: time.Second,
	})
	return c, store
}

var testSpec = StaticRouteSpec{RouteDNSAddr: "127.0.0.1:53053", RouterAddr: "127.0.0.1:21213", ToolboxPort: 2280, LocalIP: "127.0.0.1"}

// Regression (live cluster-3-mixed-routing): the static route went after the
// *.<domain> catch-all site and every sandbox URL answered 404. It must be
// first; its matcher excludes the apex.
func TestEnsureStaticSandboxRouteGoesFirstOnce(t *testing.T) {
	c, store := newStaticClient(t)
	ctx := context.Background()
	if err := c.EnsureStaticSandboxRoute(ctx, testSpec); err != nil {
		t.Fatal(err)
	}
	if got := store.ids(httpRoutes); strings.Join(got, ",") != StaticSandboxRouteID+",apex,catch-all" {
		t.Fatalf("http routes = %v, want the static route ahead of the *.domain catch-all site", got)
	}
	// Idempotent: a re-install PATCHes in place and never duplicates.
	if err := c.EnsureStaticSandboxRoute(ctx, testSpec); err != nil {
		t.Fatal(err)
	}
	if got := store.ids(httpRoutes); len(got) != 3 {
		t.Fatalf("re-install duplicated the route: %v", got)
	}
}

func TestEnsureStaticIngressRoutesOrder(t *testing.T) {
	c, store := newStaticClient(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ { // second pass: idempotent
		if err := c.EnsureStaticIngressRoutes(ctx, testSpec); err != nil {
			t.Fatal(err)
		}
	}
	want := StaticLoopbackRouteID + "," + StaticApexSNIRouteID + "," + StaticSNIRouteID + "," + tlsFallbackRouteID
	if got := store.ids(muxRoutes); strings.Join(got, ",") != want {
		t.Fatalf("tls-mux routes = %v, want %s (loopback first: it breaks the self-dial loop)", got, want)
	}
}

func TestRemoveStaticRoutes(t *testing.T) {
	c, store := newStaticClient(t)
	ctx := context.Background()
	_ = c.EnsureStaticSandboxRoute(ctx, testSpec)
	_ = c.EnsureStaticIngressRoutes(ctx, testSpec)
	if err := c.RemoveStaticRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if got := store.ids(httpRoutes); strings.Join(got, ",") != "apex,catch-all" {
		t.Fatalf("http routes after removal = %v", got)
	}
	if got := store.ids(muxRoutes); strings.Join(got, ",") != tlsFallbackRouteID {
		t.Fatalf("tls-mux routes after removal = %v", got)
	}
	if err := c.RemoveStaticRoutes(ctx); err != nil {
		t.Fatalf("removing already-removed routes: %v", err)
	}
}

func TestStaticRoutesRefuseOutsideDomainMode(t *testing.T) {
	c := New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://127.0.0.1:1", HTTPClientTimeout: time.Second})
	if err := c.EnsureStaticSandboxRoute(context.Background(), testSpec); err == nil {
		t.Fatal("static sandbox route installed without a domain")
	}
	if err := c.EnsureStaticIngressRoutes(context.Background(), testSpec); err == nil {
		t.Fatal("static ingress routes installed without domain/tls-mux")
	}
	off := New(config.Config{})
	if off.EnsureStaticSandboxRoute(context.Background(), testSpec) != nil || off.EnsureStaticIngressRoutes(context.Background(), testSpec) != nil || off.RemoveStaticRoutes(context.Background()) != nil {
		t.Fatal("a disabled client must no-op")
	}
}

// The static route's shape is the contract with the responder: a
// fully-qualified A lookup against the responder, the map-derived port, and
// the router as the static fallback.
func TestStaticSandboxRouteShape(t *testing.T) {
	c, _ := newStaticClient(t)
	raw, _ := json.Marshal(c.StaticSandboxRoute(testSpec))
	js := string(raw)
	for _, want := range []string{
		`"source":"a"`, `"name":"{http.request.host}."`, `"port":"{sbport}"`,
		`"addresses":["127.0.0.1:53053"]`, `"dial":"127.0.0.1:21213"`, `"defaults":["2280"]`,
		`"not":[{"host":["sandbox.test"]}]`, `"flush_interval":-1`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("static route missing %s:\n%s", want, js)
		}
	}
	re := regexp.MustCompile(SandboxPortHostRegexp)
	if m := re.FindStringSubmatch("sb1-8080.sandbox.test."); m == nil || m[1] != "8080" {
		t.Fatalf("port regexp = %v", m)
	}
	if re.MatchString("sb1.sandbox.test.") {
		t.Fatal("root host must fall to the toolbox-port default")
	}
}

func TestEnsureStaticRouteErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", Domain: "sandbox.test",
		L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443", HTTPClientTimeout: time.Second})
	if err := c.EnsureStaticSandboxRoute(context.Background(), testSpec); err == nil {
		t.Fatal("a 500 from the admin API must surface")
	}
	if err := c.RemoveStaticRoutes(context.Background()); err == nil {
		t.Fatal("a 500 on delete must surface")
	}
	// PATCH 404, then the route-list GET fails.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv2.Close()
	c2 := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv2.URL, CaddyServerID: "srv0", Domain: "sandbox.test", HTTPClientTimeout: time.Second})
	if err := c2.EnsureStaticSandboxRoute(context.Background(), testSpec); err == nil {
		t.Fatal("a failed route-list read must surface")
	}
}
