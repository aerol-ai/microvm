package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// statefulCaddyFake emulates the slice of the Caddy admin API that the create
// path exercises: PATCH /id/<id> (update-in-place; 404 forces the PUT insert),
// PUT /config/.../routes/0 (fresh insert, body carries the @id), and
// DELETE /id/<id>. Unlike the all-500 fake in TestCreateSandboxRollbackAndCustomDomainBranches,
// this one tracks which route IDs are actually live, so a test can assert that
// the rollback chain deleted every route it installed — main toolbox route AND
// the per-custom-domain leaf routes UpsertSandboxRoute installs in domain mode.
type statefulCaddyFake struct {
	mu     sync.Mutex
	routes map[string]struct{}
}

func newStatefulCaddyFake() *statefulCaddyFake {
	return &statefulCaddyFake{routes: map[string]struct{}{}}
}

func (f *statefulCaddyFake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			f.mu.Lock()
			_, ok := f.routes[id]
			f.mu.Unlock()
			if ok {
				w.WriteHeader(http.StatusOK) // updated in place
				return
			}
			// Unknown @id: 404 makes the client fall through to PUT-insert,
			// mirroring real Caddy on a fresh route.
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/routes/0"):
			var route map[string]any
			_ = json.NewDecoder(r.Body).Decode(&route)
			id, _ := route["@id"].(string)
			f.mu.Lock()
			if id != "" {
				f.routes[id] = struct{}{}
			}
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			f.mu.Lock()
			_, ok := f.routes[id]
			delete(f.routes, id)
			f.mu.Unlock()
			if ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound) // 404 is a no-op for the client
		default:
			// Any other admin call (config GETs etc.) is irrelevant to this
			// test; succeed so it doesn't mask the assertion below.
			w.WriteHeader(http.StatusOK)
		}
	})
}

func (f *statefulCaddyFake) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.routes[id]
	return ok
}

func (f *statefulCaddyFake) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.routes))
	for id := range f.routes {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// TestCreateSandboxRollbackDeletesCustomDomainLeafRoutes is the regression test
// for the caddy custom-domain leaf-route leak: UpsertSandboxRoute installs a
// main route PLUS one HTTP leaf route per custom domain (domain mode), but the
// create rollback used to call DeleteSandboxRoute, which only removes the main
// route — leaving each leaf route orphaned in caddy. The fix routes rollback
// through deleteSandboxPublicRoutes, which deletes the main route and every
// leaf. This test installs both kinds of route, forces a post-route create
// failure, and asserts no route bearing the failed sandbox's id survives.
func TestCreateSandboxRollbackDeletesCustomDomainLeafRoutes(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	fake := newStatefulCaddyFake()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.cfg.EnableCustomDomains = true
	svc.caddy = caddy.New(svc.cfg)
	svc.admitter = nil

	const host = "api.external.test"

	// Seed sandbox claims the custom domain and installs its main + leaf routes.
	allowPublic := true
	if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image:              "alpine:3.20",
		CustomDomains:      []string{host},
		AllowPublicTraffic: &allowPublic,
	}, "sb-keep"); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	keepLeaf := caddy.IngressCustomDomainHTTPRouteID("sb-keep", host)
	// Guard against a false negative: if leaf routes weren't installed at all,
	// the leak assertion below would pass vacuously.
	if !fake.has(keepLeaf) {
		t.Fatalf("seed sandbox leaf route %q was never installed; test setup is wrong (have %v)", keepLeaf, fake.ids())
	}

	// Second sandbox installs its OWN main + leaf routes via syncSandboxPublicRoute,
	// then trips the custom-domain conflict at persistCustomDomainsOnCreate, which
	// runs the post-route rollback chain.
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image:              "alpine:3.20",
		CustomDomains:      []string{host},
		AllowPublicTraffic: &allowPublic,
	}, "sb-roll")
	if err == nil || !errors.Is(err, storepkg.ErrCustomDomainConflict) {
		t.Fatalf("CreateSandboxWithID() error = %v, want custom domain conflict", err)
	}

	mainID := caddy.SandboxRouteID("sb-roll")
	leafID := caddy.IngressCustomDomainHTTPRouteID("sb-roll", host)
	if fake.has(leafID) {
		t.Errorf("custom-domain leaf route %q leaked after rollback; live routes=%v", leafID, fake.ids())
	}
	if fake.has(mainID) {
		t.Errorf("main route %q leaked after rollback; live routes=%v", mainID, fake.ids())
	}
	// Rollback of sb-roll must not over-delete the kept sandbox's routes.
	if !fake.has(keepLeaf) {
		t.Errorf("kept sandbox leaf route %q was removed by sb-roll rollback; live routes=%v", keepLeaf, fake.ids())
	}
}
