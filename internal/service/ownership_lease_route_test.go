package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// leaseRouteWorker is a lease worker whose Caddy is the admin emulator (real
// PATCH-by-@id and insert-before semantics), in domain mode d.test.
func leaseRouteWorker(t *testing.T) (*Service, *storepkg.Store, *leaseCluster, *freezeRuntime, *emulatedCaddy) {
	t.Helper()
	rt := newFreezeRuntime()
	svc, st, lc := newLeaseService(t, rt)
	e := newEmulatedCaddy(t, 0)
	svc.cfg.Domain = "d.test"
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = e.srv.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, CaddyAdminURL: e.srv.URL, CaddyServerID: "srv0", Domain: "d.test", HTTPClientTimeout: 5 * time.Second})
	return svc, st, lc, rt, e
}

// seedPublicLeaseRow is a started public sandbox (like seedLeaseRow) with a
// container IP and an HTTP port 8080 whose route is installed, as
// ExposePort leaves it.
func seedPublicLeaseRow(t *testing.T, svc *Service, st *storepkg.Store, id, ip string, recreate bool) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	public := true
	sb := &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-" + id, ContainerIP: ip, AuditIncarnationID: "inc-" + id, AllowPublicTraffic: &public,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if recreate {
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: id, Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://" + id + "-8080.d.test", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sb, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.installHTTPPortRoute(ctx, sb, 8080); err != nil {
		t.Fatalf("install the route of %s: %v", id, err)
	}
}

// servedAs says what the worker's Caddy does with a request for host: the
// first route whose host matcher takes it, as Caddy evaluates them.
// "503 retry-after=2" for a static 503, "proxy <dial>" for a reverse proxy,
// "404" for the not-found fallback.
func servedAs(t *testing.T, e *emulatedCaddy, host string) string {
	t.Helper()
	resp, err := e.emu.RoundTrip(httptest.NewRequest(http.MethodGet, "/config/apps/http/servers/srv0/routes", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var routes []struct {
		Match []struct {
			Host []string `json:"host"`
		} `json:"match"`
		Handle []struct {
			Handler    string              `json:"handler"`
			StatusCode int                 `json:"status_code"`
			Headers    map[string][]string `json:"headers"`
			Upstreams  []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
		} `json:"handle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		hit := false
		for _, m := range r.Match {
			for _, h := range m.Host {
				if h == host || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
					hit = true
				}
			}
		}
		if !hit || len(r.Handle) == 0 {
			continue
		}
		h := r.Handle[0]
		switch h.Handler {
		case "static_response":
			if h.StatusCode == http.StatusNotFound {
				return "404"
			}
			return fmt.Sprintf("%d retry-after=%s", h.StatusCode, strings.Join(h.Headers["Retry-After"], ","))
		case "reverse_proxy":
			if len(h.Upstreams) > 0 {
				return "proxy " + h.Upstreams[0].Dial
			}
		}
		return h.Handler
	}
	return "no route"
}

// TestFencedSandboxPublicPortAnswers503 is the data-plane half of the C4
// part 1 fence (live UC-470, 2026-11-08). The fence froze the sandbox, but
// its public port route still proxied to the frozen container. A frozen
// process keeps its listening socket, so the connection was accepted and
// never answered, and every request through the cut-off side hung until the
// client gave up (10 s), where I7 asks for a quick 503. Now the fence swaps
// the route for a 503 + Retry-After in the same check that freezes the
// sandbox, and the confirm that resumes it swaps the proxy route back.
func TestFencedSandboxPublicPortAnswers503(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, rt, e := leaseRouteWorker(t)
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	seedPublicLeaseRow(t, svc, st, "sb-plain", "10.88.0.6", false)
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "proxy 10.88.0.5:8080" {
		t.Fatalf("before the fence sb-ha is served as %q, want the proxy route", got)
	}
	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-plain"))
	t0 := time.Unix(70_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatal(err)
	}

	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-ha") || !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: sb-ha fenced and frozen")
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("the fenced, frozen sb-ha is served as %q; want 503 with Retry-After, not a proxy to a process that never answers", got)
	}
	if got := servedAs(t, e, "sb-plain-8080.d.test"); got != "proxy 10.88.0.6:8080" {
		t.Fatalf("sb-plain (not fenced) is served as %q, want its proxy route untouched", got)
	}

	// Ownership is confirmed again: the proxy route comes back.
	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-plain"))
	if err := svc.confirmOwnership(ctx, t0.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	if svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: sb-ha resumed")
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "proxy 10.88.0.5:8080" {
		t.Fatalf("after the resume sb-ha is served as %q, want its proxy route back", got)
	}
}

// failRouteWrites makes the emulator answer 500 to writes of routeID whose
// body contains marker, while on is set.
func failRouteWrites(e *emulatedCaddy, routeID, marker string, on *atomic.Bool) {
	e.setBefore(func(w http.ResponseWriter, r *http.Request) bool {
		if !on.Load() || (r.Method != http.MethodPatch && r.Method != http.MethodPut) {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if strings.Contains(string(body), `"`+routeID+`"`) && strings.Contains(string(body), marker) {
			http.Error(w, "injected admin failure", http.StatusInternalServerError)
			return true
		}
		return false
	})
}

// A route swap that fails is retried by the next check, never left with the
// proxy route in front of a frozen sandbox, and a failed swap back is retried
// too: the route is the 503 until the proxy route lands, never neither.
func TestFencedRouteSwapIsRetried(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, rt, e := leaseRouteWorker(t)
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	lc.up(selfPlacement("sb-ha"))
	t0 := time.Unix(80_000, 0)
	svc.beginOwnershipLease(t0)
	routeID := caddy.PortRouteID("sb-ha", 8080)

	var fail atomic.Bool
	failRouteWrites(e, routeID, "static_response", &fail)
	fail.Store(true)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: frozen")
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "proxy 10.88.0.5:8080" {
		t.Fatalf("with the admin write failing the route is %q; the test injects nothing", got)
	}
	fail.Store(false)
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("one check after a failed swap the route is %q; want the swap retried to 503", got)
	}

	// The swap back fails once: the route stays the 503 (the sandbox is
	// thawed, but a 503 is a quick answer), and the next check retries it.
	failRouteWrites(e, routeID, "reverse_proxy", &fail)
	fail.Store(true)
	lc.up(selfPlacement("sb-ha"))
	if err := svc.confirmOwnership(ctx, t0.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: resumed")
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("with the swap back failing the route is %q, want it still the 503", got)
	}
	fail.Store(false)
	svc.enforceOwnershipLease(ctx, t0.Add(21*time.Second))
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "proxy 10.88.0.5:8080" {
		t.Fatalf("one check after a failed swap back the route is %q; want the proxy route retried back", got)
	}
}

// Anything that re-installs the route while the sandbox is fenced (reconcile
// after Caddy lost its config, a port write) installs the 503, not the proxy.
func TestFencedRouteSurvivesAReinstall(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, _, e := leaseRouteWorker(t)
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	t0 := time.Unix(90_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	e.outOfBand(t, http.MethodDelete, "/id/"+caddy.PortRouteID("sb-ha", 8080), "")
	sb, err := st.Get(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.installHTTPPortRoute(ctx, sb, 8080); err != nil {
		t.Fatal(err)
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("a re-install of a fenced sandbox's route served it as %q, want 503", got)
	}
}

// A fence lifted before a partly failed swap was retried still swaps back
// the ports that did turn into 503: none is left answering 503 for a sandbox
// that runs again.
func TestResumeRestoresAPartlySwappedSandbox(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, _, e := leaseRouteWorker(t)
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-ha", Port: 9090, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-ha-9090.d.test", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	sb, err := st.Get(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.installHTTPPortRoute(ctx, sb, 9090); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(95_000, 0)
	svc.beginOwnershipLease(t0)
	var fail atomic.Bool
	failRouteWrites(e, caddy.PortRouteID("sb-ha", 9090), "static_response", &fail)
	fail.Store(true)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("precondition: port 8080 swapped, got %q", got)
	}
	if got := servedAs(t, e, "sb-ha-9090.d.test"); got != "proxy 10.88.0.5:9090" {
		t.Fatalf("precondition: port 9090 swap failed, got %q", got)
	}

	lc.up(selfPlacement("sb-ha"))
	if err := svc.confirmOwnership(ctx, t0.Add(18*time.Second)); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"sb-ha-8080.d.test": "proxy 10.88.0.5:8080", "sb-ha-9090.d.test": "proxy 10.88.0.5:9090"} {
		if got := servedAs(t, e, host); got != want {
			t.Fatalf("after the resume %s is served as %q, want %q", host, got, want)
		}
	}
}
