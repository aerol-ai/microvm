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

// seedRootAndDomains gives the public sandbox id a custom domain that dials
// the toolbox and one that dials port 8080, and installs its root and
// custom-domain routes, as a create and AddCustomDomain leave them.
func seedRootAndDomains(t *testing.T, svc *Service, st *storepkg.Store, id string) {
	t.Helper()
	ctx := context.Background()
	if err := st.AddCustomDomain(ctx, id, "app-"+id+".example.com", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCustomDomain(ctx, id, "api-"+id+".example.com", 8080); err != nil {
		t.Fatal(err)
	}
	sb, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatalf("install the root route of %s: %v", id, err)
	}
}

// #1028 gave a paused sandbox's public ports a 503, but its other public
// URLs still proxied to the frozen process and hung: the toolbox route
// <id>.<domain> and its custom domains (#1028's "Not in this PR"). The fence
// now swaps those too, and the resume swaps them back.
func TestFencedSandboxRootAndCustomDomainsAnswer503(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, rt, e := leaseRouteWorker(t)
	svc.cfg.ToolboxPort = 2280
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	seedPublicLeaseRow(t, svc, st, "sb-plain", "10.88.0.6", false)
	seedRootAndDomains(t, svc, st, "sb-ha")
	seedRootAndDomains(t, svc, st, "sb-plain")
	live := func(id, ip string) map[string]string {
		return map[string]string{
			id + ".d.test":               "proxy " + ip + ":2280",
			"app-" + id + ".example.com": "proxy " + ip + ":2280",
			"api-" + id + ".example.com": "proxy " + ip + ":8080",
		}
	}
	check := func(when string, want map[string]string) {
		t.Helper()
		for host, w := range want {
			if got := servedAs(t, e, host); got != w {
				t.Fatalf("%s: %s is served as %q, want %q", when, host, got, w)
			}
		}
	}
	check("before the fence", live("sb-ha", "10.88.0.5"))

	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-plain"))
	t0 := time.Unix(100_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatal(err)
	}
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-ha") || !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: sb-ha fenced and frozen")
	}
	check("while sb-ha is fenced", map[string]string{
		"sb-ha.d.test":          "503 retry-after=2",
		"app-sb-ha.example.com": "503 retry-after=2",
		"api-sb-ha.example.com": "503 retry-after=2",
		"sb-ha-8080.d.test":     "503 retry-after=2",
	})
	check("sb-plain is not fenced", live("sb-plain", "10.88.0.6"))

	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-plain"))
	if err := svc.confirmOwnership(ctx, t0.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	if svc.OwnershipFenced("sb-ha") {
		t.Fatal("precondition: sb-ha resumed")
	}
	check("after the resume", live("sb-ha", "10.88.0.5"))
}

// Anything that rewrites the root route while the sandbox is fenced (a
// reconcile after Caddy lost its config, a custom domain added) writes the
// 503, not the proxy.
func TestFencedRootRouteSurvivesARewrite(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, _, e := leaseRouteWorker(t)
	svc.cfg.ToolboxPort = 2280
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	seedRootAndDomains(t, svc, st, "sb-ha")
	t0 := time.Unix(110_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-ha") {
		t.Fatal("precondition: fenced")
	}

	e.outOfBand(t, http.MethodDelete, "/id/"+caddy.SandboxRouteID("sb-ha"), "")
	if err := st.AddCustomDomain(ctx, "sb-ha", "new-sb-ha.example.com", 0); err != nil {
		t.Fatal(err)
	}
	sb, err := st.Get(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncSandboxPublicRoute(ctx, sb); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"sb-ha.d.test", "app-sb-ha.example.com", "api-sb-ha.example.com", "new-sb-ha.example.com"} {
		if got := servedAs(t, e, host); got != "503 retry-after=2" {
			t.Fatalf("a rewrite while fenced served %s as %q, want 503", host, got)
		}
	}
}

// A WASM sandbox's custom domains are written again after an expose or a
// domain change (syncWasmCustomDomainRoutes, to the host mediator). While it
// is fenced that rewrite writes the 503 too, so it cannot put the live route
// back over the fence's.
func TestFencedWasmCustomDomainStays503(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _, e := leaseRouteWorker(t)
	svc.cfg.ToolboxPort = 2280
	now := time.Now().UTC()
	public := true
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-w", Image: "python", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
		ContainerIP: "127.0.0.1", AllowPublicTraffic: &public, AuditIncarnationID: "inc-sb-w",
		CPU: 1, MemoryMB: 128, DiskGB: 1, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCustomDomain(ctx, "sb-w", "w.example.com", 0); err != nil {
		t.Fatal(err)
	}
	sb, err := st.Get(ctx, "sb-w")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncWasmCustomDomainRoutes(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got := servedAs(t, e, "w.example.com"); got != "proxy 127.0.0.1:2280" {
		t.Fatalf("before the fence w.example.com is %q, want the mediator proxy", got)
	}

	svc.ownership.mu.Lock()
	svc.fenceLocked("sb-w")
	svc.ownership.mu.Unlock()
	if err := svc.syncWasmCustomDomainRoutes(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got := servedAs(t, e, "w.example.com"); got != "503 retry-after=2" {
		t.Fatalf("a WASM custom-domain rewrite while fenced served it as %q, want 503", got)
	}

	svc.ownership.mu.Lock()
	svc.unfenceLocked("sb-w")
	svc.ownership.mu.Unlock()
	if err := svc.syncWasmCustomDomainRoutes(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got := servedAs(t, e, "w.example.com"); got != "proxy 127.0.0.1:2280" {
		t.Fatalf("after the fence the rewrite served it as %q, want the mediator proxy back", got)
	}
}

// A failed swap of the root route is retried by the next check, like a
// port's: until it lands, routesFenced stays unset.
func TestFencedRootRouteSwapIsRetried(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, _, e := leaseRouteWorker(t)
	svc.cfg.ToolboxPort = 2280
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	seedRootAndDomains(t, svc, st, "sb-ha")
	t0 := time.Unix(120_000, 0)
	svc.beginOwnershipLease(t0)
	var fail atomic.Bool
	failRouteWrites(e, caddy.SandboxRouteID("sb-ha"), "static_response", &fail)
	fail.Store(true)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if got := servedAs(t, e, "sb-ha.d.test"); got != "proxy 10.88.0.5:2280" {
		t.Fatalf("with the admin write failing the root route is %q; the test injects nothing", got)
	}
	fail.Store(false)
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	if got := servedAs(t, e, "sb-ha.d.test"); got != "503 retry-after=2" {
		t.Fatalf("one check after a failed swap the root route is %q; want the swap retried to 503", got)
	}
}

// l4Route finds the layer4 route with @id routeID in any server and returns
// its server's listen addresses, its SNI matcher and its handler names.
func l4Route(t *testing.T, e *emulatedCaddy, routeID string) (listen, sni, handlers []string) {
	t.Helper()
	resp, err := e.emu.RoundTrip(httptest.NewRequest(http.MethodGet, "/config/apps/layer4/servers", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var servers map[string]struct {
		Listen []string `json:"listen"`
		Routes []struct {
			ID    string `json:"@id"`
			Match []struct {
				TLS struct {
					SNI []string `json:"sni"`
				} `json:"tls"`
			} `json:"match"`
			Handle []struct {
				Handler string `json:"handler"`
			} `json:"handle"`
		} `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		t.Fatal(err)
	}
	for _, srv := range servers {
		for _, r := range srv.Routes {
			if r.ID != routeID {
				continue
			}
			for _, m := range r.Match {
				sni = append(sni, m.TLS.SNI...)
			}
			for _, h := range r.Handle {
				handlers = append(handlers, h.Handler)
			}
			return srv.Listen, sni, handlers
		}
	}
	t.Fatalf("no layer4 route %q", routeID)
	return nil, nil, nil
}

// Raw TCP and TLS exposures cannot carry a 503 (#1028), but a proxy to the
// frozen process hung every new connection. While the sandbox is fenced the
// route closes each new connection at once instead: the TCP server keeps its
// listener on the host port, the TLS route keeps its SNI matcher. The resume
// puts the proxies back.
func TestFencedSandboxTCPAndTLSPortsClose(t *testing.T) {
	ctx := context.Background()
	svc, st, lc, rt, e := leaseRouteWorker(t)
	svc.l4Ready.Store(true)
	seedPublicLeaseRow(t, svc, st, "sb-ha", "10.88.0.5", true)
	now := time.Now().UTC()
	for _, p := range []models.ExposedPort{
		{SandboxID: "sb-ha", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 40001, PublicURL: "tcp://d.test:40001", CreatedAt: now},
		{SandboxID: "sb-ha", Port: 6379, Protocol: models.ExposedPortProtocolTLS, PublicURL: "tls://sb-ha-6379.d.test:443", CreatedAt: now},
	} {
		if err := st.UpsertPort(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	sb, err := st.Get(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.installTCPPortRoute(ctx, sb, 5432, 40001); err != nil {
		t.Fatal(err)
	}
	if err := svc.installTLSPortRoute(ctx, sb, 6379); err != nil {
		t.Fatal(err)
	}
	const tcpID, tlsID = "sandbox-sb-ha-port-5432-tcp", "sandbox-sb-ha-port-6379-tls"
	live := func(when string) {
		t.Helper()
		if listen, _, h := l4Route(t, e, tcpID); strings.Join(h, ",") != "proxy" || strings.Join(listen, ",") != ":40001" {
			t.Fatalf("%s: tcp route = listen %v handlers %v, want the proxy on :40001", when, listen, h)
		}
		if _, sni, h := l4Route(t, e, tlsID); strings.Join(h, ",") != "tls,proxy" || strings.Join(sni, ",") != "sb-ha-6379.d.test" {
			t.Fatalf("%s: tls route = sni %v handlers %v, want tls,proxy on sb-ha-6379.d.test", when, sni, h)
		}
	}
	live("before the fence")

	lc.up(selfPlacement("sb-ha"))
	t0 := time.Unix(130_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatal(err)
	}
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-ha") || !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: sb-ha fenced and frozen")
	}
	if listen, _, h := l4Route(t, e, tcpID); strings.Join(h, ",") != "close" || strings.Join(listen, ",") != ":40001" {
		t.Fatalf("fenced tcp route = listen %v handlers %v, want close on :40001 (listener kept)", listen, h)
	}
	if _, sni, h := l4Route(t, e, tlsID); strings.Join(h, ",") != "close" || strings.Join(sni, ",") != "sb-ha-6379.d.test" {
		t.Fatalf("fenced tls route = sni %v handlers %v, want close on sb-ha-6379.d.test", sni, h)
	}
	if got := servedAs(t, e, "sb-ha-8080.d.test"); got != "503 retry-after=2" {
		t.Fatalf("fenced http port = %q, want 503", got)
	}

	// A reinstall while fenced (reconcile) keeps the close.
	if err := svc.installTCPPortRoute(ctx, sb, 5432, 40001); err != nil {
		t.Fatal(err)
	}
	if _, _, h := l4Route(t, e, tcpID); strings.Join(h, ",") != "close" {
		t.Fatalf("a reinstall while fenced wrote tcp handlers %v, want close", h)
	}

	lc.up(selfPlacement("sb-ha"))
	if err := svc.confirmOwnership(ctx, t0.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	live("after the resume")
}
