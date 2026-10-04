package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ingressNodeCaddyConfig is a dedicated ingress node's Caddy before any
// sandbox route: the Caddyfile's catch-all sites and a tls-mux holding only
// its fallback to the local HTTPS listener.
const ingressNodeCaddyConfig = `{"apps":{
 "http":{"servers":{"srv0":{"routes":[
  {"match":[{"host":["d.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:21212"}]}],"terminal":true},
  {"match":[{"host":["*.d.test"]}],"handle":[{"handler":"static_response","body":"Sandbox not found","status_code":404}],"terminal":true}]}}},
 "layer4":{"servers":{"tls-mux":{"listen":[":443"],"routes":[
  {"@id":"tls-mux-fallback","handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:8443"]}]}]}]}}}}}`

// emulatedCaddy serves the caddy package's config emulator (real admin
// semantics: PATCH by @id, insert-before PUT, duplicate-ID refusal) over
// HTTP. It does not serialize requests, so overlapping writes are visible
// in peak, and before lets a test drop or fail a request.
type emulatedCaddy struct {
	emu   http.RoundTripper
	srv   *httptest.Server
	delay time.Duration

	inFlight, peak atomic.Int32

	mu     sync.Mutex
	before func(w http.ResponseWriter, r *http.Request) bool // true: handled
}

func newEmulatedCaddy(t *testing.T, delay time.Duration) *emulatedCaddy {
	t.Helper()
	var root any
	if err := json.Unmarshal([]byte(ingressNodeCaddyConfig), &root); err != nil {
		t.Fatal(err)
	}
	e := &emulatedCaddy{emu: caddy.NewConfigEmulator(root), delay: delay}
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *emulatedCaddy) setBefore(fn func(w http.ResponseWriter, r *http.Request) bool) {
	e.mu.Lock()
	e.before = fn
	e.mu.Unlock()
}

func (e *emulatedCaddy) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	before := e.before
	e.mu.Unlock()
	if before != nil && before(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		n := e.inFlight.Add(1)
		defer e.inFlight.Add(-1)
		for {
			p := e.peak.Load()
			if n <= p || e.peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(e.delay)
	}
	e.apply(w, r)
}

// apply runs r against the config without fault injection.
func (e *emulatedCaddy) apply(w http.ResponseWriter, r *http.Request) {
	resp, err := e.emu.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// outOfBand changes the config behind sandboxd's back, the way a Caddy
// restart or an operator's admin call does.
func (e *emulatedCaddy) outOfBand(t *testing.T, method, path, body string) {
	t.Helper()
	resp, err := e.emu.RoundTrip(httptest.NewRequest(method, path, strings.NewReader(body)))
	if err != nil || resp.StatusCode >= 400 {
		t.Fatalf("out-of-band %s %s: %v %v", method, path, resp.StatusCode, err)
	}
}

func (e *emulatedCaddy) routeIDs(t *testing.T, path string) []string {
	t.Helper()
	resp, err := e.emu.RoundTrip(httptest.NewRequest(http.MethodGet, path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want the route list", path, resp.StatusCode)
	}
	var routes []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	ids := make([]string, 0, len(routes))
	for _, r := range routes {
		id, _ := r["@id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func (e *emulatedCaddy) tlsMuxRouteIDs(t *testing.T) []string {
	return e.routeIDs(t, "/config/apps/layer4/servers/tls-mux/routes")
}

// hijackClose drops the connection without a response: the client sees EOF.
func hijackClose(t *testing.T, w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.Close()
}

// newLiveIngressService is a dedicated ingress node (the ingress-1 shape)
// reconciling against e, with placements owned by worker-z.
func newLiveIngressService(t *testing.T, e *emulatedCaddy, placements ...cluster.Placement) *Service {
	t.Helper()
	cfg := config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleIngress, EnableCaddy: true,
		Domain: "d.test", L4TLSListen: ":443", L4TLSFallback: "127.0.0.1:8443",
		CaddyAdminURL: e.srv.URL, CaddyServerID: "srv0", HTTPClientTimeout: 5 * time.Second,
	}
	svc := &Service{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		caddy:  caddy.New(cfg),
	}
	svc.AttachCluster(&stubIngressCluster{
		Noop:       cluster.NewNoop("ingress-1", "http://ingress-1", ""),
		placements: placements,
		members:    []cluster.Member{{NodeID: "ingress-1", Alive: true, Role: config.NodeRoleIngress, APIURL: "http://ingress-1"}},
	})
	return svc
}

// exposedPlacement is a sandbox on worker-z with port 8080 exposed over
// HTTP (expose_port opts the sandbox into public traffic).
func exposedPlacement(id string) cluster.Placement {
	return cluster.Placement{
		SandboxID: id, OwnerNodeID: "worker-z",
		OwnerAPIURL: "http://10.42.1.108:21212", OwnerDataPlaneHost: "10.42.1.108",
		Version: 7, PublicTraffic: true,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{8080: {Protocol: models.ExposedPortProtocolHTTP}},
	}
}

func requireRouteOnce(t *testing.T, ids []string, id string) {
	t.Helper()
	n := 0
	for _, got := range ids {
		if got == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("config holds %d copies of %s, want 1 (route ids: %v)", n, id, ids)
	}
}

func requireRouteAbsent(t *testing.T, ids []string, id string) {
	t.Helper()
	for _, got := range ids {
		if got == id {
			t.Fatalf("%s is in the config, want it absent (route ids: %v)", id, ids)
		}
	}
}

func dueLiveAudit(svc *Service) {
	svc.ingressLastFullGCUnix.Store(time.Now().Add(-2 * clusterIngressFullGCInterval).Unix())
}

// The reconciler used to trust its own route cache: once it had written a
// route, nothing put it back if Caddy lost it, and the periodic pass only
// deleted extra routes. The live audit compares desired routes by @id with
// Caddy's actual config and re-applies what is missing.
func TestReconcileClusterIngressReaddsRoutesCaddyLost(t *testing.T) {
	const sb = "sb-327b99d07eac8f25"
	sandboxRoute := caddy.IngressSandboxSNIRouteID(sb)
	portRoute := caddy.IngressPortSNIRouteID(sb, 8080)
	for _, tc := range []struct {
		name string
		lose func(t *testing.T, e *emulatedCaddy)
		gone []string
	}{
		{
			name: "one route deleted behind sandboxd's back",
			lose: func(t *testing.T, e *emulatedCaddy) {
				e.outOfBand(t, http.MethodDelete, "/id/"+portRoute, "")
			},
			gone: []string{portRoute},
		},
		{
			// caddy.service runs `caddy run --config Caddyfile` without
			// --resume: a restart drops every dynamic route.
			name: "caddy restarted from its Caddyfile",
			lose: func(t *testing.T, e *emulatedCaddy) {
				e.outOfBand(t, http.MethodPatch, "/config/apps/layer4/servers/tls-mux/routes",
					`[{"@id":"tls-mux-fallback","handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:8443"]}]}]}]`)
			},
			gone: []string{sandboxRoute, portRoute},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEmulatedCaddy(t, 0)
			svc := newLiveIngressService(t, e, exposedPlacement(sb))
			ctx := context.Background()

			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("first pass: %v", err)
			}
			requireRouteOnce(t, e.tlsMuxRouteIDs(t), sandboxRoute)
			requireRouteOnce(t, e.tlsMuxRouteIDs(t), portRoute)

			tc.lose(t, e)

			// Unchanged view, no audit due: the pass idles. This is the
			// window the audit bounds.
			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("idle pass: %v", err)
			}
			for _, id := range tc.gone {
				requireRouteAbsent(t, e.tlsMuxRouteIDs(t), id)
			}

			dueLiveAudit(svc)
			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("audit pass: %v", err)
			}
			ids := e.tlsMuxRouteIDs(t)
			requireRouteOnce(t, ids, sandboxRoute)
			requireRouteOnce(t, ids, portRoute)
			if ids[len(ids)-1] != "tls-mux-fallback" {
				t.Fatalf("fallback is not last after the re-add: %v", ids)
			}
		})
	}
}

// One pass must never have two admin writes in flight, and lifecycle writes
// racing it on the same client must not either; no insert may be lost.
// Live 2026-10-04 (ingress-1): one pass issued two PUT routes/0 within 1ms,
// and two later passes failed with EOF on a write racing the other's reload.
func TestReconcileClusterIngressNeverOverlapsAdminWrites(t *testing.T) {
	e := newEmulatedCaddy(t, 2*time.Millisecond)
	var placements []cluster.Placement
	for i := range 8 {
		placements = append(placements, exposedPlacement(fmt.Sprintf("sb-%02d", i)))
	}
	svc := newLiveIngressService(t, e, placements...)
	// No live audit: this service has no store, so its GC would rightly
	// treat the local routes below as zombies.
	svc.ingressLastFullGCUnix.Store(time.Now().Unix())
	ctx := context.Background()

	// A node that is ingress AND owner (mixed) writes its own routes on the
	// same client while the reconciler runs: a PATCH-then-PUT upsert, and a
	// single-request raw-TCP server write.
	var lifecycle sync.WaitGroup
	lifecycleErrs := make(chan error, 16)
	for i := range 8 {
		lifecycle.Add(1)
		go func() {
			defer lifecycle.Done()
			id := fmt.Sprintf("local-%d", i)
			if err := svc.publicRoutes().UpsertPortRoute(ctx, id, "10.1.0.2", 3000); err != nil {
				lifecycleErrs <- err
			}
			if err := svc.publicRoutes().UpsertTCPRoute(ctx, id, "10.1.0.2", 5432, 22000+i); err != nil {
				lifecycleErrs <- err
			}
		}()
	}
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	lifecycle.Wait()
	close(lifecycleErrs)
	for err := range lifecycleErrs {
		t.Fatalf("lifecycle write: %v", err)
	}

	if got := e.peak.Load(); got != 1 {
		t.Fatalf("peak concurrent admin writes = %d, want 1", got)
	}
	ids := e.tlsMuxRouteIDs(t)
	for _, p := range placements {
		requireRouteOnce(t, ids, caddy.IngressSandboxSNIRouteID(p.SandboxID))
		requireRouteOnce(t, ids, caddy.IngressPortSNIRouteID(p.SandboxID, 8080))
	}
	httpIDs := e.routeIDs(t, "/config/apps/http/servers/srv0/routes")
	for i := range 8 {
		requireRouteOnce(t, httpIDs, caddy.PortRouteID(fmt.Sprintf("local-%d", i), 3000))
		e.routeIDs(t, fmt.Sprintf("/config/apps/layer4/servers/tcp-port-%d/routes", 22000+i))
	}
}

// A write that dies with the connection (EOF) may or may not have landed.
// The pass reports a transient error, the loop retries in 500ms instead of
// 5s, and the replay converges to exactly one copy either way.
func TestReconcileClusterIngressConvergesAfterAWriteDiesInFlight(t *testing.T) {
	const sb = "sb-a4aed2c1cbb841f1"
	for _, tc := range []struct {
		name    string
		applied bool
	}{
		{"write lost before Caddy applied it", false},
		{"write applied, response lost", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEmulatedCaddy(t, 0)
			svc := newLiveIngressService(t, e, exposedPlacement(sb))
			ctx := context.Background()

			var dropped atomic.Bool
			e.setBefore(func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodPut || dropped.Swap(true) {
					return false
				}
				if tc.applied {
					e.apply(httptest.NewRecorder(), r)
				}
				hijackClose(t, w)
				return true
			})

			err := svc.ReconcileClusterIngress(ctx)
			if err == nil {
				t.Fatal("pass with a dropped write reported success")
			}
			if !caddy.IsTransientAdminError(err) {
				t.Fatalf("dropped connection = %v; want a transient admin error", err)
			}
			if wait, _ := nextClusterIngressWait(err, clusterIngressTransientRetryDelay); wait != clusterIngressTransientRetryDelay {
				t.Fatalf("retry after a transient error in %s, want %s", wait, clusterIngressTransientRetryDelay)
			}

			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("replay pass: %v", err)
			}
			ids := e.tlsMuxRouteIDs(t)
			requireRouteOnce(t, ids, caddy.IngressSandboxSNIRouteID(sb))
			requireRouteOnce(t, ids, caddy.IngressPortSNIRouteID(sb, 8080))
		})
	}
}

// An audit that did not finish runs again on the next pass, not a minute
// later.
func TestReconcileClusterIngressRearmsAnUnfinishedAudit(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(r *http.Request) bool
	}{
		{"snapshot fails", func(r *http.Request) bool { return r.Method == http.MethodGet && r.URL.Path == "/config/" }},
		{"layer4 repair fails", func(r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == "/config/apps/layer4"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEmulatedCaddy(t, 0)
			svc := newLiveIngressService(t, e, exposedPlacement("sb-audit"))
			ctx := context.Background()
			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("first pass: %v", err)
			}

			var failing atomic.Bool
			failing.Store(true)
			e.setBefore(func(w http.ResponseWriter, r *http.Request) bool {
				if failing.Load() && tc.fail(r) {
					http.Error(w, `{"error":"down"}`, http.StatusInternalServerError)
					return true
				}
				return false
			})
			dueLiveAudit(svc)
			if err := svc.ReconcileClusterIngress(ctx); err == nil {
				t.Fatal("audit pass with a failing admin read reported success")
			}
			if got := svc.ingressLastFullGCUnix.Load(); got != 0 {
				t.Fatalf("audit clock = %d after a failed audit, want 0 (re-armed)", got)
			}

			failing.Store(false)
			e.outOfBand(t, http.MethodDelete, "/id/"+caddy.IngressPortSNIRouteID("sb-audit", 8080), "")
			if err := svc.ReconcileClusterIngress(ctx); err != nil {
				t.Fatalf("re-armed audit pass: %v", err)
			}
			requireRouteOnce(t, e.tlsMuxRouteIDs(t), caddy.IngressPortSNIRouteID("sb-audit", 8080))
			if svc.ingressLastFullGCUnix.Load() == 0 {
				t.Fatal("a finished audit must restart the audit clock")
			}
		})
	}
}

// Single-node and cluster-off make no admin call at all, audit due or not.
func TestReconcileClusterIngressNoopWithoutClusterIngress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Service)
	}{
		{"cluster off", func(s *Service) { s.cfg.EnableCluster = false }},
		{"dedicated worker", func(s *Service) { s.cfg.NodeRole = config.NodeRoleWorker }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEmulatedCaddy(t, 0)
			var calls atomic.Int32
			e.setBefore(func(http.ResponseWriter, *http.Request) bool { calls.Add(1); return false })
			svc := newLiveIngressService(t, e, exposedPlacement("sb-noop"))
			tc.mutate(svc)
			dueLiveAudit(svc)
			if err := svc.ReconcileClusterIngress(context.Background()); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("made %d admin calls, want 0", got)
			}
		})
	}
}

func TestMissingIngressRoutes(t *testing.T) {
	intents := map[string]ingressRouteIntent{
		"tls:a":  {surface: ingressSurfaceTLS, routeID: "sandbox-a-ingress-sni"},
		"tls:b":  {surface: ingressSurfaceTLS, routeID: "sandbox-b-ingress-sni"},
		"http:c": {surface: ingressSurfaceHTTP, routeID: "sandbox-c"},
		"tcp:d":  {surface: ingressSurfaceTCP, routeID: "tcp-port-22001"},
		// Present, but on another surface: still missing where it belongs.
		"http:e": {surface: ingressSurfaceHTTP, routeID: "sandbox-e-ingress-sni"},
	}
	live := &caddy.Snapshot{
		HTTPRouteIDs:   []string{"sandbox-c"},
		L4TCPServerIDs: []string{"tcp-port-22001"},
		L4TLSRouteIDs:  []string{"sandbox-a-ingress-sni", "sandbox-e-ingress-sni"},
	}

	svc := &Service{}
	got := svc.missingIngressRoutes(intents, live)
	want := map[string]struct{}{"tls:b": {}, "http:e": {}}
	if len(got) != len(want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing = %v, want %v", got, want)
		}
	}

	if got := svc.missingIngressRoutes(intents, nil); got != nil {
		t.Fatalf("no audit this pass: missing = %v, want nil", got)
	}
	// Under proxy routing per-sandbox routes live in the index, not Caddy;
	// their absence from Caddy is the point, not drift.
	svc.setRouteWriter(noopRouteWriter{})
	if got := svc.missingIngressRoutes(intents, live); got != nil {
		t.Fatalf("proxy routing: missing = %v, want nil", got)
	}
}

func TestNextClusterIngressWait(t *testing.T) {
	transient := fmt.Errorf("delete caddy route: %w", &url.Error{Op: "Delete", URL: "http://127.0.0.1:2019/id/x", Err: io.EOF})
	retry := clusterIngressTransientRetryDelay
	var waits []time.Duration
	for range 6 {
		var wait time.Duration
		wait, retry = nextClusterIngressWait(transient, retry)
		waits = append(waits, wait)
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("consecutive transient waits = %v, want %v", waits, want)
		}
	}

	for _, err := range []error{nil, errors.New("insert caddy route failed: 400"), context.Canceled} {
		wait, next := nextClusterIngressWait(err, 4*time.Second)
		if wait != clusterIngressReconcileInterval || next != clusterIngressTransientRetryDelay {
			t.Fatalf("err %v: wait %s next %s, want the interval and a reset backoff", err, wait, next)
		}
	}
	if wait, _ := nextClusterIngressWait(transient, 0); wait != clusterIngressTransientRetryDelay {
		t.Fatalf("zero backoff waited %s, want %s", wait, clusterIngressTransientRetryDelay)
	}
}
