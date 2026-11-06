package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// gateRouteWriter records the HTTP port route shape each write asked for
// and can fail the next wake-route write.
type gateRouteWriter struct {
	noopRouteWriter
	mu       sync.Mutex
	shapes   map[int]string
	failWake error
}

func (w *gateRouteWriter) set(port int, shape string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shapes == nil {
		w.shapes = map[int]string{}
	}
	w.shapes[port] = shape
}

func (w *gateRouteWriter) shape(port int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.shapes[port]
}

func (w *gateRouteWriter) UpsertPortRoute(_ context.Context, _, _ string, port int, _ ...caddy.HTTPRouteOptions) error {
	w.set(port, "direct")
	return nil
}

func (w *gateRouteWriter) UpsertWakeHTTPPortRoute(_ context.Context, _, _ string, port int) error {
	if w.failWake != nil {
		return w.failWake
	}
	w.set(port, "ingress")
	return nil
}

// newGateHarness is a running public sandbox on a domain-mode server whose
// route writes go to a gateRouteWriter.
func newGateHarness(t *testing.T) (*Service, *recordingRuntime, *gateRouteWriter, string) {
	t.Helper()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(svc.cfg)
	w := &gateRouteWriter{}
	svc.setRouteWriter(w)
	allow := true
	resp, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: &allow})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	return svc, rt, w, resp.ID
}

func lastAllowed(rt *recordingRuntime) []int {
	if len(rt.pushes) == 0 {
		return nil
	}
	return rt.pushes[len(rt.pushes)-1].ports
}

// A2 through the service: a token port gets the ingress-proxy route (never
// the direct one), is stored and reported as "token", is left off
// toolboxd's /proxy allowlist, and reads as gated to the ingress proxy. A
// re-expose that names no visibility keeps the gate; only an explicit
// "public" lifts it.
func TestExposeTokenVisibility(t *testing.T) {
	svc, rt, w, id := newGateHarness(t)
	ctx := context.Background()

	resp, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken)
	if err != nil {
		t.Fatalf("expose token: %v", err)
	}
	if resp.Visibility != models.ExposedPortVisibilityToken || w.shape(3000) != "ingress" {
		t.Fatalf("token expose: %+v, route %q", resp, w.shape(3000))
	}
	if _, err := svc.ExposePort(ctx, id, 4000, "http"); err != nil {
		t.Fatal(err)
	}
	if w.shape(4000) != "direct" {
		t.Fatalf("a public port took the %q route", w.shape(4000))
	}
	if got := lastAllowed(rt); len(got) != 1 || got[0] != 4000 {
		t.Fatalf("toolboxd allowlist = %v, want only the public port", got)
	}
	access, err := svc.PortAccess(ctx, id, 3000)
	if err != nil || !access.Started || !access.TokenGated {
		t.Fatalf("PortAccess(3000) = %+v, %v", access, err)
	}
	// Served from the warm cache now, still gated; the public port is not.
	if a, _ := svc.PortAccess(ctx, id, 3000); !a.TokenGated {
		t.Fatal("the warm cache lost the gate")
	}
	if a, _ := svc.PortAccess(ctx, id, 4000); a.TokenGated {
		t.Fatal("a public port reads as gated")
	}

	// A retry from a client that knows nothing of visibility keeps the gate.
	again, err := svc.ExposePort(ctx, id, 3000, "http")
	if err != nil || again.Visibility != models.ExposedPortVisibilityToken || again.PublicURL != resp.PublicURL || w.shape(3000) != "ingress" {
		t.Fatalf("plain re-expose: %+v %v, route %q", again, err, w.shape(3000))
	}
	sb, _ := svc.store.Get(ctx, id)
	if !portTokenGated(sb, 3000) {
		t.Fatal("plain re-expose lifted the gate in the store")
	}

	// An explicit "public" lifts it: direct route, stored public, back on
	// the allowlist, and the ingress proxy no longer asks for a token.
	pub, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityPublic)
	if err != nil || pub.Visibility != "" || w.shape(3000) != "direct" {
		t.Fatalf("explicit public: %+v %v, route %q", pub, err, w.shape(3000))
	}
	if a, _ := svc.PortAccess(ctx, id, 3000); a.TokenGated {
		t.Fatal("the gate outlived the change to public")
	}
	if got := lastAllowed(rt); len(got) != 2 {
		t.Fatalf("allowlist after lifting the gate = %v", got)
	}

	// Gate again, then unexpose: the cached gate goes with the row.
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnexposePort(ctx, id, 3000); err != nil {
		t.Fatal(err)
	}
	if a, _ := svc.PortAccess(ctx, id, 3000); a.TokenGated {
		t.Fatal("an unexposed port still reads as gated")
	}
}

// Where the gate could not hold, "token" is refused before anything
// changes: an unknown value, a TCP port, a server with no domain, a server
// with neither the wake proxy nor ingress proxy routing, a custom domain on
// the port. And a custom domain cannot target a gated port.
func TestExposeTokenVisibilityRefusals(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)

	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", "private"); !errors.Is(err, ErrTokenVisibilityInvalid) {
		t.Fatalf("unknown value: %v", err)
	}
	if _, err := svc.ExposePortWithVisibility(ctx, id, 5432, "tcp", models.ExposedPortVisibilityToken); !errors.Is(err, ErrTokenVisibilityUnavailable) {
		t.Fatalf("tcp: %v", err)
	}
	sb, _ := svc.store.Get(ctx, id)
	sb.CustomDomains = []models.CustomDomain{{Hostname: "app.acme.test", TargetPort: 3000}}
	if err := svc.checkTokenVisibility(sb, 3000, "http"); !errors.Is(err, ErrTokenVisibilityConflict) {
		t.Fatalf("custom domain on the port: %v", err)
	}
	sb.Runtime = models.RuntimeWasm
	if err := svc.checkTokenVisibility(sb, 3000, "http"); !errors.Is(err, ErrTokenVisibilityUnavailable) {
		t.Fatalf("wasm: %v", err)
	}

	svc.cfg.Domain = ""
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); !errors.Is(err, ErrTokenVisibilityUnavailable) {
		t.Fatalf("no domain: %v", err)
	}
	svc.cfg.Domain = "sandbox.test"

	// Caddy routes and no wake proxy (serverless off): no ingress proxy runs.
	svc.setRouteWriter(nil)
	svc.cfg.EnableServerless = false
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); !errors.Is(err, ErrTokenVisibilityUnavailable) {
		t.Fatalf("no ingress proxy: %v", err)
	}
	svc.setRouteWriter(w)
	if sb, _ := svc.store.Get(ctx, id); findExposure(sb, 3000) != nil {
		t.Fatal("a refused expose left a row")
	}

	// A custom domain cannot target a gated port.
	svc.cfg.EnableCustomDomains = true
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddCustomDomain(ctx, id, "app.acme.test", 3000); !errors.Is(err, ErrTokenVisibilityConflict) {
		t.Fatalf("custom domain on a gated port: %v", err)
	}
}

// A failed route write rolls the row back: a new token port leaves no row,
// and a public port that failed to become gated is stored public again, so
// the store never claims a gate the route does not have.
func TestExposeTokenVisibilityRollback(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)
	w.failWake = errors.New("caddy down")
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err == nil {
		t.Fatal("expose succeeded with the route write failing")
	}
	if sb, _ := svc.store.Get(ctx, id); findExposure(sb, 3000) != nil {
		t.Fatal("a failed new token expose left a row")
	}

	w.failWake = nil
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	w.failWake = errors.New("caddy down")
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err == nil {
		t.Fatal("gate change succeeded with the route write failing")
	}
	sb, _ := svc.store.Get(ctx, id)
	if e := findExposure(sb, 3000); e == nil || e.TokenGated() || w.shape(3000) != "direct" {
		t.Fatalf("after a failed gate change: %+v, route %q", e, w.shape(3000))
	}
	if a, _ := svc.PortAccess(ctx, id, 3000); a.TokenGated {
		t.Fatal("the cache kept a gate the store rolled back")
	}
}

// A cluster recreate replays the placement's port routes: a token route is
// re-exposed gated, and the placement mapping carries the visibility.
func TestTokenVisibilitySurvivesReplay(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)
	if err := svc.replayClusterExposedPorts(ctx, id, map[int]cluster.ExposedPortRoute{
		3000: {Protocol: "http", Visibility: models.ExposedPortVisibilityToken},
		4000: {Protocol: "http"},
	}); err != nil {
		t.Fatal(err)
	}
	if w.shape(3000) != "ingress" || w.shape(4000) != "direct" {
		t.Fatalf("replayed routes: 3000 %q, 4000 %q", w.shape(3000), w.shape(4000))
	}
	sb, _ := svc.store.Get(ctx, id)
	routes := clusterPortsFromSandbox(sb)
	if routes[3000].Visibility != models.ExposedPortVisibilityToken || routes[4000].Visibility != "" {
		t.Fatalf("placement routes = %+v", routes)
	}
}

// warmCacheSet (no port list) is never trusted for the gate: PortAccess
// reads the row instead.
func TestPortAccessIgnoresAnEntryWithoutPorts(t *testing.T) {
	ctx := context.Background()
	svc, _, _, id := newGateHarness(t)
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	svc.warmCacheSet(id)
	if a, err := svc.PortAccess(ctx, id, 3000); err != nil || !a.TokenGated {
		t.Fatalf("PortAccess after a port-less cache entry = %+v, %v", a, err)
	}
	if _, err := svc.PortAccess(ctx, "sb-none", 3000); err == nil {
		t.Fatal("an unknown sandbox has port access")
	}
	if portTokenGated(nil, 1) {
		t.Fatal("nil sandbox gated")
	}
}

type tokenPortGateCluster struct {
	*cluster.Noop
	open bool
}

func (c *tokenPortGateCluster) TokenPortsAllowed() bool { return c.open }

// In cluster mode a port becomes token-gated only once every live member
// keeps the gate through failover: a failover through an older build would
// recreate the port as public. A single node, with no older peer, always
// may; a cluster client that cannot answer, or a closed gate, refuses.
func TestTokenVisibilityWaitsForTheWholeCluster(t *testing.T) {
	svc, _, _, id := newGateHarness(t)
	sb, err := svc.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		enabled bool
		client  cluster.Client
		want    bool
	}{
		{name: "single node", client: cluster.NewNoop("n1", "", ""), want: true},
		{name: "cluster client that cannot answer", enabled: true, client: cluster.NewNoop("n1", "", "")},
		{name: "rolling upgrade in progress", enabled: true, client: &tokenPortGateCluster{Noop: cluster.NewNoop("n1", "", "")}},
		{name: "every member keeps the gate", enabled: true, client: &tokenPortGateCluster{Noop: cluster.NewNoop("n1", "", ""), open: true}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc.cfg.EnableCluster = tc.enabled
			svc.cluster = tc.client
			err := svc.checkTokenVisibility(sb, 3000, "http")
			if tc.want && err != nil {
				t.Fatalf("checkTokenVisibility = %v, want allowed", err)
			}
			if !tc.want && (!errors.Is(err, ErrTokenVisibilityUnavailable) || !strings.Contains(err.Error(), "upgrading the cluster")) {
				t.Fatalf("checkTokenVisibility = %v, want the upgrade refusal", err)
			}
		})
	}
	var nilSvc *Service
	if !nilSvc.tokenPortsClusterReady() {
		t.Fatal("a nil service refused (single-node default)")
	}
}

// Two expose calls on one port run one after the other. Without the port
// lock a "public" call landing while a "token" call is between its writes
// could leave the row saying "token" on the direct route, which skips the
// gate. Calls on another port do not wait. The lock map empties after.
func TestExposeCallsOnOnePortDoNotInterleave(t *testing.T) {
	ctx := context.Background()
	svc, _, w, id := newGateHarness(t)
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}

	publicDone := make(chan error, 1)
	var otherErr error
	// The hook fires again inside itself (the port 4000 call) and in the
	// public call: only the token call's first install does the checks.
	var fired atomic.Bool
	svc.testAfterHTTPPortInstall = func() {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		// The "token" call has written its row and route and still
		// holds the port. A "public" call on the same port must wait.
		go func() {
			_, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityPublic)
			publicDone <- err
		}()
		select {
		case err := <-publicDone:
			t.Errorf("a public call ran inside a token call on the same port (err %v)", err)
		case <-time.After(150 * time.Millisecond):
		}
		// Its route write can sit in the Caddy batcher, so "not done" is
		// not enough: it must not have written its row either.
		if sb, _ := svc.store.Get(ctx, id); !portTokenGated(sb, 3000) {
			t.Error("a public call wrote its row inside a token call on the same port")
		}
		_, otherErr = svc.ExposePort(ctx, id, 4000, "http")
	}
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	if otherErr != nil {
		t.Fatalf("a call on another port: %v", otherErr)
	}
	select {
	case err := <-publicDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the public call never ran after the token call let go")
	}

	// The later call wins, and the row and the route agree.
	sb, _ := svc.store.Get(ctx, id)
	if e := findExposure(sb, 3000); e == nil || e.TokenGated() || w.shape(3000) != "direct" {
		t.Fatalf("after token then public: %+v, route %q", e, w.shape(3000))
	}
	svc.portLocksMu.Lock()
	left := len(svc.portLocks)
	svc.portLocksMu.Unlock()
	if left != 0 {
		t.Fatalf("%d port locks left after every call returned", left)
	}
}

// A reader that read the row before a gate change must not cache it after
// the change invalidated the entry: the ingress proxy would let requests
// through without a token for up to warmCacheTTL.
func TestWarmCacheSkipsARowReadBeforeAnInvalidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _, id := newGateHarness(t)
	if _, err := svc.ExposePort(ctx, id, 3000, "http"); err != nil {
		t.Fatal(err)
	}
	gen := svc.warmGen.Load()
	before, err := svc.store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
		t.Fatal(err)
	}
	svc.warmCacheSetSandbox(before, gen)
	if svc.warmCacheHit(id) {
		t.Fatal("a row read before the gate change was cached after it")
	}
	if a, err := svc.PortAccess(ctx, id, 3000); err != nil || !a.TokenGated {
		t.Fatalf("PortAccess after the gate change = %+v, %v", a, err)
	}
	// A set with the current generation still caches.
	if !svc.warmCacheHit(id) {
		t.Fatal("PortAccess's own read was not cached")
	}
}
