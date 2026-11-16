package service

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// lagCluster is the placement view one ingress node reads, the version
// that view is current to, and the placement version the node has seen,
// which on a gateway also counts point reads (a Raft node's applied index
// is both).
type lagCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements []cluster.Placement
	version    uint64
	view       uint64
}

func (c *lagCluster) PlacementsForShards(cluster.PlacementShardFilter) []cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Placement(nil), c.placements...)
}

func (c *lagCluster) PlacementVersion() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func (c *lagCluster) PlacementViewForShards(cluster.PlacementShardFilter) ([]cluster.Placement, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Placement(nil), c.placements...), c.view
}

// set is a view current to version, as on a Raft node.
func (c *lagCluster) set(version uint64, placements ...cluster.Placement) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version, c.view = version, version
	c.placements = placements
}

// pointRead is a gateway's point read of a row at version that its view
// does not hold yet: PlacementVersion moves, the view does not.
func (c *lagCluster) pointRead(version uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = max(c.version, version)
}

func publicPlacement(id string, version uint64) cluster.Placement {
	return cluster.Placement{
		SandboxID:          id,
		OwnerNodeID:        "node-A",
		OwnerAPIURL:        "http://10.0.0.1:21212",
		OwnerDataPlaneHost: "10.0.0.1",
		Version:            version,
		Spec:               &models.CreateSandboxRequest{AllowPublicTraffic: privateFlag(true)},
		ExposedPortRoutes:  map[int]cluster.ExposedPortRoute{3000: {Protocol: models.ExposedPortProtocolHTTP}},
	}
}

// A gateway whose Caddy admin API was down while sandboxes came and went
// must read no lag once a reconcile succeeds again: it has installed every
// route the view needs, and the routes of the deleted sandboxes went with
// them. It used to count only the highest version left in the view, so the
// lag stayed at the versions of the deleted sandboxes until the next create
// (issue #1343, kind: 32 on a converged gateway), and a quiet cluster kept
// SandboxdIngressRouteLag firing after the fix.
func TestReconcileClusterIngressRouteLagClearsAfterCaddyOutage(t *testing.T) {
	prevInstalled, prevLag := ingressPlacementVersionMax.Value(), ingressRouteLagVersions.Value()
	t.Cleanup(func() {
		ingressPlacementVersionMax.Set(prevInstalled)
		ingressRouteLagVersions.Set(prevLag)
	})
	ingressPlacementVersionMax.Set(0)

	fake := newCountingCaddyFake(0)
	var down atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "admin endpoint moved", http.StatusServiceUnavailable)
			return
		}
		fake.handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{
		// A domain, as on a gateway: every pass that is not idle checks the
		// layer4 app over the admin API, so each fails while it is down.
		cfg:    config.Config{EnableCluster: true, Domain: "aerolvm.test"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true,
			HTTPClientTimeout: 5 * time.Second}),
	}
	cl := &lagCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	svc.AttachCluster(cl)
	ctx := context.Background()
	lag := func() int64 { return ingressRouteLagVersions.Value() }

	cl.set(10, publicPlacement("sb-a", 10))
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("healthy reconcile: %v", err)
	}
	if lag() != 0 {
		t.Fatalf("healthy: lag %d, want 0", lag())
	}

	// Caddy's admin API goes away; a sandbox is created, then deleted.
	down.Store(true)
	cl.set(20, publicPlacement("sb-a", 10), publicPlacement("sb-b", 20))
	if err := svc.ReconcileClusterIngress(ctx); err == nil {
		t.Fatal("reconcile with Caddy down: want an error")
	}
	if lag() != 10 {
		t.Fatalf("Caddy down, one new placement: lag %d, want 10", lag())
	}
	cl.set(25, publicPlacement("sb-a", 10))
	if err := svc.ReconcileClusterIngress(ctx); err == nil {
		t.Fatal("reconcile with Caddy still down: want an error")
	}
	if lag() != 15 {
		t.Fatalf("Caddy still down after the delete: lag %d, want 15", lag())
	}

	// Caddy is back: the next pass converges, and the lag is gone with no
	// new create.
	down.Store(false)
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("reconcile after Caddy is back: %v", err)
	}
	if lag() != 0 {
		t.Fatalf("converged after the outage: lag %d, want 0 (the deleted sandbox's version must not count)", lag())
	}

	// Later entries that change nothing this node serves (an idle pass) keep
	// it at 0.
	cl.set(40, publicPlacement("sb-a", 10))
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatal(err)
	}
	if lag() != 0 {
		t.Fatalf("idle pass after more entries: lag %d, want 0", lag())
	}
}

// A gateway's PlacementVersion also moves with point reads: OwnerOf for
// every API call it routes reads the row of a sandbox the placement feed may
// not have delivered yet. A pass after such a read must not record that
// version as installed: /v1/cluster/placements/{id} would say the sandbox's
// route is in place on this gateway (node_installed_version) and the lag
// would read 0 while it is not (issue #1343 review). The view's own version
// is what a pass has caught up to.
func TestReconcileClusterIngressNeverRecordsAPointReadVersion(t *testing.T) {
	prevInstalled, prevLag := ingressPlacementVersionMax.Value(), ingressRouteLagVersions.Value()
	t.Cleanup(func() {
		ingressPlacementVersionMax.Set(prevInstalled)
		ingressRouteLagVersions.Set(prevLag)
	})
	ingressPlacementVersionMax.Set(0)

	fake := newCountingCaddyFake(0)
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{
		cfg:    config.Config{EnableCluster: true, Domain: "aerolvm.test"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true,
			HTTPClientTimeout: 5 * time.Second}),
	}
	cl := &lagCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	svc.AttachCluster(cl)
	ctx := context.Background()

	cl.set(10, publicPlacement("sb-a", 10))
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	// sb-b is created at version 11; an API call for it through this
	// gateway point-reads its row before the feed delivers it. A pass runs
	// (a timer, or an unrelated wake) over a view that still holds only
	// sb-a.
	cl.pointRead(11)
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("pass after the point read: %v", err)
	}
	if got := IngressInstalledVersion(); got >= 11 {
		t.Fatalf("installed %d >= sb-b's version 11, though sb-b's route was never installed here", got)
	}
	if lag := ingressRouteLagVersions.Value(); lag == 0 {
		t.Fatal("route lag 0 while this gateway knows of a placement its view has not installed")
	}
	// The feed delivers sb-b: the next pass installs it.
	cl.set(11, publicPlacement("sb-a", 10), publicPlacement("sb-b", 11))
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("pass after the feed: %v", err)
	}
	if got, lag := IngressInstalledVersion(), ingressRouteLagVersions.Value(); got != 11 || lag != 0 {
		t.Fatalf("after sb-b reached the view: installed %d, lag %d; want 11 and 0", got, lag)
	}
}
