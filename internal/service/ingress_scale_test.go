package service

import (
	"context"
	"fmt"
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

// makeScalePlacements builds a synthetic placement set sized for fleet-scale
// reconciler tests. Each placement is owned by an arbitrary remote node and
// carries one HTTP port and one TCP port — enough to exercise both the
// per-sandbox hash contribution and the per-port hash + counter paths without
// drowning the test in unrealistic per-sandbox fan-out (a 10K-sandbox fleet
// with 50 ports each isn't a shape we operate against).
func makeScalePlacements(n int) []cluster.Placement {
	out := make([]cluster.Placement, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sb-%07d", i)
		out[i] = cluster.Placement{
			SandboxID:          id,
			OwnerNodeID:        fmt.Sprintf("node-%03d", i%32),
			OwnerAPIURL:        fmt.Sprintf("http://10.0.%d.%d:21212", (i/256)%256, i%256),
			OwnerDataPlaneHost: fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256),
			Version:            uint64(i + 1),
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				3000: {Protocol: models.ExposedPortProtocolHTTP},
				5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22000 + i},
			},
		}
	}
	return out
}

// TestHashPlacementViewAt10KIsStable is the steady-state idle-skip claim at
// fleet scale: with 10K placements unchanged between ticks, the reconciler
// must produce the same hash and the same per-protocol counters — otherwise
// the reconciler would push ~30K Caddy admin calls every tick instead of
// returning early. Also logs the wall-clock so a future regression that
// turns hashing super-linear shows up in CI output.
func TestHashPlacementViewAt10KIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	placements := makeScalePlacements(10_000)

	t0 := time.Now()
	h1, c1, v1 := hashPlacementView("ingress-self", placements)
	first := time.Since(t0)

	t1 := time.Now()
	h2, c2, v2 := hashPlacementView("ingress-self", placements)
	second := time.Since(t1)

	if h1 != h2 {
		t.Fatalf("hash changed across identical calls: %x vs %x", h1, h2)
	}
	if c1 != c2 {
		t.Fatalf("counts changed across identical calls: %+v vs %+v", c1, c2)
	}
	if v1 != v2 {
		t.Fatalf("maxVersion changed across identical calls: %d vs %d", v1, v2)
	}
	// 10K placements × 2 ports + 1 sandbox-level route = 30K hash entries.
	// counts.http = sandbox-level routes (10K) + per-port HTTP (10K) = 20K.
	// counts.tcp = per-port TCP (10K).
	if c1.http != 20_000 || c1.tcp != 10_000 || c1.tls != 0 {
		t.Fatalf("counts mismatch: http=%d tls=%d tcp=%d", c1.http, c1.tls, c1.tcp)
	}
	if v1 != 10_000 {
		t.Fatalf("maxVersion = %d, want 10000", v1)
	}
	t.Logf("hashPlacementView(10K): first=%s, repeat=%s", first, second)
}

// TestHashPlacementViewAt10KDetectsSingleMutation pins that one placement
// flipping its Version is observable in the hash even when buried in 10K
// peers. Without this, the reconciler would silently miss small drifts —
// an ExposePort on one sandbox would never trigger a route reinstall if
// 9,999 unchanged peers diluted the hash.
func TestHashPlacementViewAt10KDetectsSingleMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	placements := makeScalePlacements(10_000)
	before, _, _ := hashPlacementView("ingress-self", placements)

	// Bump the version on a single placement in the middle of the set.
	placements[5_000].Version = 99_999_999
	after, _, _ := hashPlacementView("ingress-self", placements)

	if before == after {
		t.Fatalf("hash did not change when one of 10K placements bumped Version")
	}
}

// TestRunIngressOpsAt10KCompletesAll is the worker-pool scale claim: with
// 10K fast ops and concurrency=8, every op must run, the pool must not
// deadlock, and observed in-flight concurrency must respect the cap. The
// reconciler's correctness depends on "every queued admin call eventually
// runs" — a leak here would silently drop routes.
func TestRunIngressOpsAt10KCompletesAll(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	const n = 10_000
	var ran, inFlight, peakInFlight atomic.Int64
	ops := make([]func(context.Context) error, n)
	for i := 0; i < n; i++ {
		ops[i] = func(_ context.Context) error {
			cur := inFlight.Add(1)
			// Track high-water mark with a compare-and-swap retry so the
			// observed peak never undercounts under contention.
			for {
				prev := peakInFlight.Load()
				if cur <= prev || peakInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}
			ran.Add(1)
			inFlight.Add(-1)
			return nil
		}
	}

	start := time.Now()
	if err := runIngressOps(context.Background(), ops, clusterIngressMaxConcurrentWrites); err != nil {
		t.Fatalf("runIngressOps: %v", err)
	}
	elapsed := time.Since(start)

	if got := ran.Load(); got != n {
		t.Fatalf("ran=%d, want %d (ops were dropped by the pool)", got, n)
	}
	if peak := peakInFlight.Load(); peak > clusterIngressMaxConcurrentWrites {
		t.Fatalf("peak concurrency = %d, exceeded cap %d", peak, clusterIngressMaxConcurrentWrites)
	}
	t.Logf("runIngressOps(10K, cc=%d): wall=%s, peak in-flight=%d",
		clusterIngressMaxConcurrentWrites, elapsed, peakInFlight.Load())
}

// countingCaddyFake is a Caddy admin stand-in tuned for failover-storm
// load tests: every request is counted, peak in-flight is tracked, and a
// small artificial delay forces concurrent ops to actually overlap so the
// runIngressOps concurrency cap is observable instead of vacuously true on
// a fast loopback. The handler accepts whatever shape the reconciler sends
// (PATCH /id/*, DELETE /id/*, PUT /config/.../routes/0, PUT/DELETE
// /config/apps/layer4/servers/*) so a real caddy.Client can drive it.
type countingCaddyFake struct {
	mu              sync.Mutex
	totalCalls      int64
	inFlight        atomic.Int64
	peakInFlight    atomic.Int64
	perRoute        map[string]int
	installedRoutes map[string]struct{}
	installedL4     map[string]struct{}
	requestDelay    time.Duration
}

func newCountingCaddyFake(requestDelay time.Duration) *countingCaddyFake {
	return &countingCaddyFake{
		perRoute:        map[string]int{},
		installedRoutes: map[string]struct{}{},
		installedL4:     map[string]struct{}{},
		requestDelay:    requestDelay,
	}
}

func (f *countingCaddyFake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := f.inFlight.Add(1)
		defer f.inFlight.Add(-1)
		for {
			prev := f.peakInFlight.Load()
			if cur <= prev || f.peakInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		atomic.AddInt64(&f.totalCalls, 1)
		if f.requestDelay > 0 {
			time.Sleep(f.requestDelay)
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			// Empty-config snapshot is enough for gcClusterIngressRoutes to
			// run without exploding — it's looking for sandbox-* @ids and an
			// empty config has none.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"routes":[]}}},"layer4":{"servers":{"tls-mux":{"listen":[":443"],"routes":[]}}}}}`))
		case r.Method == http.MethodPatch && len(r.URL.Path) > len("/id/") && r.URL.Path[:4] == "/id/":
			id := r.URL.Path[4:]
			f.mu.Lock()
			f.perRoute[id]++
			_, present := f.installedRoutes[id]
			f.mu.Unlock()
			if present {
				w.WriteHeader(http.StatusOK)
			} else {
				// First PATCH for a never-seen @id: 404 forces the caddy.Client
				// fallback path (PUT routes/0). Mirrors real Caddy behavior.
				http.Error(w, "not found", http.StatusNotFound)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			// The reconciler PUTs the route body here on the create path. The
			// route's @id is inside the JSON; we don't need to parse it to
			// honor the contract — just record that an insert happened, and
			// the next PATCH for that id will succeed.
			//
			// In practice the second tick of the same view PATCHes the same
			// @id and hits 200 (no insert). For our failover test this means
			// the burst can include both PATCH and PUT calls per route.
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && len(r.URL.Path) > len("/id/") && r.URL.Path[:4] == "/id/":
			id := r.URL.Path[4:]
			f.mu.Lock()
			delete(f.installedRoutes, id)
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && len(r.URL.Path) > len("/config/apps/layer4/servers/") && r.URL.Path[:len("/config/apps/layer4/servers/")] == "/config/apps/layer4/servers/":
			sid := r.URL.Path[len("/config/apps/layer4/servers/"):]
			f.mu.Lock()
			f.installedL4[sid] = struct{}{}
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && len(r.URL.Path) > len("/config/apps/layer4/servers/") && r.URL.Path[:len("/config/apps/layer4/servers/")] == "/config/apps/layer4/servers/":
			sid := r.URL.Path[len("/config/apps/layer4/servers/"):]
			f.mu.Lock()
			delete(f.installedL4, sid)
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unhandled "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	})
}

// TestReconcileClusterIngressFailoverStormBoundedBurst pins the failover
// surge: when a node owning 50 sandboxes vanishes, every surviving peer
// must (a) install in-flux 503 routes for each orphaned placement, (b)
// keep concurrent admin calls inside the documented cap so Caddy's admin
// API never sees a thundering herd, and (c) issue a deterministic and
// bounded number of calls — not "one per gossip retry" or anything that
// could scale with cluster size. Without this assertion a regression that
// quietly removed the runIngressOps worker pool or fanned out per-port ops
// unbounded would only be caught at fleet scale, after it had already
// melted Caddy admin under a real failure.
func TestReconcileClusterIngressFailoverStormBoundedBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	const n = 50
	fake := newCountingCaddyFake(2 * time.Millisecond)
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	st, err := store.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	caddyClient := caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: 5 * time.Second,
	})

	svc := &Service{
		cfg:    config.Config{EnableCluster: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy:  caddyClient,
	}
	// Skip the caddy-l4 bootstrap path — this test exercises the per-tick
	// ingress write loop, not the L4 app handshake (covered in
	// layer4_bootstrap_test.go). Without this the first reconcile would
	// 400 on GET /config/apps/layer4 which our minimal fake doesn't model.
	svc.l4Ready.Store(true)

	// Healthy: 50 placements owned by node-A; we're "self" (router/peer).
	// Each carries one HTTP port and one TCP port, matching makeScalePlacements
	// shape so the per-port ingress branches all get exercised.
	healthy := make([]cluster.Placement, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("storm-%03d", i)
		healthy[i] = cluster.Placement{
			SandboxID:          id,
			OwnerNodeID:        "node-A",
			OwnerAPIURL:        "http://10.0.0.1:21212",
			OwnerDataPlaneHost: "10.0.0.1",
			Version:            uint64(i + 1),
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				3000: {Protocol: models.ExposedPortProtocolHTTP},
				5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22000 + i},
			},
		}
	}
	stub := &stubIngressCluster{Noop: cluster.NewNoop("self", "http://self"), placements: healthy}
	svc.AttachCluster(stub)

	ctx := context.Background()
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("healthy reconcile: %v", err)
	}
	healthyCalls := atomic.LoadInt64(&fake.totalCalls)
	healthyPeak := fake.peakInFlight.Load()

	// Simulate failover storm: node-A is dead, every owner gets cleared. The
	// reconciler's in-flux branch should fire once per placement (delete-live
	// + upsert-in-flux + per-HTTP-port mirror). TCP-port in-flux mirroring is
	// intentionally skipped by applyInFluxRoute, so the only TCP work in the
	// failover pass comes from gcClusterIngressRoutes if it sees orphan TCP
	// servers (it shouldn't, in this test — no store rows).
	atomic.StoreInt64(&fake.totalCalls, 0)
	fake.peakInFlight.Store(0)
	failover := make([]cluster.Placement, n)
	for i, p := range healthy {
		p.OwnerNodeID = ""
		p.OwnerAPIURL = ""
		p.OwnerDataPlaneHost = ""
		p.Version = uint64(i + 1 + n) // bump so hashPlacementView won't idle-skip
		failover[i] = p
	}
	stub.placements = failover
	// Belt and suspenders: reset the idle-skip hash directly so even an
	// unforeseen hash collision can't suppress the failover pass.
	svc.ingressLastHash.Store(0)

	start := time.Now()
	if err := svc.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("failover reconcile: %v", err)
	}
	elapsed := time.Since(start)
	failoverCalls := atomic.LoadInt64(&fake.totalCalls)
	failoverPeak := fake.peakInFlight.Load()

	// Bound 1: peak in-flight must respect the worker pool cap. With a
	// real Caddy a violation here means a real burst — the cap is the
	// single mechanism keeping admin queueing bounded.
	if healthyPeak > clusterIngressMaxConcurrentWrites {
		t.Fatalf("healthy peak concurrency = %d, exceeded cap %d", healthyPeak, clusterIngressMaxConcurrentWrites)
	}
	if failoverPeak > clusterIngressMaxConcurrentWrites {
		t.Fatalf("failover peak concurrency = %d, exceeded cap %d", failoverPeak, clusterIngressMaxConcurrentWrites)
	}

	// Bound 2: the failover pass must produce a bounded, predictable
	// number of admin calls. Per placement applyInFluxRoute issues:
	//   1 DeleteSandboxRoute  + 1 UpsertInFluxSandboxRoute
	//   per HTTP port: 1 DeletePortRoute + 1 UpsertInFluxPortRoute
	//   TCP ports: skipped (no hostname to in-flux)
	// One HTTP port per placement here → 4 admin calls per placement.
	// Upserts that fall through to the PUT-insert path on a cold cache
	// add one more call each (PATCH 404 + PUT). Allow that overhead but
	// reject anything that would imply unbounded fanout per placement.
	const perPlacementHard = 8 // 4 base + worst-case PATCH/PUT doubling on 2 upserts
	maxFailoverCalls := int64(n*perPlacementHard) + 4
	if failoverCalls > maxFailoverCalls {
		t.Fatalf("failover storm produced %d admin calls; expected ≤ %d (≤%d per placement). regression: per-placement fanout unbounded?",
			failoverCalls, maxFailoverCalls, perPlacementHard)
	}
	// And at least one full delete-live + upsert-in-flux per placement
	// must reach Caddy — a silent no-op pass would also "respect the cap"
	// while leaving every orphan serving a live route to a dead node.
	if min := int64(n * 2); failoverCalls < min {
		t.Fatalf("failover storm produced only %d admin calls; expected ≥ %d (delete-live + upsert-in-flux per placement)",
			failoverCalls, min)
	}

	t.Logf("failover storm (n=%d): healthy=%d calls peak=%d, failover=%d calls peak=%d, wall=%s",
		n, healthyCalls, healthyPeak, failoverCalls, failoverPeak, elapsed)
}

// BenchmarkHashPlacementView10K gives operators a number to track over time.
// At the 10K mark this is the inner-loop cost the idle-skip is paying every
// tick; a regression that pushes this from ~ms to ~100ms would silently
// starve the reconciler.
func BenchmarkHashPlacementView10K(b *testing.B) {
	placements := makeScalePlacements(10_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = hashPlacementView("ingress-self", placements)
	}
}
