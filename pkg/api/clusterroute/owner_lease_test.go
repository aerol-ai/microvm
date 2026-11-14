package clusterroute

import (
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// leaseFleet is a fleet in cluster mode with the owner cache flag on, which
// also turns on the owner's lease fast path (E3b).
func leaseFleet(t *testing.T, withCache bool, ids ...string) *fleet {
	t.Helper()
	return newFleetWithConfig(t, withCache, config.Config{EnableCluster: true, ClusterOwnerCache: true, ClusterDeadOwnerGrace: 30 * time.Second, NodeRole: config.NodeRoleWorker}, ids...)
}

// prove installs, on node, a lease reading taken now that proves it owns id
// at the epoch the shared table holds.
func (f *fleet) prove(node, id string, age time.Duration) {
	f.nodes[node].svc.SetOwnerLeaseForTest(map[string]uint64{id: f.epochOf(id)}, time.Now().Add(-age))
}

// With the edge's fresh lookup and the owner's lease reading agreeing on the
// epoch, the owner serves without a lookup of its own: one control-plane
// read per call instead of two.
func TestOwnerServesFromItsLeaseWithoutALookup(t *testing.T) {
	f := leaseFleet(t, false, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.prove("worker-a", "sb-1", 0)

	serves0 := expvarInt(t, "aerolvm_cluster_owner_lease_serves_total")
	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Served-By") != "worker-a" {
		t.Fatalf("got %d from %q, want 200 from worker-a", rr.Code, rr.Header().Get("X-Served-By"))
	}
	if d.lookups != 1 {
		t.Fatalf("lookups = %d, want 1 (the edge's only)", d.lookups)
	}
	if got := expvarInt(t, "aerolvm_cluster_owner_lease_serves_total") - serves0; got != 1 {
		t.Fatalf("lease serves delta = %d, want 1", got)
	}
}

// With the owner cache on too, a routed call in steady state reads the
// control plane zero times: the edge forwards from its entry and the owner
// serves from its lease.
func TestCachedForwardServedFromTheLeaseNeedsNoLookup(t *testing.T) {
	f := leaseFleet(t, true, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "") // fill the cache
	f.prove("worker-a", "sb-1", 0)

	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || d.lookups != 0 || d.served["worker-a"] != 1 {
		t.Fatalf("got %d, lookups=%d served=%d; want 200, 0, 1", rr.Code, d.lookups, d.served["worker-a"])
	}
}

// A cache-routed forward needs a reading under 2 s: an older one takes the
// lookup path, which turns the stale entry down after a move.
func TestCachedForwardWithAnOldLeaseReadingLooksUp(t *testing.T) {
	f := leaseFleet(t, true, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "") // fill the cache
	f.prove("worker-a", "sb-1", 3*time.Second)          // proved, but 3 s ago
	f.move("sb-1", "worker-b")                          // worker-a keeps its stale row

	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Header().Get("X-Served-By") != "worker-b" || d.served["worker-a"] != 0 || d.notHere["worker-a"] != 1 {
		t.Fatalf("served by %q, worker-a served=%d not-here=%d; want worker-b, 0, 1",
			rr.Header().Get("X-Served-By"), d.served["worker-a"], d.notHere["worker-a"])
	}
}

// The owner's reading holds a newer epoch than a cache-routed forward (the
// sandbox moved away and back): the forward is turned down without a lookup,
// and the edge routes again from a fresh one.
func TestCachedForwardOlderThanTheLeaseIsTurnedDown(t *testing.T) {
	f := leaseFleet(t, true, "ingress-1", "worker-a", "worker-b")
	f.placeOn("sb-1", "worker-a", "")
	f.call("ingress-1", http.MethodGet, "sb-1", "", "") // fill the cache
	f.move("sb-1", "worker-b")
	f.move("sb-1", "worker-a")
	f.prove("worker-a", "sb-1", 0)

	before := f.snapshot()
	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	d := f.snapshot().since(before)
	if rr.Code != http.StatusOK || d.notHere["worker-a"] != 1 || d.served["worker-a"] != 1 || d.forwards["ingress-1"] != 2 {
		t.Fatalf("got %d, not-here=%d served=%d forwards=%d; want 200, 1, 1, 2", rr.Code, d.notHere["worker-a"], d.served["worker-a"], d.forwards["ingress-1"])
	}
	// One lookup: the edge's retry. The owner used its reading both times.
	if d.lookups != 1 {
		t.Fatalf("lookups = %d, want 1", d.lookups)
	}
}

// A fenced sandbox is never served from the lease: the lookup path answers
// with the fence's 503, as without the fast path.
func TestFencedSandboxIsNotServedFromTheLease(t *testing.T) {
	f := leaseFleet(t, false, "ingress-1", "worker-a")
	f.placeOn("sb-1", "worker-a", "")
	f.prove("worker-a", "sb-1", 0)
	f.nodes["worker-a"].svc.FenceOwnershipForTest("sb-1")

	rr := f.call("ingress-1", http.MethodGet, "sb-1", "", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rr.Code)
	}
	if d := f.nodes["worker-a"].served.Load(); d != 0 {
		t.Fatalf("worker-a served %d, want 0", d)
	}
}
