package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDeadOwnerTrackerMarkAndClear verifies the tiny piece of state the
// reconciler relies on: marks are sticky (re-marking returns the original
// timestamp) and clear removes them.
func TestDeadOwnerTrackerMarkAndClear(t *testing.T) {
	tr := newDeadOwnerTracker()
	t0 := time.Now()
	got := tr.markDead("a", t0)
	if !got.Equal(t0) {
		t.Fatalf("first markDead returned %v, want %v", got, t0)
	}
	t1 := t0.Add(2 * time.Second)
	got = tr.markDead("a", t1)
	if !got.Equal(t0) {
		t.Fatalf("second markDead should preserve original ts; got %v, want %v", got, t0)
	}
	tr.clear("a")
	got = tr.markDead("a", t1)
	if !got.Equal(t1) {
		t.Fatalf("after clear, markDead should accept new ts; got %v, want %v", got, t1)
	}
}

// TestEvictDeadOwnerOrphansAndRemoves drives the eviction path on a real
// single-node cluster: place a sandbox owned by a fictional dead node, then
// invoke evictDeadOwner directly and verify (a) the placement gets orphaned
// (OwnerNodeID="") and (b) the dead node — if it had been a voter — would be
// removed from raft. We can't test the RemoveServer side-effect on a phantom
// node (it never joined), but we cover the orphan path which is the
// safety-critical half.
func TestEvictDeadOwnerOrphansAndRemoves(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Inject a placement owned by a phantom dead node by writing the FSM
	// command directly. Bypassing RecordPlacement avoids tying this test to
	// the leader's identity.
	cmd := command{Op: opPlace, SandboxID: "sb-orphan-me", OwnerNodeID: "dead-node", OwnerAPIURL: "http://gone"}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	// Sanity: placement starts with the dead owner.
	if owner, err := c.OwnerOf("sb-orphan-me"); err != nil || owner.NodeID != "dead-node" {
		t.Fatalf("pre-evict OwnerOf = %+v err=%v, want NodeID=dead-node nil err", owner, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.evictDeadOwner(ctx, "dead-node")

	// After eviction: OwnerOf should report ErrOrphaned.
	_, err = c.OwnerOf("sb-orphan-me")
	if err != ErrOrphaned {
		t.Fatalf("post-evict OwnerOf err = %v, want ErrOrphaned", err)
	}
	p, ok := c.PlacementOf("sb-orphan-me")
	if !ok || !p.IsOrphaned() || p.OrphanedOwnerNodeID != "dead-node" || p.OrphanedUnix == 0 {
		t.Fatalf("orphan metadata = %+v ok=%v, want previous owner dead-node", p, ok)
	}
}

// TestReconcileDeadOwnersRespectsGrace asserts that a node within the grace
// window does NOT get evicted, and a node past it does. The grace is taken
// from cfg.ClusterDeadOwnerGrace; we set it to a small value via a dedicated
// builder to keep the test fast.
func TestReconcileDeadOwnersRespectsGrace(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr", true, nil, func(cfg *config.Config) {
		cfg.ClusterDeadOwnerGrace = 200 * time.Millisecond
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Place a sandbox owned by a phantom node, then mark that node dead.
	cmd := command{Op: opPlace, SandboxID: "sb-grace", OwnerNodeID: "phantom"}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}
	c.deadOwners.markDead("phantom", time.Now())

	// Immediately reconcile — placement must still be intact (grace not yet up).
	c.reconcileDeadOwners(context.Background())
	if owner, err := c.OwnerOf("sb-grace"); err != nil || owner.NodeID != "phantom" {
		t.Fatalf("during grace, OwnerOf = %+v err=%v, want NodeID=phantom", owner, err)
	}

	// Wait past the grace window, reconcile, expect orphan.
	time.Sleep(300 * time.Millisecond)
	c.reconcileDeadOwners(context.Background())
	if _, err := c.OwnerOf("sb-grace"); err != ErrOrphaned {
		t.Fatalf("after grace, OwnerOf err = %v, want ErrOrphaned", err)
	}
}

// TestEvictDeadOwnerReassignsWhenSpecExists drives the spec-replication
// codepath: a placement carrying a Spec gets reassigned to a live node (the
// only candidate is self/leader) instead of being marked orphan. This is the
// behaviour change behind auto-recreation — the owner watcher on the new
// owner picks up from there.
//
// Skipped under the current product policy (clusterRecreateOnFailoverEnabled
// is false): evictDeadOwner always orphans, regardless of spec. The test is
// kept so the reassign path is still validated whenever the gate flips back
// on.
func TestEvictDeadOwnerReassignsWhenSpecExists(t *testing.T) {
	if !clusterRecreateOnFailoverEnabled {
		t.Skip("failover recreate is gated off; flip clusterRecreateOnFailoverEnabled to exercise")
	}
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Placement with a non-nil spec belongs to a phantom dead node.
	cmd := command{
		Op: opPlace, SandboxID: "sb-reassign", OwnerNodeID: "dead-node", OwnerAPIURL: "http://gone",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 0.5, MemoryMB: 256},
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.evictDeadOwner(ctx, "dead-node")

	owner, err := c.OwnerOf("sb-reassign")
	if err != nil {
		t.Fatalf("post-evict OwnerOf err = %v, want nil (reassigned to leader)", err)
	}
	if owner.NodeID != "leader" || !owner.IsSelf {
		t.Fatalf("expected reassignment to self (leader); got %+v", owner)
	}
}

// newTestClusterWithCfg is newTestCluster but with a hook to mutate the
// generated config before it's handed to New. Used by tests that need to
// shorten time-based knobs.
func newTestClusterWithCfg(t *testing.T, nodeID string, bootstrap bool, gossipPeers []string, mutate func(*config.Config)) (*Cluster, func()) {
	t.Helper()
	c, cleanup := newTestCluster(t, nodeID, bootstrap, gossipPeers)
	if mutate != nil {
		mutate(&c.cfg)
	}
	return c, cleanup
}
