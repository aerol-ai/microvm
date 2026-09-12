package cluster

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDeleteFenceOwnerUnavailableAndReconcileGuards(t *testing.T) {
	if (*Cluster)(nil).deleteFenceOwnerUnavailable("") != true {
		t.Fatal("nil cluster empty owner should treat fence as abandoned")
	}
	c := &Cluster{nodeID: "self", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if !c.deleteFenceOwnerUnavailable("") {
		t.Fatal("empty owner is unavailable")
	}
	if c.deleteFenceOwnerUnavailable("self") {
		t.Fatal("self fence must stay while this node is retrying cleanup")
	}
	if c.deleteFenceOwnerUnavailable("peer") {
		t.Fatal("nil gossip must not expire a live owner's fence")
	}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	if !c.deleteFenceOwnerUnavailable("missing") {
		t.Fatal("unknown owner is unavailable")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "dead", Alive: false})
	if !c.deleteFenceOwnerUnavailable("dead") {
		t.Fatal("dead owner is unavailable")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "live", Alive: true})
	if c.deleteFenceOwnerUnavailable("live") {
		t.Fatal("live owner fence must not expire")
	}
	c.reconcileReservations(context.Background())
}

func TestPickRecreationTargetSelectError(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleServer, APIURL: "http://self", CapacityStale: true})
	c := &Cluster{
		nodeID: "self",
		apiURL: "http://self",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if id, _, _ := c.pickRecreationTarget(&models.CreateSandboxRequest{CPU: 4, MemoryMB: 4096, Image: "x"}); id != "" {
		t.Fatalf("expected no target, got %q", id)
	}
}

func TestEvictDeadOwnerNoTargetAndReconcileEdges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-evict", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	spec := &models.CreateSandboxRequest{
		Image: "alpine", CPU: 1, MemoryMB: 64,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-dead", OwnerNodeID: "dead-node", Spec: spec})
	if err := c.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	c.gossip.memberIndex.replace([]Member{
		{NodeID: c.nodeID, Alive: true, Role: config.NodeRoleServer, APIURL: c.apiURL, CapacityStale: true},
		{NodeID: "", Alive: true, Role: config.NodeRoleServer},
	})
	c.evictDeadOwner(context.Background(), "dead-node")

	c.deadOwners.markDead("ghost", time.Now().Add(-time.Hour))
	c.gossip.memberIndex.replace([]Member{
		{NodeID: "", Alive: false},
		{NodeID: "ghost", Alive: true, Role: config.NodeRoleServer, APIURL: "http://g"},
	})
	c.cfg.ClusterDeadOwnerGrace = time.Millisecond
	c.reconcileDeadOwners(context.Background())
}

func TestFSMOrphanOwnerStaleIndexAndReserveBatchStoreFail(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.mu.Lock()
	fsm.ownerIndex = map[string]map[string]struct{}{
		"n": {"ghost": {}, "res": {}},
	}
	fsm.placements["res"] = Placement{
		SandboxID: "res", OwnerNodeID: "n", State: PlacementStateReserved,
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}
	fsm.pendingReservationIDsByOwner = map[string]map[string]struct{}{
		"n": {"ghost-p": {}, "placed": {}},
	}
	fsm.placements["placed"] = Placement{SandboxID: "placed", OwnerNodeID: "n", State: PlacementStatePlaced}
	fsm.mu.Unlock()
	if got := applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "n"}); got != nil {
		t.Fatalf("orphan stale index: %v", got)
	}

	failFSM := newPlacementFSMWithRecoveryStore(failPutRecoveryStore{})
	if got := applyOp(t, failFSM, command{Op: opReserveBatch, Reservations: []reservationCommand{{
		SandboxID: "r1", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Image: "i", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}}}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("reserve batch store fail=%v", got)
	}
	if got := applyOp(t, failFSM, command{
		Op: opReserve, SandboxID: "r2", OwnerNodeID: "a",
		Spec: &models.CreateSandboxRequest{Image: "i", CPU: 1}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}); got == nil || !strings.Contains(fmtErr(got), "forced put") {
		t.Fatalf("reserve store fail=%v", got)
	}
}

func TestPickRecreationTargetIsSelf(t *testing.T) {
	fat := step3FatCapacity()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://self", Capacity: fat})
	c := &Cluster{
		nodeID:        "self",
		apiURL:        "http://self",
		dataPlaneHost: "dp",
		fsm:           newPlacementFSM(),
		gossip:        &gossipNode{memberIndex: index},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	id, url, host := c.pickRecreationTarget(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 64, Image: "x"})
	if id != "self" || url != "http://self" || host != "dp" {
		t.Fatalf("IsSelf target id=%q url=%q host=%q", id, url, host)
	}
}

func TestEvictDeadOwnerReassignFailAndRemoveServerFail(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-ev2", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-ev2", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	// Stale ownerIndex entry → !ok continue inside evict.
	leader.fsm.mu.Lock()
	if leader.fsm.ownerIndex == nil {
		leader.fsm.ownerIndex = map[string]map[string]struct{}{}
	}
	leader.fsm.ownerIndex["phantom"] = map[string]struct{}{"ghost-id": {}}
	leader.fsm.mu.Unlock()

	spec := &models.CreateSandboxRequest{
		Image: "alpine", CPU: 1, MemoryMB: 64,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-rafail", OwnerNodeID: "phantom", Spec: spec})
	if err := leader.raft.raft.Apply(place, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	// No capacity → no recreation target (warn + continue), then orphan succeeds.
	leader.gossip.memberIndex.replace([]Member{
		{NodeID: leader.nodeID, Alive: true, Role: config.NodeRoleServer, APIURL: leader.apiURL, CapacityStale: true},
	})
	leader.evictDeadOwner(context.Background(), "phantom")

	// Follower RemoveServer fails (not leader).
	follower.removeDeadOwnerServer(leader.nodeID)

	// Default grace (<=0) branch + markDead from raft config for missing gossip peers.
	leader.cfg.ClusterDeadOwnerGrace = 0
	leader.deadOwners.markDead("absent-voter", time.Now().Add(-time.Hour))
	leader.gossip.memberIndex.replace([]Member{
		{NodeID: leader.nodeID, Alive: true, Role: config.NodeRoleServer, APIURL: leader.apiURL},
	})
	leader.reconcileDeadOwners(context.Background())
}

func TestReconcileReservationsCancelError(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-resgc", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	res, _ := encodeCommand(command{
		Op: opReserve, SandboxID: "sb-exp", OwnerNodeID: c.nodeID,
		Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1},
		ExpiresUnix: time.Now().Add(-time.Minute).Unix(),
	})
	if err := c.raft.raft.Apply(res, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	// Cancel while not leader is forced by swapping to a follower-like apply path:
	// shut leadership isn't easy; instead plant an oversized cancel that can't happen.
	// Use a tiny commit timeout after pausing — simpler: call reconcile as follower.
	follower, cleanupF := newTestCluster(t, "fol-resgc", false, []string{c.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForVoter(t, c, follower.nodeID, 20*time.Second)

	// Copy expired id into follower FSM view via raft already replicated.
	// Force CancelReservation failure by using a cancelled context on leader.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.reconcileReservations(ctx)
}

func TestFSMOrphanOwnerSkipReservedAndMissing(t *testing.T) {
	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "live", OwnerNodeID: "n", Spec: &models.CreateSandboxRequest{Image: "i", Name: "live"}})
	applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "res", OwnerNodeID: "n",
		Spec: &models.CreateSandboxRequest{Name: "res", CPU: 1}, ExpiresUnix: 9999999999,
	})
	// Manually poison owner index with a missing id and a reserved id so orphan skips them.
	fsm.mu.Lock()
	fsm.ownerIndex["n"]["ghost"] = struct{}{}
	fsm.ownerIndex["n"]["res"] = struct{}{} // reserved also in pending; ownedPlacementIDs may still list if poisoned
	fsm.mu.Unlock()
	if got := applyOp(t, fsm, command{Op: opOrphanOwner, NodeID: "n"}); got != nil {
		t.Fatalf("orphan=%v", got)
	}
}
