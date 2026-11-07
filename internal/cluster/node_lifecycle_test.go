package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/raft"
)

// Regression tests for the any-role node delete and the node read
// (node_lifecycle.go), next to the cluster-correctness rules they pin:
// deny before orphaning, idempotent retries, the rolling-upgrade gate, and
// the old servers-only RemoveMember answering exactly as before.

func TestDeleteNodeLeaderPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "del-ldr", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	stopGossipRefresh(t, leader)
	ctx := context.Background()
	index := leader.gossip.currentMemberIndex()

	if _, err := leader.DeleteNode(ctx, " ", false); err == nil {
		t.Fatal("empty node id accepted")
	}
	if _, err := leader.DeleteNode(ctx, "nobody", false); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("unknown node = %v", err)
	}

	// A live worker that owns a sandbox.
	index.upsert(Member{NodeID: "wkr-1", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-1"})
	index.upsert(Member{NodeID: "wkr-2", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-2"})
	if err := leader.applyCommand(ctx, command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerAPIURL: "http://wkr-1", IncarnationID: "inc-1"}); err != nil {
		t.Fatal(err)
	}

	// The old route is unchanged: a worker is not a Raft member, so 404.
	if err := leader.RemoveMember(ctx, "wkr-1", true); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("RemoveMember(worker) = %v, want ErrUnknownMember", err)
	}

	// Rolling upgrade: an older server blocks the deny, and the gate runs
	// before anything else changes.
	if err := leader.raft.raft.AddNonvoter("old-srv", raft.ServerAddress("127.0.0.1:1"), 0, time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	index.upsert(Member{NodeID: "old-srv", Alive: false, Role: config.NodeRoleServer, FSMOpsVersion: nodeDenyFSMOpsVersion - 1})
	if _, err := leader.DeleteNode(ctx, "wkr-1", true); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("delete with an old server = %v, want ErrClusterVersion", err)
	}
	if leader.IsNodeDrained("wkr-1") || leader.IsNodeDenied("wkr-1") {
		t.Fatal("a refused delete changed state")
	}

	// A Raft server goes through RemoveMember, gate or not.
	res, err := leader.DeleteNode(ctx, "old-srv", false)
	if err != nil || !res.RaftRemoved || res.Denied || res.Role != config.NodeRoleServer {
		t.Fatalf("delete server = %+v %v", res, err)
	}
	if _, ok := leader.configuredServer("old-srv"); ok {
		t.Fatal("the server is still in the Raft configuration")
	}
	if _, err := leader.DeleteNode(ctx, "del-ldr", true); !errors.Is(err, ErrLastVoter) {
		t.Fatalf("delete the last voter = %v", err)
	}

	// A live worker that still owns sandboxes needs force.
	if _, err := leader.DeleteNode(ctx, "wkr-1", false); !errors.Is(err, ErrNodeStillServing) {
		t.Fatalf("live worker without force = %v", err)
	}
	res, err = leader.DeleteNode(ctx, "wkr-1", true)
	if err != nil || !res.Denied || res.AlreadyDeleted || res.Orphaned != 1 || res.Role != config.NodeRoleWorker {
		t.Fatalf("delete worker = %+v %v", res, err)
	}
	if !leader.IsNodeDenied("wkr-1") || !leader.IsNodeDrained("wkr-1") {
		t.Fatal("worker not denied and drained")
	}
	if p, ok := leader.PlacementOf("sb-1"); !ok || !p.IsOrphaned() || p.OrphanedOwnerNodeID != "wkr-1" {
		t.Fatalf("placement = %+v %v, want orphaned from wkr-1", p, ok)
	}
	// Gone from the view, and it cannot come back through an update.
	index.upsert(Member{NodeID: "wkr-1", Alive: true, Role: config.NodeRoleWorker})
	for _, m := range leader.Members() {
		if m.NodeID == "wkr-1" {
			t.Fatal("a deleted worker is still listed")
		}
	}
	if !leader.refuseDeniedPeer("wkr-1") || leader.refuseDeniedPeer("wkr-2") {
		t.Fatal("refuseDeniedPeer disagrees with the deny set")
	}
	if !IsDeniedPeer(leader, "wkr-1") || IsDeniedPeer(leader, "wkr-2") || IsDeniedPeer(NewNoop("a", "http://a", ""), "wkr-1") {
		t.Fatal("IsDeniedPeer disagrees with the deny set")
	}

	// A retry finishes nothing new and says so.
	res, err = leader.DeleteNode(ctx, "wkr-1", false)
	if err != nil || !res.AlreadyDeleted || res.Orphaned != 0 {
		t.Fatalf("repeat delete = %+v %v", res, err)
	}

	// A node gone from gossip but still drained is known, and an empty live
	// worker needs no force.
	if err := leader.SetNodeDrainState(ctx, "wkr-gone", true); err != nil {
		t.Fatal(err)
	}
	if res, err := leader.DeleteNode(ctx, "wkr-gone", false); err != nil || !res.Denied || res.Role != "" {
		t.Fatalf("delete a drained, departed node = %+v %v", res, err)
	}
	// The delete above refreshed the view from memberlist, which knows only
	// this node; put the live worker back.
	index.upsert(Member{NodeID: "wkr-2", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-2"})
	if res, err := leader.DeleteNode(ctx, "wkr-2", false); err != nil || !res.Denied {
		t.Fatalf("delete an empty live worker = %+v %v", res, err)
	}
}

// A deleted server gets a deny record too (Phase 2b closes the 2a gap): its
// key is a tombstone and gossip refuses its ID, so voter auto-join can't
// add it back. A refused delete writes nothing, a retry reports the record
// it finds, and the old members route still writes none.
func TestDeleteServerWritesADenyRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "dsrv-ldr", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	stopGossipRefresh(t, leader)
	ctx := context.Background()
	index := leader.gossip.currentMemberIndex()
	for i, id := range []string{"dsrv-2", "dsrv-3"} {
		addr := raft.ServerAddress(fmt.Sprintf("127.0.0.1:%d", i+1))
		if err := leader.raft.raft.AddNonvoter(raft.ServerID(id), addr, 0, time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	index.upsert(Member{NodeID: "dsrv-2", Alive: true, Role: config.NodeRoleServer, FSMOpsVersion: fsmOpsVersion})
	index.upsert(Member{NodeID: "dsrv-3", Alive: false, Role: config.NodeRoleServer, FSMOpsVersion: fsmOpsVersion})

	// Refusals come before any write.
	if _, err := leader.DeleteNode(ctx, "dsrv-ldr", true); !errors.Is(err, ErrLastVoter) || leader.IsNodeDenied("dsrv-ldr") {
		t.Fatalf("delete the last voter = %v, denied %t", err, leader.IsNodeDenied("dsrv-ldr"))
	}
	if _, err := leader.DeleteNode(ctx, "dsrv-2", false); !errors.Is(err, ErrMemberStillAlive) || leader.IsNodeDenied("dsrv-2") {
		t.Fatalf("delete a live server without force = %v, denied %t", err, leader.IsNodeDenied("dsrv-2"))
	}

	res, err := leader.DeleteNode(ctx, "dsrv-2", true)
	if err != nil || !res.RaftRemoved || !res.Denied || res.AlreadyDeleted {
		t.Fatalf("delete a server = %+v %v", res, err)
	}
	if !leader.IsNodeDenied("dsrv-2") {
		t.Fatal("the deleted server is not denied")
	}
	if _, ok := leader.configuredServer("dsrv-2"); ok {
		t.Fatal("the deleted server is still in the Raft configuration")
	}
	// Gossip refuses it, so it can't come back as a member (and voter
	// auto-join never sees it).
	index.upsert(Member{NodeID: "dsrv-2", Alive: true, Role: config.NodeRoleServer})
	for _, m := range leader.Members() {
		if m.NodeID == "dsrv-2" {
			t.Fatal("a deleted server is still listed")
		}
	}
	// A retry: no longer a Raft server, it finds the record and says so.
	if res, err := leader.DeleteNode(ctx, "dsrv-2", false); err != nil || !res.Denied || !res.AlreadyDeleted || res.RaftRemoved {
		t.Fatalf("repeat delete = %+v %v", res, err)
	}

	// The old route is unchanged: out of Raft, no record.
	if err := leader.RemoveMember(ctx, "dsrv-3", true); err != nil || leader.IsNodeDenied("dsrv-3") {
		t.Fatalf("RemoveMember = %v, denied %t", err, leader.IsNodeDenied("dsrv-3"))
	}
}

// A follower forwards one hop to the leader and restores each verdict.
func TestDeleteNodeFollowerForwards(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two raft nodes")
	}
	leader, cleanupLeader := newTestCluster(t, "del-fwd-ldr", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	follower, cleanupFollower := newTestCluster(t, "del-fwd-fol", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForLeader(t, follower, 20*time.Second)
	stopGossipRefresh(t, follower)

	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || !strings.HasPrefix(r.URL.Path, PublicNodesPath) {
			http.NotFound(w, r)
			return
		}
		switch strings.TrimPrefix(r.URL.Path, PublicNodesPath) {
		case "wkr-ok":
			_ = json.NewEncoder(w).Encode(NodeDeleteResult{NodeID: "wkr-ok", Denied: true, Orphaned: 2})
		case "wkr-missing":
			http.Error(w, `{"error":"`+ErrUnknownNode.Error()+`"}`, http.StatusNotFound)
		case "wkr-busy":
			http.Error(w, `{"error":"`+ErrNodeStillServing.Error()+`: wkr-busy owns 3"}`, http.StatusConflict)
		case "wkr-moving":
			http.Error(w, "cluster: not leader", http.StatusServiceUnavailable)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer internal.Close()
	follower.setInternalClient(internal.Client())
	follower.gossip.memberIndex.upsert(Member{NodeID: leader.nodeID, InternalURL: internal.URL, APIURL: leader.apiURL, Alive: true, Role: config.NodeRoleServer})

	ctx := context.Background()
	if res, err := follower.DeleteNode(ctx, "wkr-ok", true); err != nil || res.Orphaned != 2 {
		t.Fatalf("forwarded delete = %+v %v", res, err)
	}
	for id, want := range map[string]error{"wkr-missing": ErrUnknownNode, "wkr-busy": ErrNodeStillServing, "wkr-moving": ErrNotLeader} {
		if _, err := follower.DeleteNode(ctx, id, false); !errors.Is(err, want) {
			t.Fatalf("%s = %v, want %v", id, err, want)
		}
	}
	var se statusError
	if _, err := follower.DeleteNode(ctx, "wkr-other", false); !errors.As(err, &se) || se.status != http.StatusInternalServerError {
		t.Fatalf("unmapped refusal = %v", err)
	}
	follower.gossip.memberIndex.upsert(Member{NodeID: leader.nodeID, APIURL: leader.apiURL, Alive: true, Role: config.NodeRoleServer})
	if _, err := follower.DeleteNode(ctx, "wkr-ok", false); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("leader without an internal URL = %v", err)
	}
	follower.setInternalClient(nil)
	if _, err := follower.DeleteNode(ctx, "wkr-ok", false); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("no internal client = %v", err)
	}
}

func TestDeleteNodeWithoutLeaderOrRaft(t *testing.T) {
	if _, err := (&Cluster{}).DeleteNode(context.Background(), "wkr-1", false); err == nil {
		t.Fatal("a cluster without raft deleted a node")
	}
	if testing.Short() {
		return
	}
	lone, cleanup := newTestCluster(t, "del-lone", false, nil)
	defer cleanup()
	if _, err := lone.DeleteNode(context.Background(), "wkr-1", false); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no leader = %v", err)
	}
}

func TestNodeLifecycleErrorRestoresSentinels(t *testing.T) {
	for _, tc := range []struct {
		status  int
		message string
		want    error
	}{
		{http.StatusNotFound, `{"error":"cluster: unknown node"}`, ErrUnknownNode},
		{http.StatusNotFound, "cluster: unknown raft member", ErrUnknownMember},
		{http.StatusConflict, ErrMemberStillAlive.Error(), ErrMemberStillAlive},
		{http.StatusConflict, ErrLastVoter.Error(), ErrLastVoter},
		{http.StatusConflict, ErrClusterVersion.Error() + ": server s1", ErrClusterVersion},
		{http.StatusServiceUnavailable, ErrNotCaughtUp.Error(), ErrNotCaughtUp},
		{http.StatusServiceUnavailable, "anything", ErrNotLeader},
	} {
		if got := nodeLifecycleError(tc.status, tc.message); !errors.Is(got, tc.want) {
			t.Fatalf("%d %q = %v, want %v", tc.status, tc.message, got, tc.want)
		}
	}
	if got := agentNodeError(errors.New("dial")); got.Error() != "dial" {
		t.Fatalf("non-status error changed: %v", got)
	}
	if got := agentNodeError(statusError{status: http.StatusNotFound, message: ErrUnknownNode.Error()}); !errors.Is(got, ErrUnknownNode) {
		t.Fatalf("agent 404 = %v", got)
	}
}

func nodeDetailCluster(t *testing.T, members ...Member) *Cluster {
	t.Helper()
	index := newGossipMemberIndex()
	index.replace(members)
	return &Cluster{nodeID: "srv", apiURL: "http://srv", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: index}}
}

func TestNodeDetailCounts(t *testing.T) {
	heartbeat := recreateCandidate("wkr-1", config.NodeRoleWorker, 8)
	heartbeat.Capacity.SandboxesActive, heartbeat.Capacity.ParkedSlots = 5, 2
	heartbeat.Capacity.Labels = map[string]string{"zone": "az-1", "gpu": "a10"}
	stale := recreateCandidate("wkr-2", config.NodeRoleWorker, 8)
	stale.CapacityStale = true
	c := nodeDetailCluster(t, heartbeat, stale)
	for i, id := range []string{"sb-c", "sb-a", "sb-b"} {
		applyOp(t, c.fsm, command{Op: opPlace, SandboxID: id, OwnerNodeID: "wkr-1", IncarnationID: "inc-" + string(rune('0'+i))})
	}
	applyOp(t, c.fsm, command{Op: opPlace, SandboxID: "sb-z", OwnerNodeID: "wkr-2", IncarnationID: "inc-z"})
	c.fsm.drainedNodes["wkr-1"] = true
	ctx := context.Background()

	d, err := c.NodeDetail(ctx, "wkr-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if d.SandboxesOwned != 3 || d.SandboxesRunning != 3 || !d.RunningKnown || !d.Drained || d.Zone != "az-1" || d.Labels["gpu"] != "a10" {
		t.Fatalf("detail = %+v", d)
	}
	if strings.Join(d.SandboxIDs, ",") != "sb-a,sb-b" {
		t.Fatalf("sandbox ids = %v, want the first two in id order", d.SandboxIDs)
	}
	// No fresh heartbeat: running is unknown and falls back to owned.
	if d, _ := c.NodeDetail(ctx, "wkr-2", 0); d.RunningKnown || d.SandboxesRunning != 1 || d.SandboxIDs != nil {
		t.Fatalf("stale detail = %+v", d)
	}
	if _, err := c.NodeDetail(ctx, "nobody", 0); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("unknown = %v", err)
	}
	if _, err := c.NodeDetail(ctx, "", 0); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("empty = %v", err)
	}
	// A deleted node still in gossip reads as gone, and says why.
	applyOp(t, c.fsm, command{Op: opDenyNode, StampUnixNano: 1, NodeDeny: &NodeDenyRecord{NodeID: "wkr-2", Role: config.NodeRoleWorker}})
	if _, err := c.NodeDetail(ctx, "wkr-2", 0); !errors.Is(err, ErrNodeDeleted) || !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("deleted = %v, want ErrNodeDeleted (an ErrUnknownNode)", err)
	}
	// Parked slots never push running below zero, and owning nothing is 0.
	parked := recreateCandidate("wkr-3", config.NodeRoleWorker, 8)
	parked.Capacity.ParkedSlots = 4
	c.gossip.memberIndex.upsert(parked)
	if d, _ := c.NodeDetail(ctx, "wkr-3", maxNodeDetailSandboxIDs+5); d.SandboxesRunning != 0 || d.SandboxesOwned != 0 {
		t.Fatalf("parked detail = %+v", d)
	}
	c.catchingUp.Store(true)
	if _, err := c.NodeDetail(ctx, "wkr-1", 0); !errors.Is(err, ErrNotCaughtUp) {
		t.Fatalf("catching up = %v", err)
	}
	if n := c.fsm.ownedCount("nobody"); n != 0 {
		t.Fatalf("ownedCount(nobody) = %d", n)
	}
}

// A denied node gets no placements: not from SelectPlacement, not from a
// failover recreate, and not through a router's stale reservation.
func TestDeniedNodeGetsNoPlacements(t *testing.T) {
	c := nodeDetailCluster(t,
		recreateCandidate("wkr-gone", config.NodeRoleWorker, 120),
		recreateCandidate("wkr-ok", config.NodeRoleWorker, 8),
	)
	applyOp(t, c.fsm, denyCmd("wkr-gone", 1))
	before := expvarMapValue(denyHits, denyHitPlacement)
	for range 20 {
		target, candidates, err := c.SelectPlacementWithCandidates(capacity.Request{CPU: 1, MemoryMB: 256})
		if err != nil || target.NodeID != "wkr-ok" || len(candidates) != 1 {
			t.Fatalf("SelectPlacement = %+v %v %v", target, candidates, err)
		}
	}
	if expvarMapValue(denyHits, denyHitPlacement) == before {
		t.Fatal("placement refusals were not counted")
	}
	if target, ok := c.selectRecreationTarget(Placement{Spec: failoverRecreateSpec()}, "srv"); !ok || target.NodeID != "wkr-ok" {
		t.Fatalf("recreate target = %+v %v", target, ok)
	}
	err := c.admitReservationCommand(command{Op: opReserve, SandboxID: "sb-new", OwnerNodeID: "wkr-gone", IncarnationID: "inc-new", Spec: failoverRecreateSpec()})
	if !errors.Is(err, ErrNoPlacementTarget) || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("reservation onto a deleted node = %v", err)
	}
	if err := c.admitReservationCommand(command{Op: opReserve, SandboxID: "sb-ok", OwnerNodeID: "wkr-ok", IncarnationID: "inc-ok", Spec: failoverRecreateSpec()}); err != nil {
		t.Fatalf("reservation onto a live node = %v", err)
	}
}

// The backstop: a denied node that still owns placements (its delete failed
// after the deny landed, and nobody retried) is evicted by the dead-owner
// loop like any dead owner.
func TestDeadOwnerLoopEvictsDeniedNodeStillOwningPlacements(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "deny-backstop", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	if err := leader.applyCommand(ctx, command{Op: opPlace, SandboxID: "sb-left", OwnerNodeID: "wkr-half", OwnerAPIURL: "http://wkr-half", IncarnationID: "inc-left"}); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.writeNodeDeny(ctx, "wkr-half", config.NodeRoleWorker); err != nil {
		t.Fatal(err)
	}
	leader.cfg.ClusterDeadOwnerGrace = time.Millisecond
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		leader.reconcileDeadOwners(ctx)
		if p, ok := leader.PlacementOf("sb-left"); ok && p.IsOrphaned() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p, _ := leader.PlacementOf("sb-left")
	t.Fatalf("placement of a denied node = %+v, want orphaned", p)
}
