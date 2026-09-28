package cluster

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/memberlist"
)

func TestVoterAutoJoinAndDeadOwnerUnitBranches(t *testing.T) {
	c := &Cluster{nodeID: "self", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.handleMemberJoin("peer") // raft nil → return
	if c.peerForcedNonVoter("x") {
		t.Fatal("nil gossip should not force nonvoter")
	}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	if c.peerForcedNonVoter("missing") {
		t.Fatal("missing member")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "w", Role: config.NodeRoleWorker})
	if !c.peerForcedNonVoter("w") {
		t.Fatal("worker should force nonvoter")
	}
	if c.peerRaftAddr("missing") != "" {
		t.Fatal("missing raft addr")
	}
	c.gossip.memberIndex.upsert(Member{NodeID: "w", Role: config.NodeRoleWorker, RaftAddr: "127.0.0.1:7001"})
	if got := c.peerRaftAddr("w"); got != "127.0.0.1:7001" {
		t.Fatalf("peerRaftAddr=%q", got)
	}

	// voterCapReached when currentVoterCount fails (nil raft panics) — skip.
	c.cfg.ClusterMaxAutoVoters = 1
	// Without raft, avoid calling voterCapReached/currentVoterCount.

	d := &voterAutoJoinDelegate{c: c}
	d.NotifyUpdate(&memberlist.Node{Name: "x"})

	c.reconcileDeadOwners(context.Background()) // raft nil
	c.reconcileReservations(context.Background())
	if _, ok := c.selectRecreationTarget(Placement{}); ok {
		t.Fatal("nil spec")
	}
	if _, ok := c.selectRecreationTarget(Placement{Spec: &models.CreateSandboxRequest{ImageDistributionMode: models.ImageDistributionLocalOnly}}); ok {
		t.Fatal("local-only")
	}

}

func TestVoterAutoJoinAddrChangeAndAddErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-vaj", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-vaj", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	// Already configured voter with same addr → early return.
	leader.handleMemberJoin(follower.nodeID)

	// Force nonvoter demotion path when role is worker and addr differs.
	leader.gossip.memberIndex.upsert(Member{
		NodeID:   follower.nodeID,
		Alive:    true,
		Role:     config.NodeRoleWorker,
		RaftAddr: "127.0.0.1:1",
		APIURL:   follower.apiURL,
	})
	leader.handleMemberJoin(follower.nodeID)

	// addMemberAsVoter / Nonvoter error paths (bad address).
	leader.addMemberAsVoter("ghost-voter", "127.0.0.1:1")
	leader.addMemberAsNonvoter("ghost-non", "127.0.0.1:1")

	// Cap reached with unreadable config is true; with real raft count works.
	leader.cfg.ClusterMaxAutoVoters = 1
	if !leader.voterCapReached() {
		t.Fatal("voter cap should be reached with max=1 and existing voter")
	}
}

func TestVoterAutoJoinReAddVoterAndNonvoterPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	leader, cleanupLeader := newTestCluster(t, "ldr-vaj2", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-vaj2", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)

	leader.gossip.memberIndex.upsert(Member{
		NodeID: follower.nodeID, Alive: true, Role: config.NodeRoleServer,
		RaftAddr: "127.0.0.1:1", APIURL: follower.apiURL,
	})
	leader.handleMemberJoin(follower.nodeID)

	leader.cfg.ClusterMaxAutoVoters = 1
	leader.addMemberAsNonvoter(follower.nodeID, "127.0.0.1:2")
	leader.gossip.memberIndex.upsert(Member{
		NodeID: follower.nodeID, Alive: true, Role: config.NodeRoleServer,
		RaftAddr: "127.0.0.1:3", APIURL: follower.apiURL,
	})
	leader.handleMemberJoin(follower.nodeID)

	if srv, ok := leader.configuredServer(follower.nodeID); ok {
		leader.gossip.memberIndex.upsert(Member{
			NodeID: follower.nodeID, Alive: true, Role: config.NodeRoleWorker,
			RaftAddr: string(srv.Address), APIURL: follower.apiURL,
		})
		leader.handleMemberJoin(follower.nodeID)
	}
}
