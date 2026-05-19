package cluster

import (
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// TestVoterAutoJoinNoOpsWithoutCluster guards the nil-cluster path. Memberlist
// fires NotifyJoin for our own node during memberlist.Create, so the delegate
// must tolerate being called before the Cluster reference is fully set up — or
// not panic when raft is nil.
func TestVoterAutoJoinNoOpsWithoutCluster(t *testing.T) {
	d := &voterAutoJoinDelegate{c: nil}
	// Should not panic.
	d.NotifyJoin(nil)
	d.NotifyLeave(nil)
	d.NotifyUpdate(nil)
}

// TestHandleMemberJoinIgnoresSelfAndEmpty asserts the early-return guards on
// handleMemberJoin. We can call it on a Cluster with a nil raft handle as long
// as the early return fires first.
func TestHandleMemberJoinIgnoresSelfAndEmpty(t *testing.T) {
	c := &Cluster{nodeID: "self"}
	// Both calls must early-return before touching c.raft (which would panic).
	c.handleMemberJoin("")
	c.handleMemberJoin("self")
}

// TestVoterAutoJoinPromotesFollower exercises the end-to-end auto-promotion
// path without manually adding the voter. It's the same shape as the cluster
// integration test but lives here so the auto-join behavior has a dedicated
// regression target if someone removes the EventDelegate wiring.
func TestVoterAutoJoinPromotesFollower(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestCluster(t, "ldr", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	_, cleanupFollower := newTestCluster(t, "fol", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	waitForVoter(t, leader, "fol", 10*time.Second)
}

func TestVoterAutoJoinAddsNonvoterAfterCap(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}

	leader, cleanupLeader := newTestCluster(t, "ldr-cap", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	leader.cfg.ClusterMaxAutoVoters = 1

	_, cleanupFollower := newTestCluster(t, "nonvoter", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	waitForServerSuffrage(t, leader, "nonvoter", raft.Nonvoter, 10*time.Second)
}
