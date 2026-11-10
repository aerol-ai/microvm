package cluster

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// Regression test for placement and the active cluster version
// (plans/kubectl-style-cluster-ops.md §6.5): a member below it gets no
// placements; a cluster that never wrote one excludes nobody.

func TestSelectPlacementSkipsMembersBelowActiveVersion(t *testing.T) {
	c := &Cluster{nodeID: "self", apiURL: "http://self", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	snap := capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, CPUBudget: 4, MemoryBudgetMB: 4096}
	old := Member{NodeID: "old", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://old", FSMOpsVersion: 12, Capacity: snap}
	c.gossip.memberIndex.replace([]Member{old})
	req := capacity.Request{CPU: 1, MemoryMB: 128}
	// Never written: nobody is excluded (single-node and fresh clusters
	// behave as before).
	if target, err := c.SelectPlacement(req); err != nil || target.NodeID != "old" {
		t.Fatalf("before the first write = %+v %v", target, err)
	}
	applyDenyLogAt(t, c.fsm, 1, activeCmd(13, 0, "v1", 1))
	if _, err := c.SelectPlacement(req); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("a member below the active version got a placement: %v", err)
	}
	cur := old
	cur.NodeID, cur.APIURL, cur.FSMOpsVersion = "cur", "http://cur", 13
	unknown := old
	unknown.NodeID, unknown.APIURL, unknown.FSMOpsVersion = "unknown", "http://unknown", 0
	c.gossip.memberIndex.replace([]Member{old, cur})
	for i := 0; i < 20; i++ {
		target, err := c.SelectPlacement(req)
		if err != nil || target.NodeID != "cur" {
			t.Fatalf("placement = %+v %v, want only the current member", target, err)
		}
	}
	// fv 0 is "unknown", never obsolete.
	c.gossip.memberIndex.replace([]Member{unknown})
	if target, err := c.SelectPlacement(req); err != nil || target.NodeID != "unknown" {
		t.Fatalf("unknown fv = %+v %v", target, err)
	}
}
