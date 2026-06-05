package cluster

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestCanServeIngressRole(t *testing.T) {
	for _, tc := range []struct {
		role string
		want bool
	}{
		{"", true},
		{"mixed", true},
		{"ingress", true},
		{"ingress,worker", true},
		{"worker", false},
		{"server,worker", false},
		{"server", false},
		{"controller", false},
	} {
		if got := CanServeIngressRole(tc.role); got != tc.want {
			t.Fatalf("role %q CanServeIngressRole = %v, want %v", tc.role, got, tc.want)
		}
	}
}

func TestSelectPlacementEdgeCases(t *testing.T) {
	c := &Cluster{
		nodeID: "self-node",
		apiURL: "http://self-node",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: newGossipMemberIndex()},
	}

	// Setup cluster members with various rejected states
	members := []Member{
		{NodeID: "dead-node", Alive: false, Role: config.NodeRoleWorker},
		{NodeID: "bad-role", Alive: true, Role: config.NodeRoleServer},
		{NodeID: "no-api-url", Alive: true, Role: config.NodeRoleWorker, APIURL: ""},
		{NodeID: "stale-cap", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://stale", CapacityStale: true},
	}
	c.gossip.memberIndex.replace(members)

	// All should be rejected, returns ErrNoPlacementTarget
	req := capacity.Request{CPU: 1, MemoryMB: 128}
	_, err := c.SelectPlacement(req)
	if !errors.Is(err, ErrNoPlacementTarget) {
		t.Errorf("expected ErrNoPlacementTarget, got %v", err)
	}

	// Add a drained node
	drainedMember := Member{
		NodeID: "drained-node", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://drained",
		Capacity: capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, CPUBudget: 4, MemoryBudgetMB: 4096},
	}
	members = append(members, drainedMember)
	c.gossip.memberIndex.replace(members)

	// Mark as drained
	applyOp(t, c.fsm, command{Op: opSetNodeDrainState, NodeID: "drained-node", Drained: true})
	_, err = c.SelectPlacement(req)
	if !errors.Is(err, ErrNoPlacementTarget) {
		t.Errorf("expected ErrNoPlacementTarget for drained node, got %v", err)
	}

	// Add a valid node that fits
	validMember := Member{
		NodeID: "valid-node", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://valid",
		Capacity: capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, CPUBudget: 4, MemoryBudgetMB: 4096},
	}
	members = append(members, validMember)
	c.gossip.memberIndex.replace(members)

	target, err := c.SelectPlacement(req)
	if err != nil {
		t.Errorf("expected successful placement, got %v", err)
	}
	if target.NodeID != "valid-node" {
		t.Errorf("expected valid-node, got %v", target.NodeID)
	}

	// Test fallback to self node logic (if it fits)
	// Add self node to members, but no api url is allowed for self node
	selfMember := Member{
		NodeID: "self-node", Alive: true, Role: config.NodeRoleWorker, APIURL: "",
		Capacity: capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, CPUBudget: 4, MemoryBudgetMB: 4096},
	}
	c.gossip.memberIndex.replace([]Member{selfMember})

	target, err = c.SelectPlacement(req)
	if err != nil {
		t.Errorf("expected successful placement on self, got %v", err)
	}
	if target.NodeID != "self-node" {
		t.Errorf("expected self-node, got %v", target.NodeID)
	}
	if !target.IsSelf {
		t.Errorf("expected IsSelf=true")
	}

	// Test LargeClusterTopologyError
	var manyMembers []Member
	for i := 0; i < 500; i++ {
		manyMembers = append(manyMembers, Member{NodeID: "m" + string(rune('a'+(i%26))), Role: config.NodeRoleMixed, Alive: true})
	}
	c.gossip.memberIndex.replace(manyMembers)
	_, err = c.SelectPlacement(req)
	if err == nil {
		t.Errorf("expected topology error, got nil")
	}
}
