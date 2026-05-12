package cluster

import (
	"math"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestNodeFitsRespectsBudget asserts that a peer whose post-reservation
// budget would be exceeded is rejected by nodeFits.
func TestNodeFitsRespectsBudget(t *testing.T) {
	tight := Member{
		NodeID: "tight",
		APIURL: "http://t",
		Alive:  true,
		Capacity: capacity.Snapshot{
			HostCPUCores:      4,
			HostMemoryTotalMB: 8000,
			CPUBudget:         4,
			MemoryBudgetMB:    8000,
			ReservedCPU:       3.5,
			ReservedMemoryMB:  7800,
		},
	}
	if nodeFits(tight, capacity.Request{CPU: 1, MemoryMB: 1024}) {
		t.Fatal("tight node should not fit a 1-core/1G request")
	}
	if !nodeFits(tight, capacity.Request{CPU: 0.1, MemoryMB: 100}) {
		t.Fatal("tight node should still fit a small request that fits in remaining budget")
	}
}

// TestNodeFitsUnknownCapacity asserts that a peer with no advertised capacity
// snapshot is treated as candidate (better to forward and be rejected by the
// remote admitter than to skip a viable node).
func TestNodeFitsUnknownCapacity(t *testing.T) {
	unknown := Member{NodeID: "u", APIURL: "http://u", Alive: true}
	if !nodeFits(unknown, capacity.Request{CPU: 1, MemoryMB: 1024}) {
		t.Fatal("unknown-capacity node should be treated as candidate")
	}
}

// TestHeadroomScorePrefersEmptier checks the scoring monotonicity that
// power-of-two-choices relies on.
func TestHeadroomScorePrefersEmptier(t *testing.T) {
	full := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 4, HostMemoryTotalMB: 8000,
		CPUBudget: 4, MemoryBudgetMB: 8000,
		ReservedCPU: 3.0, ReservedMemoryMB: 6000,
	}}
	empty := Member{Capacity: capacity.Snapshot{
		HostCPUCores: 4, HostMemoryTotalMB: 8000,
		CPUBudget: 4, MemoryBudgetMB: 8000,
		ReservedCPU: 0.5, ReservedMemoryMB: 1000,
	}}
	req := capacity.Request{CPU: 0.5, MemoryMB: 500}
	if headroomScore(full, req) >= headroomScore(empty, req) {
		t.Fatal("emptier node should score higher")
	}
}

// TestPickTwoDistinct ensures pickTwo never picks the same index twice when
// the candidate slice has more than one element. This is the property
// power-of-two-choices depends on for actually being two choices.
func TestPickTwoDistinct(t *testing.T) {
	members := []Member{
		{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}, {NodeID: "d"},
	}
	for i := 0; i < 200; i++ {
		x, y := pickTwo(members)
		if x.NodeID == y.NodeID {
			t.Fatalf("pickTwo returned identical members on iter %d: %v / %v", i, x, y)
		}
	}
}

// TestHeadroomScoreSymmetricNeutral verifies the unknown-capacity path
// returns a neutral 0.5 score so it ties with peers that haven't reported.
func TestHeadroomScoreSymmetricNeutral(t *testing.T) {
	unknown := Member{}
	score := headroomScore(unknown, capacity.Request{CPU: 1, MemoryMB: 1024})
	if math.Abs(score-0.5) > 1e-9 {
		t.Fatalf("expected neutral 0.5 score for unknown capacity, got %v", score)
	}
}
