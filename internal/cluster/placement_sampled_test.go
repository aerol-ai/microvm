package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// sampledFleet is a cell of three servers, three gateways and n workers in
// zones z-a, z-b and z-c. A worker for which room(i) is false has no CPU
// left; edit(i, &m) changes a worker before it joins.
func sampledFleet(n int, room func(int) bool, edit func(int, *Member)) *Cluster {
	c := &Cluster{
		nodeID: "server-0",
		apiURL: "http://server-0",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: newGossipMemberIndex()},
	}
	members := make([]Member, 0, n+6)
	for i := range 3 {
		members = append(members,
			Member{NodeID: fmt.Sprintf("server-%d", i), Alive: true, Role: config.NodeRoleServer},
			Member{NodeID: fmt.Sprintf("gateway-%d", i), Alive: true, Role: config.NodeRoleIngress})
	}
	for i := range n {
		id := fmt.Sprintf("worker-%04d", i)
		reserved := 15.0
		if room == nil || room(i) {
			reserved = float64(i % 10)
		}
		m := Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + id,
			Capacity: capacity.Snapshot{HostCPUCores: 16, HostMemoryTotalMB: 65536, CPUBudget: 15, MemoryBudgetMB: 60000,
				ReservedCPU: reserved, Labels: map[string]string{models.PlacementZoneLabel: fmt.Sprintf("z-%c", 'a'+i%3)}}}
		if edit != nil {
			edit(i, &m)
		}
		members = append(members, m)
	}
	c.gossip.memberIndex.replace(members)
	return c
}

func workerIndex(t *testing.T, id string) int {
	t.Helper()
	var i int
	if _, err := fmt.Sscanf(id, "worker-%04d", &i); err != nil {
		t.Fatalf("target %q is not a worker", id)
	}
	return i
}

// The sampled path judges its members with the same rules as the full scan:
// a worker with no room is never chosen, and a large fleet decides from a
// sample, not a scan.
func TestSampledPlacementOnlyPicksWorkersWithRoom(t *testing.T) {
	c := sampledFleet(300, func(i int) bool { return i%2 == 0 }, nil)
	sampled := placementSampledDecisions.Value()
	for range 500 {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if i := workerIndex(t, target.NodeID); i%2 != 0 {
			t.Fatalf("chose %s, which has no room", target.NodeID)
		}
	}
	if got := placementSampledDecisions.Value() - sampled; got < 450 {
		t.Fatalf("sampled decisions = %d of 500, want nearly all on a 300-worker fleet", got)
	}
}

// A nearly full cell: the sample almost never holds the one worker with
// room, so the full scan decides, and finds it every time.
func TestSampledPlacementFindsTheLastFreeWorker(t *testing.T) {
	c := sampledFleet(300, func(i int) bool { return i == 123 }, nil)
	for range 50 {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024})
		if err != nil || target.NodeID != "worker-0123" {
			t.Fatalf("target = %q, %v; want worker-0123, the only one with room", target.NodeID, err)
		}
	}
}

// A full cell still says it is full, not "no target".
func TestSampledPlacementFullCellIsAtCapacity(t *testing.T) {
	c := sampledFleet(300, func(int) bool { return false }, nil)
	if _, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024}); !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("err = %v, want ErrClusterAtCapacity", err)
	}
}

// Below sampledPlacementMinOwners the full scan decides, exactly as before.
func TestSmallFleetsScanEverything(t *testing.T) {
	c := sampledFleet(sampledPlacementMinOwners-1, nil, nil)
	sampled, full := placementSampledDecisions.Value(), placementFullScans.Value()
	for range 20 {
		if _, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024}); err != nil {
			t.Fatal(err)
		}
	}
	if placementSampledDecisions.Value() != sampled || placementFullScans.Value()-full != 20 {
		t.Fatalf("sampled +%d, full +%d; want 0 and 20", placementSampledDecisions.Value()-sampled, placementFullScans.Value()-full)
	}
}

// A placement rule holds on the sampled path: every pick is in the zone.
func TestSampledPlacementKeepsPlacementRules(t *testing.T) {
	c := sampledFleet(300, nil, nil)
	req := capacity.Request{CPU: 1, MemoryMB: 1024, Labels: map[string]string{models.PlacementZoneLabel: "z-b"}}
	for range 200 {
		target, err := c.SelectPlacement(req)
		if err != nil {
			t.Fatal(err)
		}
		if i := workerIndex(t, target.NodeID); i%3 != 1 {
			t.Fatalf("chose %s outside z-b", target.NodeID)
		}
	}
}

// Members the rules turn away never win on the sampled path: dead, about to
// restart, a stale heartbeat, no API URL.
func TestSampledPlacementSkipsMembersTheRulesTurnAway(t *testing.T) {
	c := sampledFleet(300, nil, func(i int, m *Member) {
		switch i % 5 {
		case 1:
			m.Restarting = true
		case 2:
			m.CapacityStale = true
		case 3:
			m.APIURL = ""
		}
	})
	for range 300 {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if i := workerIndex(t, target.NodeID); i%5 == 1 || i%5 == 2 || i%5 == 3 {
			t.Fatalf("chose %s, which the rules turn away", target.NodeID)
		}
	}
}

// A create bound to one node, or to a template's holders, is the full scan's.
func TestSampledPlacementLeavesBoundCreatesToTheFullScan(t *testing.T) {
	c := sampledFleet(300, nil, nil)
	full := placementFullScans.Value()
	target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024, RequiredNodeID: "worker-0200"})
	if err != nil || target.NodeID != "worker-0200" {
		t.Fatalf("target = %q, %v; want worker-0200", target.NodeID, err)
	}
	if placementFullScans.Value()-full != 1 {
		t.Fatal("a create bound to one node was not decided by the full scan")
	}
}

// The owner list and the topology error follow membership churn, and an
// invalid topology still fails the create with its own error.
func TestOwnerIndexFollowsChurn(t *testing.T) {
	c := sampledFleet(100, nil, nil)
	idx := c.gossip.memberIndex
	if _, owners, err := idx.sampleOwners(8, func(n int) int { return 0 }); owners != 100 || err != nil {
		t.Fatalf("owners = %d, %v; want 100", owners, err)
	}
	gone, _ := idx.get("worker-0007")
	gone.Alive = false
	idx.upsert(gone)
	if _, owners, _ := idx.sampleOwners(8, func(n int) int { return n - 1 }); owners != 99 {
		t.Fatalf("owners after a death = %d, want 99", owners)
	}
	sample, _, _ := idx.sampleOwners(150, func(n int) int { return 3 })
	if len(sample) != 1 {
		t.Fatalf("a picker that repeats itself gave %d members, want 1, and no endless loop", len(sample))
	}

	// Workers only, no server tier: the topology rule refuses the cell.
	bad := &Cluster{nodeID: "x", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	var members []Member
	for i := range 100 {
		id := fmt.Sprintf("worker-%04d", i)
		members = append(members, Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + id,
			Capacity: capacity.Snapshot{HostCPUCores: 16, HostMemoryTotalMB: 65536, CPUBudget: 15, MemoryBudgetMB: 60000}})
	}
	bad.gossip.memberIndex.replace(members)
	if _, err := bad.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024}); !errors.Is(err, ErrInvalidTopology) {
		t.Fatalf("err = %v, want ErrInvalidTopology", err)
	}
}

// The sampled path reads capacity from the leases, as the full scan does
// (membersWithCapacity): gossip's copy is not what decides. Here gossip says
// every worker has room, and the leases say the odd ones are full or stale.
func TestSampledPlacementReadsTheCapacityLeases(t *testing.T) {
	c := sampledFleet(300, nil, nil)
	c.capacityLeases = newCapacityLeaseCache("", nil, 5*time.Second, nil)
	now := time.Now()
	for i := range 300 {
		id := fmt.Sprintf("worker-%04d", i)
		snap := capacity.Snapshot{HostCPUCores: 16, HostMemoryTotalMB: 65536, CPUBudget: 15, MemoryBudgetMB: 60000,
			Labels: map[string]string{models.PlacementZoneLabel: fmt.Sprintf("z-%c", 'a'+i%3)}}
		updated := now
		switch i % 4 {
		case 1:
			snap.ReservedCPU = 15 // full
		case 3:
			updated = now.Add(-time.Hour) // stale
		}
		c.capacityLeases.leases[id] = capacityLease{snapshot: snap, updated: updated}
	}
	sampled := placementSampledDecisions.Value()
	for range 300 {
		target, err := c.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if i := workerIndex(t, target.NodeID); i%4 == 1 || i%4 == 3 {
			t.Fatalf("chose %s, which its lease says is full or stale", target.NodeID)
		}
	}
	if placementSampledDecisions.Value() == sampled {
		t.Fatal("no decision was sampled")
	}
}
