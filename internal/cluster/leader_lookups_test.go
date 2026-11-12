package cluster

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The leader's per-request reads of one member (C18, bench-full-4): an owner
// lookup and a reservation check read the members they name, never a copy
// of the fleet. At 500 workers those copies were a fifth of the leader's CPU
// and most of its garbage.

// allocBytesPerRun is the heap allocated by one call of f, averaged over n.
func allocBytesPerRun(n int, f func()) uint64 {
	f() // warm up: lazily built state is not the call's cost
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range n {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}

func TestPeerLookupsReadOneMember(t *testing.T) {
	c := sampledFleet(500, nil, func(i int, m *Member) {
		m.InternalURL = fmt.Sprintf("https://%s:7002", m.NodeID)
		m.DataPlaneHost = fmt.Sprintf("10.0.%d.%d", i/250, i%250)
		if i == 9 {
			m.Alive = false
		}
	})
	g := c.gossip
	if got := g.peerInternalURL("worker-0250"); got != "https://worker-0250:7002" {
		t.Fatalf("peerInternalURL = %q", got)
	}
	if got := g.peerAPIURL("worker-0250"); got != "http://worker-0250" {
		t.Fatalf("peerAPIURL = %q", got)
	}
	if got := g.peerDataPlaneHost("worker-0251"); got != "10.0.1.1" {
		t.Fatalf("peerDataPlaneHost = %q", got)
	}
	for _, id := range []string{"no-such-node", ""} {
		if g.peerInternalURL(id) != "" || g.peerAPIURL(id) != "" || g.peerDataPlaneHost(id) != "" || c.memberAlive(id) {
			t.Fatalf("an unknown node %q answered", id)
		}
	}
	if !c.memberAlive("worker-0008") || c.memberAlive("worker-0009") {
		t.Fatal("memberAlive does not follow the member's own record")
	}
	if b := allocBytesPerRun(200, func() { _ = g.peerInternalURL("worker-0250"); _ = c.memberAlive("worker-0250") }); b > 0 {
		t.Fatalf("one lookup allocated %d bytes, want 0: it copies the fleet", b)
	}
	var nilGossip *gossipNode
	if nilGossip.peerInternalURL("worker-0001") != "" || (&Cluster{}).memberAlive("worker-0001") {
		t.Fatal("no gossip node must mean no member")
	}
}

// reserveOn is a reservation of one CPU for a new sandbox on owner.
func reserveOn(id, owner string) command {
	return command{Op: opReserve, SandboxID: id, OwnerNodeID: owner, IncarnationID: "inc-" + id,
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Unix() + 120}
}

// The reservation check reads its owners only, with the same answers as
// before: room, no room, unknown, stale capacity lease.
func TestReservationCheckReadsOnlyItsOwners(t *testing.T) {
	c := sampledFleet(500, func(i int) bool { return i != 7 }, nil)
	if err := c.admitReservationCommand(reserveOn("sb-a", "worker-0006")); err != nil {
		t.Fatalf("a worker with room: %v", err)
	}
	if err := c.admitReservationCommand(reserveOn("sb-b", "worker-0007")); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("a full worker = %v, want ErrCapacityExceeded", err)
	}
	if err := c.admitReservationCommand(reserveOn("sb-c", "worker-9999")); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("an unknown worker = %v, want ErrNoPlacementTarget", err)
	}
	batch := command{Op: opReserveBatch, Reservations: []reservationCommand{
		{SandboxID: "sb-d", OwnerNodeID: "worker-0006", IncarnationID: "inc-d", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Unix() + 120},
		{SandboxID: "sb-e", OwnerNodeID: "worker-0006", IncarnationID: "inc-e", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Unix() + 120},
	}}
	if err := c.admitReservationCommand(batch); err != nil {
		t.Fatalf("two reservations on one worker with room: %v", err)
	}
	if b := allocBytesPerRun(200, func() { _ = c.admitReservationCommand(reserveOn("sb-a", "worker-0006")) }); b > 16<<10 {
		t.Fatalf("one check allocated %d bytes at 500 workers, want under 16 KB: it copies the fleet", b)
	}

	// The capacity lease decides, as on the full list: gossip says room,
	// the lease is an hour old.
	c.capacityLeases = newCapacityLeaseCache("", nil, 5*time.Second, nil)
	c.capacityLeases.leases["worker-0006"] = capacityLease{
		snapshot: capacity.Snapshot{HostCPUCores: 16, HostMemoryTotalMB: 65536, CPUBudget: 15, MemoryBudgetMB: 60000},
		updated:  time.Now().Add(-time.Hour),
	}
	if err := c.admitReservationCommand(reserveOn("sb-f", "worker-0006")); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("a stale lease = %v, want ErrNoPlacementTarget", err)
	}
}
