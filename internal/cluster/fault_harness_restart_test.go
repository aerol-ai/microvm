package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestClusterFaultHarnessRestartedOwnerIsPlaceable pins what every fault test
// relies on once start or startAgain returns: every live server lists the
// started server alive in gossip and holds its stand-in capacity lease. A
// reserve onto that server then gets the FSM's verdict, never admission's
// "has no fresh capacity heartbeat" or "is not an alive placement target".
//
// The property model hit that once (seed 7, step 23 "start pmr-s2", step 24
// "create sb-prop-04 on pmr-s2 via pmr-s3"; the leader was pmr-s1, as the
// error came back across the forward hop). Every server ran the product's
// capacity sweep, and its retain dropped the lease of any server its gossip
// did not list. start returned before the leader's gossip had taken the
// restarted server's refute of its old leave, so a sweep in that gap left
// the leader without the lease until leaseLoop wrote it again, up to
// faultLeaseRefresh later, and the next create landed in between.
//
// Both halves are forced here. First the owner stays down until no live
// server's gossip lists it and two sweep intervals pass: the stand-in lease
// must stay put. Then it restarts after a short stop, the shape in which the
// leader's gossip used to lag start, and every live server runs its capacity
// sweep the moment start returns, as its ticker may at any moment.
func TestClusterFaultHarnessRestartedOwnerIsPlaceable(t *testing.T) {
	fc := newFaultCluster(t, "hro", 3)
	for _, s := range fc.servers {
		fc.setLease(s.id, staticCapacity(10))
	}
	leader := fc.leader()
	var owner, via *faultServer
	for _, s := range fc.servers {
		switch {
		case s == leader:
		case owner == nil:
			owner = s
		default:
			via = s
		}
	}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reserve := func(id, incarnation string) error {
		oc := owner.cluster()
		target := PlacementTarget{NodeID: oc.nodeID, APIURL: oc.apiURL, DataPlaneHost: oc.dataPlaneHost}
		return retryLeaderChange(ctx, 50*time.Millisecond, func(ctx context.Context) error {
			return via.cluster().ReserveOnTarget(ctx, id, target, spec, PlacementSecrets{IncarnationID: incarnation}, time.Minute)
		})
	}
	held := mustIncarnation(t)
	if err := reserve("sb-hro-held", held); err != nil {
		t.Fatalf("reserve sb-hro-held: %v", err)
	}
	if err := retryLeaderChange(ctx, 50*time.Millisecond, func(ctx context.Context) error {
		return owner.cluster().RecordPlacement(ctx, "sb-hro-held", nil, PlacementSecrets{IncarnationID: held})
	}); err != nil {
		t.Fatalf("promote sb-hro-held: %v", err)
	}
	stopUntilUnlisted := func() {
		t.Helper()
		fc.stopServer(owner)
		deadline := time.Now().Add(faultWait)
		for listed := true; listed; {
			listed = false
			for _, s := range fc.up() {
				if _, ok := s.cluster().gossip.lookupMember(owner.id); ok {
					listed = true
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("live servers still list %s %s after it stopped", owner.id, faultWait)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	stopUntilUnlisted()
	// Two sweeps at the test config's ClusterCapacityGossipInterval (1 s).
	for end := time.Now().Add(2*time.Second + faultLeaseRefresh); time.Now().Before(end); time.Sleep(time.Millisecond) {
		for _, s := range fc.up() {
			if !s.cluster().capacityLeases.freshLease(owner.id, time.Now()) {
				t.Fatalf("%s lost %s's stand-in capacity lease while %s was down", s.id, owner.id, owner.id)
			}
		}
	}
	fc.startAgain(owner)

	stopUntilUnlisted()
	// startAgain's own steps, with the sweeps run the moment start returns.
	fc.start(owner, false)
	for _, s := range fc.up() {
		s.cluster().refreshCapacityLeases(ctx)
	}
	for _, s := range fc.up() {
		c := s.cluster()
		if m, ok := c.gossip.lookupMember(owner.id); !ok || !m.Alive {
			t.Errorf("%s does not list %s alive once start returned (listed %v)", s.id, owner.id, ok)
		}
		if !c.capacityLeases.freshLease(owner.id, time.Now()) {
			t.Errorf("%s has no fresh capacity lease for %s once start returned", s.id, owner.id)
		}
	}
	waitForLeader(t, owner.cluster(), faultWait)
	fc.settle()
	err := reserve("sb-hro-held", mustIncarnation(t))
	if !errors.Is(err, ErrReservationConflict) && !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("reserve of held sb-hro-held on restarted %s refused with %v, want a reservation or incarnation conflict", owner.id, err)
	}
	if err := reserve("sb-hro-free", mustIncarnation(t)); err != nil {
		t.Fatalf("reserve of free sb-hro-free on restarted %s: %v", owner.id, err)
	}
}
