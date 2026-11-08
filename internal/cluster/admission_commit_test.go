package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A create the leader must refuse for capacity is refused at once, even while
// another create's commit is still under way, and the create still in flight
// is what fills the worker (plan item E2). The leader used to hold its
// admission lock across every Raft commit, so this refusal waited for the
// other create's disk sync and quorum round trip, and creates committed one
// at a time.
func TestAdmissionRefusalDoesNotWaitForAnotherCommit(t *testing.T) {
	bc := newReserveTestCluster(t, 0, 2)
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	ctx := context.Background()
	// The first admission of a leader term runs a Raft barrier, holding the
	// admission lock, by design. Get it done before freezing a commit.
	if err := bc.leader.ReserveOnTarget(ctx, "sb-warm", bc.target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("warm-up reserve: %v", err)
	}
	gate := newStoreGate()
	bc.leaderStore.gate.Store(gate)
	defer gate.open()

	first := make(chan error, 1)
	go func() {
		first <- bc.leader.ReserveOnTarget(ctx, "sb-first", bc.target, spec, PlacementSecrets{}, time.Minute)
	}()
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first reserve never reached the leader's log")
	}
	// sb-first is admitted and its log write is stuck: it is in flight, not
	// committed, and holds the worker's last slot.
	second := make(chan error, 1)
	go func() {
		second <- bc.leader.ReserveOnTarget(ctx, "sb-second", bc.target, spec, PlacementSecrets{}, time.Minute)
	}()
	select {
	case err := <-second:
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("second reserve on a full worker = %v, want ErrCapacityExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the refusal waited for another create's commit: the admission lock is held across the Raft commit")
	}
	gate.open()
	if err := <-first; err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if p, ok := bc.leader.fsm.get("sb-first"); !ok || !p.IsReserved() {
		t.Fatalf("sb-first after its commit = %v %+v, want reserved", ok, p)
	}
	if _, ok := bc.leader.fsm.get("sb-second"); ok {
		t.Fatal("sb-second was refused but is in the FSM")
	}
}
