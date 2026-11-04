package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCancelReservationReachesLeaderWhenReplicaLags is the live failure: the
// proposer reserves a name through raft and forwards the create to another
// node, the create fails within milliseconds, and that node cancels before
// its FSM has applied the reservation. CancelReservation used to treat the
// local miss as "nothing to cancel", so the name stayed held until the
// reservation expired and every retry got "sandbox name already in use".
func TestCancelReservationReachesLeaderWhenReplicaLags(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "cancel-lag", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	giveFreshCapacity(leader)

	ctx := context.Background()
	target := PlacementTarget{NodeID: leader.nodeID, APIURL: leader.apiURL, DataPlaneHost: leader.dataPlaneHost}
	spec := &models.CreateSandboxRequest{Image: "alpine", Name: "lagging-name"}
	if err := leader.ReserveOnTarget(ctx, "sb-lag", target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget: %v", err)
	}

	// The forwarded-create target: its cancel goes through the same raft
	// (so it reaches the leader), but its own FSM has not applied the
	// reservation yet.
	lagging := &Cluster{
		nodeID:        leader.nodeID,
		fsm:           newPlacementFSM(),
		raft:          leader.raft,
		commitTimeout: leader.commitTimeout,
		authoritativePlacementsHook: func(_ context.Context, ids []string) (map[string]Placement, error) {
			return leader.fsm.placementsByIDs(ids), nil
		},
	}
	if err := lagging.CancelReservation(ctx, "sb-lag"); err != nil {
		t.Fatalf("CancelReservation from a lagging replica: %v", err)
	}
	if p, ok := leader.PlacementOf("sb-lag"); ok {
		t.Fatalf("the reservation survived a cancel from a lagging replica: %+v", p)
	}
	// What the client saw: a retry with the same name must reserve again.
	if err := leader.ReserveOnTarget(ctx, "sb-retry", target, spec, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("retry with the same name = %v, want the name released", err)
	}
}

// TestCancelReservationLocalRowIsConclusive: a row the local FSM already has
// needs no leader round trip, whatever its state. A replica only lags, so a
// local row that is no longer reserved cannot be reserved on the leader.
func TestCancelReservationLocalRowIsConclusive(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "cancel-local", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)

	ctx := context.Background()
	if err := leader.RecordPlacement(ctx, "sb-placed", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	leader.authoritativePlacementsHook = func(context.Context, []string) (map[string]Placement, error) {
		t.Fatal("a locally present row must not trigger a leader read")
		return nil, nil
	}
	defer func() { leader.authoritativePlacementsHook = nil }()
	if err := leader.CancelReservation(ctx, "sb-placed"); err != nil {
		t.Fatalf("CancelReservation on a placed row: %v", err)
	}
	if _, ok := leader.PlacementOf("sb-placed"); !ok {
		t.Fatal("cancelling a placed (not reserved) row removed it")
	}
}

func TestCancelReservationLocalMissBranches(t *testing.T) {
	ctx := context.Background()

	// No raft and no hook: a single-process FSM is the whole truth.
	if err := (&Cluster{fsm: newPlacementFSM()}).CancelReservation(ctx, "sb-missing"); err != nil {
		t.Fatalf("FSM-only miss = %v, want nil", err)
	}

	// The leader does not have it either: nothing to cancel, no apply.
	gone := &Cluster{fsm: newPlacementFSM(), authoritativePlacementsHook: func(context.Context, []string) (map[string]Placement, error) {
		return map[string]Placement{}, nil
	}}
	if err := gone.CancelReservation(ctx, "sb-gone"); err != nil {
		t.Fatalf("authoritative miss = %v, want nil", err)
	}

	// The leader has it but it is no longer reserved (already promoted).
	promoted := &Cluster{fsm: newPlacementFSM(), authoritativePlacementsHook: func(_ context.Context, ids []string) (map[string]Placement, error) {
		return map[string]Placement{ids[0]: {SandboxID: ids[0], State: PlacementStatePlaced}}, nil
	}}
	if err := promoted.CancelReservation(ctx, "sb-promoted"); err != nil {
		t.Fatalf("authoritative placed row = %v, want nil", err)
	}

	// The leader cannot be asked: surface it, so the caller's retract path
	// logs a cancel failure instead of silently leaking the name.
	unreachable := errors.New("leader unreachable")
	broken := &Cluster{fsm: newPlacementFSM(), authoritativePlacementsHook: func(context.Context, []string) (map[string]Placement, error) {
		return nil, unreachable
	}}
	if err := broken.CancelReservation(ctx, "sb-unknown"); !errors.Is(err, unreachable) {
		t.Fatalf("authoritative read failure = %v, want it surfaced", err)
	}
}

// giveFreshCapacity lets placement reserve on c itself: a target needs a
// fresh capacity heartbeat (same setup as the reservation wrapper test).
func giveFreshCapacity(c *Cluster) {
	c.gossip.delegate.mu.Lock()
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 8192, DiskTotalGB: 100, DiskFreeGB: 100},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	)
	c.gossip.delegate.admitter = admitter
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
	c.capacityLeases.setAdmitter(admitter)
	c.capacityLeases.set(c.nodeID, admitter.Snapshot(), time.Now())
}
