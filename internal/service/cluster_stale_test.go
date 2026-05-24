package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stubStaleCluster is a Noop wrapper that returns a fixed non-self owner for
// every sandbox. Used to drive reconcileStaleOwnership through its destroy
// branch without standing up a real raft node in this test.
type stubStaleCluster struct {
	*cluster.Noop
	otherNode string
	otherURL  string
}

func (s *stubStaleCluster) OwnerOf(_ string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{NodeID: s.otherNode, APIURL: s.otherURL, IsSelf: false}, nil
}

type recordingOwnershipCluster struct {
	*cluster.Noop
	placements map[string]cluster.Placement
	asserted   [][]cluster.LocalSandboxState
}

func (r *recordingOwnershipCluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := r.placements[id]
	return p, ok
}

func (r *recordingOwnershipCluster) AssertOwnership(_ context.Context, local []cluster.LocalSandboxState) error {
	cp := append([]cluster.LocalSandboxState(nil), local...)
	r.asserted = append(r.asserted, cp)
	for _, st := range local {
		r.placements[st.ID] = cluster.Placement{
			SandboxID:           st.ID,
			OwnerNodeID:         r.SelfNodeID(),
			OwnerAPIURL:         r.SelfAPIURL(),
			Spec:                st.Spec,
			ExposedPortRoutes:   st.ExposedPorts,
			ExposedPorts:        legacyPortProtocols(st.ExposedPorts),
			State:               cluster.PlacementStatePlaced,
			OwnerState:          cluster.PlacementOwnerStateActive,
			OrphanedOwnerNodeID: "",
		}
	}
	return nil
}

func legacyPortProtocols(routes map[int]cluster.ExposedPortRoute) map[int]string {
	if len(routes) == 0 {
		return nil
	}
	out := make(map[int]string, len(routes))
	for port, route := range routes {
		out[port] = route.Protocol
	}
	return out
}

// TestReplayReservationsThenStaleOwnershipReleasesCapacity is the boot-time
// interaction test for the rejoin-after-outage case: a node returns to find
// the cluster has reassigned one of its sandboxes to a peer. ReplayReservations
// re-Reserves capacity for the local row at boot (it can't yet know about the
// reassignment), but the next Reconcile must spot the stale ownership, destroy
// the local copy, and free the admitter so the host isn't permanently
// over-reserved by a sandbox someone else now owns.
func TestReplayReservationsThenStaleOwnershipReleasesCapacity(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	// Local row for a sandbox the cluster has already reassigned to "node-b".
	const sandboxID = "sb-reassigned"
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-reassigned",
		ContainerIP:  "10.0.0.20",
		CPU:          2,
		MemoryMB:     2048,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Boot step 1: ReplayReservations re-Reserves capacity for the local row.
	svc.ReplayReservations(ctx)
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 || snap.ReservedCPU != 2 {
		t.Fatalf("after replay: active=%d cpu=%v, want 1 / 2", snap.SandboxesActive, snap.ReservedCPU)
	}

	// Now attach a cluster client that reports the sandbox as owned by a peer.
	svc.AttachCluster(&stubStaleCluster{
		Noop:      cluster.NewNoop("self", "http://self"),
		otherNode: "node-b",
		otherURL:  "http://node-b",
	})

	// Boot step 2: first Reconcile must destroy the stale local copy and
	// release its admitter slot — otherwise capacity stays double-billed
	// across this node and the new owner forever.
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	snap := admitter.Snapshot()
	if snap.SandboxesActive != 0 {
		t.Fatalf("admitter still holds reservation after stale destroy: %+v", snap)
	}
	if snap.ReservedCPU != 0 || snap.ReservedMemoryMB != 0 {
		t.Fatalf("admitter accounting not zeroed: cpu=%v mem=%v", snap.ReservedCPU, snap.ReservedMemoryMB)
	}
	if _, err := st.Get(ctx, sandboxID); err == nil {
		t.Fatal("local row should be deleted after stale-ownership destroy")
	}
}

// TestReconcileStaleOwnershipKeepsLocalSandboxWhenSelfOwns guards the negative
// case: a normally-owned sandbox must NOT be touched by reconcileStaleOwnership
// even when a cluster client is attached. Without this guard, every Reconcile
// would destroy every sandbox in cluster mode.
func TestReconcileStaleOwnershipKeepsLocalSandboxWhenSelfOwns(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-mine"
	const containerID = "ctr-mine"
	// Pre-populate the runtime's managed map so reconcile's "container gone"
	// branch does NOT fire — we want the test to isolate stale-ownership behaviour.
	svc, admitter, st := newCapacityHarness(t, map[string]*models.SandboxRuntimeState{
		sandboxID: {
			SandboxID:   sandboxID,
			ContainerID: containerID,
			ContainerIP: "10.0.0.30",
			Status:      models.SandboxStatusStarted,
		},
	}, nil)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  containerID,
		ContainerIP:  "10.0.0.30",
		CPU:          1,
		MemoryMB:     1024,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	admitter.Reserve(sandboxID, capacity.Request{CPU: 1, MemoryMB: 1024})

	// Noop cluster reports self for every id.
	svc.AttachCluster(cluster.NewNoop("self", "http://self"))

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := st.Get(ctx, sandboxID); err != nil {
		t.Fatalf("self-owned sandbox was destroyed by reconcileStaleOwnership: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 {
		t.Fatalf("admitter lost the reservation: %+v", snap)
	}
}

func TestReconcileBackfillsMissingPlacementForManagedLocalSandbox(t *testing.T) {
	ctx := context.Background()
	const sandboxID = "sb-local-missing-placement"
	const containerID = "ctr-local-missing-placement"
	svc, _, st := newCapacityHarness(t, map[string]*models.SandboxRuntimeState{
		sandboxID: {
			SandboxID:   sandboxID,
			ContainerID: containerID,
			ContainerIP: "10.0.0.41",
			Status:      models.SandboxStatusStarted,
		},
	}, nil)
	svc.cfg.EnableCluster = true
	recorder := &recordingOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self"),
		placements: map[string]cluster.Placement{},
	}
	svc.AttachCluster(recorder)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           sandboxID,
		Image:        "ubuntu:22.04",
		Status:       models.SandboxStatusStarted,
		ContainerID:  containerID,
		ContainerIP:  "10.0.0.41",
		CPU:          1,
		MemoryMB:     1024,
		Runtime:      models.RuntimeDocker,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if len(recorder.asserted) != 1 || len(recorder.asserted[0]) != 1 {
		t.Fatalf("AssertOwnership calls = %+v, want one local sandbox replay", recorder.asserted)
	}
	if got := recorder.asserted[0][0]; got.ID != sandboxID || got.Spec == nil || got.Spec.Image != "ubuntu:22.04" {
		t.Fatalf("replayed state = %+v", got)
	}

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(recorder.asserted) != 1 {
		t.Fatalf("ownership replay was not idempotent; calls = %d", len(recorder.asserted))
	}
}
