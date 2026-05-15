package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAssertOwnershipBackfillsFreshPlacement covers the boot scenario where the
// FSM has no record of a locally-running sandbox: AssertOwnership must mint a
// placement pointing to self AND carry the spec/ports through so a later
// failover-recreate has everything it needs.
func TestAssertOwnershipBackfillsFreshPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512}
	local := []LocalSandboxState{{
		ID:   "sb-fresh",
		Spec: spec,
		ExposedPorts: map[int]ExposedPortRoute{
			80:   {Protocol: "http"},
			5432: {Protocol: "tcp", HostPort: 22432},
		},
	}}
	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}

	got, ok := c.fsm.get("sb-fresh")
	if !ok {
		t.Fatal("placement not created by AssertOwnership")
	}
	if got.OwnerNodeID != "leader" {
		t.Fatalf("OwnerNodeID = %q, want leader", got.OwnerNodeID)
	}
	if got.Spec == nil || got.Spec.Image != "alpine" {
		t.Fatalf("spec not backfilled: %+v", got.Spec)
	}
	if got.ExposedPorts[80] != "http" || got.ExposedPorts[5432] != "tcp" {
		t.Fatalf("exposed ports not backfilled: %+v", got.ExposedPorts)
	}
}

// TestAssertOwnershipBackfillsMissingSpec is the pre-cluster-sandbox case: a
// placement already exists (e.g. legacy opPlace with spec=nil) and the local
// boot replay carries the spec + ports the FSM never received. The backfill
// path must opUpsertSpec without disturbing ownership and add every port intent.
func TestAssertOwnershipBackfillsMissingSpec(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Plant a spec-less placement via raw raft Apply so we hit the
	// "placement exists, spec missing" branch deterministically.
	cmd := command{Op: opPlace, SandboxID: "sb-legacy", OwnerNodeID: "leader"}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed opPlace: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 0.25, MemoryMB: 128}
	local := []LocalSandboxState{{
		ID:           "sb-legacy",
		Spec:         spec,
		ExposedPorts: map[int]ExposedPortRoute{443: {Protocol: "tls"}},
	}}
	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}

	got, ok := c.fsm.get("sb-legacy")
	if !ok {
		t.Fatal("placement disappeared")
	}
	if got.Spec == nil || got.Spec.Image != "alpine" || got.Spec.MemoryMB != 128 {
		t.Fatalf("spec not backfilled by UpsertSpec: %+v", got.Spec)
	}
	if got.ExposedPorts[443] != "tls" {
		t.Fatalf("port intent not backfilled: %+v", got.ExposedPorts)
	}
}

// TestAssertOwnershipDoesNotReclaimForeignOwnedPlacement is the
// failover-recovery regression. Scenario:
//
//  1. This node owned sb-failover, died hard.
//  2. The dead-owner reconciler reassigned sb-failover to "node-b" and node-b
//     recreated it from the replicated spec.
//  3. This node comes back online with the stale local row still in its store.
//
// AssertOwnership MUST NOT call RecordPlacement here — doing so would overwrite
// node-b's ownership in the FSM, after which node-b's stale-ownership
// reconciler would destroy its freshly-recreated container, silently losing
// user state. The local row is cleaned up later by service.reconcileStaleOwnership.
func TestAssertOwnershipDoesNotReclaimForeignOwnedPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	// Plant a placement that points to a different (live) node — simulates the
	// post-failover state where the new owner already wrote ownership and ran
	// the recreate. Spec is set to mimic the new owner having shipped one.
	newOwnerSpec := &models.CreateSandboxRequest{Image: "alpine:new", CPU: 2, MemoryMB: 1024}
	cmd := command{
		Op:          opPlace,
		SandboxID:   "sb-failover",
		OwnerNodeID: "node-b",
		OwnerAPIURL: "http://node-b:21212",
		Spec:        newOwnerSpec,
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("seed opPlace: %v", err)
	}
	before, ok := c.fsm.get("sb-failover")
	if !ok {
		t.Fatal("seed placement missing")
	}

	// Now this node (which is "leader" in the test setup) wakes up and replays
	// its local store. The local row still claims this sandbox with its
	// pre-failover spec — the divergent state we must NOT promote into the FSM.
	staleLocalSpec := &models.CreateSandboxRequest{Image: "alpine:old", CPU: 1, MemoryMB: 256}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	local := []LocalSandboxState{{
		ID:           "sb-failover",
		Spec:         staleLocalSpec,
		ExposedPorts: map[int]ExposedPortRoute{9999: {Protocol: "tcp", HostPort: 22999}},
	}}
	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}

	after, ok := c.fsm.get("sb-failover")
	if !ok {
		t.Fatal("placement disappeared — AssertOwnership must not delete foreign-owned placements either")
	}
	if after.OwnerNodeID != "node-b" {
		t.Fatalf("AssertOwnership clobbered FSM owner: was %q now %q (this is the failover-recovery data-loss bug)", before.OwnerNodeID, after.OwnerNodeID)
	}
	if after.Spec == nil || after.Spec.Image != "alpine:new" || after.Spec.MemoryMB != 1024 {
		t.Fatalf("AssertOwnership clobbered FSM spec with stale local spec: %+v", after.Spec)
	}
	// Port intents must not be added either — we don't own it.
	if _, exists := after.ExposedPorts[9999]; exists {
		t.Fatalf("AssertOwnership added port intent to foreign-owned placement: %+v", after.ExposedPorts)
	}
	if after.Version != before.Version {
		t.Fatalf("AssertOwnership wrote a new version (%d -> %d) for a foreign-owned placement; it must have been a complete no-op at the FSM layer", before.Version, after.Version)
	}
}

// TestAssertOwnershipIsIdempotent guards the two-restart case: after the first
// boot writes the backfill, a second boot with the same payload must produce
// no churn — same ownership, same spec, same ports.
func TestAssertOwnershipIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	local := []LocalSandboxState{{
		ID:           "sb-twice",
		Spec:         &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256},
		ExposedPorts: map[int]ExposedPortRoute{8080: {Protocol: "http"}},
	}}
	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("first AssertOwnership: %v", err)
	}
	first, ok := c.fsm.get("sb-twice")
	if !ok {
		t.Fatal("placement missing after first AssertOwnership")
	}

	if err := c.AssertOwnership(ctx, local); err != nil {
		t.Fatalf("second AssertOwnership: %v", err)
	}
	second, ok := c.fsm.get("sb-twice")
	if !ok {
		t.Fatal("placement disappeared after second AssertOwnership")
	}
	if second.OwnerNodeID != first.OwnerNodeID {
		t.Fatalf("owner changed across idempotent calls: %q -> %q", first.OwnerNodeID, second.OwnerNodeID)
	}
	if second.CreatedUnix != first.CreatedUnix {
		t.Fatalf("CreatedUnix changed across idempotent calls: %d -> %d", first.CreatedUnix, second.CreatedUnix)
	}
}
