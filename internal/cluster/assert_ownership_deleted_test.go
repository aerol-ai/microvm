package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAssertOwnershipDoesNotReplaceDeletedLifecycle is C2's replay half. A
// node is cut off, the cluster deletes its sandbox (opDelete commits), and the
// node comes back with the local row still in its store. Its ownership replay
// finds no placement and, before the fix, wrote one back with the old
// incarnation, so the deleted sandbox was routable again.
func TestAssertOwnershipDoesNotReplaceDeletedLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const sandboxID, incarnationID = "sb-returning", "inc-returning"
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	if err := c.RecordPlacement(ctx, sandboxID, spec, PlacementSecrets{IncarnationID: incarnationID}); err != nil {
		t.Fatalf("place: %v", err)
	}
	if err := c.DeletePlacementExact(ctx, sandboxID, c.nodeID, incarnationID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID:           sandboxID,
		Spec:         spec,
		Secrets:      PlacementSecrets{IncarnationID: incarnationID},
		ExposedPorts: map[int]ExposedPortRoute{8080: {Protocol: "http"}},
	}})
	if got, ok := c.fsm.get(sandboxID); ok {
		t.Fatalf("ownership replay re-placed a deleted lifecycle: %+v", got)
	}
	if err == nil {
		t.Fatal("ownership replay hid the refusal; the caller must learn the row was not placed")
	}
}
