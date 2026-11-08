package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newDeletedLifecycleTestCluster is a single-voter cluster that keeps a
// post-delete record for an hour, the SB_AUDIT_DELETED_GRACE default. The
// plain test cluster keeps none (grace 0), and with no record there is
// nothing for the deleted-lifecycle fence to find.
func newDeletedLifecycleTestCluster(t *testing.T, nodeID string) (*Cluster, func()) {
	t.Helper()
	c, cleanup := newTestClusterWithCfg(t, nodeID, true, nil, func(cfg *config.Config) {
		cfg.AuditDeletedGrace = time.Hour
	})
	waitForLeader(t, c, 10*time.Second)
	return c, cleanup
}

// TestRecordPlacementRefusesDeletedLifecycle is the FSM half of C2
// (plans/cluster-correctness-and-create-latency.md, invariant I3): once a
// lifecycle (sandbox id + incarnation) is deleted, an opPlace for the same
// lifecycle on the now-missing row must be refused. Before the fix the FSM
// treated the missing row as a fresh placement and wrote it back.
func TestRecordPlacementRefusesDeletedLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const sandboxID, incarnationID = "sb-deleted", "inc-deleted"
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	secrets := PlacementSecrets{IncarnationID: incarnationID}
	if err := c.RecordPlacement(ctx, sandboxID, spec, secrets); err != nil {
		t.Fatalf("place: %v", err)
	}
	if err := c.DeletePlacementExact(ctx, sandboxID, c.nodeID, incarnationID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := c.fsm.get(sandboxID); ok {
		t.Fatal("placement survived its own delete")
	}

	err := c.RecordPlacement(ctx, sandboxID, spec, secrets)
	if _, ok := c.fsm.get(sandboxID); ok {
		t.Fatal("opPlace re-created the placement of a deleted lifecycle: the deleted sandbox is routable again")
	}
	if err == nil {
		t.Fatal("opPlace for a deleted lifecycle returned no error; the caller cannot tell it was refused")
	}

	// ID reuse is a new lifecycle with a new incarnation, and stays allowed.
	if err := c.RecordPlacement(ctx, sandboxID, spec, PlacementSecrets{IncarnationID: "inc-reused"}); err != nil {
		t.Fatalf("place a new lifecycle of the same id: %v", err)
	}
	if got, ok := c.fsm.get(sandboxID); !ok || got.IncarnationID != "inc-reused" {
		t.Fatalf("reused id placement = %+v ok=%v, want incarnation inc-reused", got, ok)
	}
}
