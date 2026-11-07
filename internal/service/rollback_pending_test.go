package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// rollbackCluster is an FSM view for the rollback-pending tests: one
// placement row per sandbox, exact-fenced begin-delete and delete, a switch
// that makes every authoritative read fail (no leader), and a record of what
// the ownership replay published.
type rollbackCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	readErr    error
	asserted   []string
}

func newRollbackCluster() *rollbackCluster {
	return &rollbackCluster{Noop: cluster.NewNoop("node-a", "http://node-a", ""), placements: map[string]cluster.Placement{}}
}

func (c *rollbackCluster) setReadErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readErr = err
}

func (c *rollbackCluster) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	return p, ok
}

func (c *rollbackCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return nil, c.readErr
	}
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *rollbackCluster) AssertOwnership(_ context.Context, local []cluster.LocalSandboxState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range local {
		c.asserted = append(c.asserted, st.ID)
	}
	return nil
}

func (c *rollbackCluster) BeginDeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	if !ok {
		return cluster.ErrUnknownSandbox
	}
	if p.OwnerNodeID != owner || p.IncarnationID != incarnation {
		return cluster.ErrReservationConflict
	}
	p.State = cluster.PlacementStateDeleting
	c.placements[id] = p
	return nil
}

func (c *rollbackCluster) DeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.placements[id]; ok && p.OwnerNodeID == owner && p.IncarnationID == incarnation {
		delete(c.placements, id)
	}
	return nil
}

// newRollbackHarness is a cluster worker holding one local row per id, each
// with its reservation still in the FSM (the promote never landed).
func newRollbackHarness(t *testing.T, ids ...string) (*Service, *store.Store, *recordingRuntime, *rollbackCluster) {
	t.Helper()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	fc := newRollbackCluster()
	svc.AttachCluster(fc)
	for _, id := range ids {
		resp, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
		if err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		fc.placements[id] = cluster.Placement{
			SandboxID: id, OwnerNodeID: "node-a", IncarnationID: resp.Sandbox.AuditIncarnationID,
			State: cluster.PlacementStateReserved,
		}
	}
	return svc, st, rt, fc
}

// TestOwnershipReplaySkipsRollbackPendingRows: the boot replay and the
// reconcile replay publish every local row except one whose create was
// reported failed; publishing that one would promote its reservation.
func TestOwnershipReplaySkipsRollbackPendingRows(t *testing.T) {
	ctx := context.Background()
	svc, _, _, fc := newRollbackHarness(t, "sb-live", "sb-failed")
	if err := svc.MarkRollbackPending(ctx, "sb-failed"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if len(fc.asserted) != 1 || fc.asserted[0] != "sb-live" {
		t.Fatalf("replay published %v, want only [sb-live]", fc.asserted)
	}
}

// TestReconcileRollbackPendingRetriesUntilDestroyed: while the leader is
// away the destroy fails and the row stays marked; the first pass after a
// leader is back destroys the row and its reservation. Unmarked rows are
// never touched.
func TestReconcileRollbackPendingRetriesUntilDestroyed(t *testing.T) {
	ctx := context.Background()
	svc, st, rt, fc := newRollbackHarness(t, "sb-live", "sb-failed")
	if err := svc.MarkRollbackPending(ctx, "sb-failed"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	fc.setReadErr(cluster.ErrNotLeader)
	svc.reconcileRollbackPending(ctx)
	if got, err := st.Get(ctx, "sb-failed"); err != nil || !got.RollbackPending {
		t.Fatalf("row after a pass with no leader = %+v, %v; want it kept and still marked", got, err)
	}
	if len(rt.destroyIDs) != 0 {
		t.Fatalf("runtime destroyed %v with no leader for the fence, want nothing", rt.destroyIDs)
	}

	fc.setReadErr(nil)
	svc.reconcileRollbackPending(ctx)
	if _, err := st.Get(ctx, "sb-failed"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row after a pass with a leader = %v, want ErrNotFound", err)
	}
	if _, ok := fc.PlacementOf("sb-failed"); ok {
		t.Fatal("reservation of the failed create survived its destroy")
	}
	if _, err := st.Get(ctx, "sb-live"); err != nil {
		t.Fatalf("unmarked row = %v, want it untouched", err)
	}
	if ids, err := st.ListRollbackPendingIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("pending ids after the sweep = %v, %v; want none", ids, err)
	}
	// Nothing left: another pass is a no-op.
	svc.reconcileRollbackPending(ctx)
}

// TestCreateReplayRefusesRollbackPendingRow: an Idempotency-Key retry of a
// create that failed must not be handed the leftover sandbox reconcile is
// about to destroy. It gets a retryable 503 and nothing is created.
func TestCreateReplayRefusesRollbackPendingRow(t *testing.T) {
	ctx := context.Background()
	svc, _, rt, _ := newRollbackHarness(t, "sb-keyed")
	if err := svc.MarkRollbackPending(ctx, "sb-keyed"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-keyed")
	if !errors.Is(err, ErrCreateRollbackPending) || !errors.Is(err, ErrCreateInProgress) {
		t.Fatalf("replay of a rollback-pending create = %v, want ErrCreateRollbackPending (an ErrCreateInProgress)", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime creates = %d, want only the original 1", rt.createCalls)
	}
}

func TestMarkRollbackPendingEdges(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).MarkRollbackPending(ctx, "sb-x"); err != nil {
		t.Fatalf("nil service: %v", err)
	}
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	// No row: the create left nothing to roll back.
	if err := svc.MarkRollbackPending(ctx, "sb-none"); err != nil {
		t.Fatalf("missing row: %v", err)
	}
	_ = st.Close()
	if err := svc.MarkRollbackPending(ctx, "sb-none"); err == nil {
		t.Fatal("mark on a closed store succeeded")
	}
	// A list failure is logged and leaves the next pass to retry.
	svc.reconcileRollbackPending(ctx)
	(*Service)(nil).reconcileRollbackPending(ctx)
}
