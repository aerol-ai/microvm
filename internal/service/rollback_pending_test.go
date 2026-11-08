package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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
// create that failed must not be handed the leftover sandbox. While the
// leader is still away its inline attempt to finish the rollback fails too,
// so it gets a retryable 503, nothing is created, and the row stays marked
// for the reconcile sweep.
func TestCreateReplayRefusesRollbackPendingRow(t *testing.T) {
	ctx := context.Background()
	svc, st, rt, fc := newRollbackHarness(t, "sb-keyed")
	if err := svc.MarkRollbackPending(ctx, "sb-keyed"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	fc.setReadErr(cluster.ErrNotLeader)
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-keyed")
	if !errors.Is(err, ErrCreateRollbackPending) || !errors.Is(err, ErrCreateInProgress) {
		t.Fatalf("replay of a rollback-pending create = %v, want ErrCreateRollbackPending (an ErrCreateInProgress)", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime creates = %d, want only the original 1", rt.createCalls)
	}
	if len(rt.destroyIDs) != 0 {
		t.Fatalf("runtime destroyed %v with no leader for the fence, want nothing", rt.destroyIDs)
	}
	if row, err := st.Get(ctx, "sb-keyed"); err != nil || !row.RollbackPending {
		t.Fatalf("row after the refused retry = %+v, %v; want it kept and still marked", row, err)
	}
}

// TestCreateRetryFinishesPendingRollbackInline: a retry that finds its failed
// create still marked runs the pending destroy itself once the leader is
// back, and then creates afresh in the same request instead of answering 503
// until the next reconcile pass.
func TestCreateRetryFinishesPendingRollbackInline(t *testing.T) {
	ctx := context.Background()
	svc, st, rt, fc := newRollbackHarness(t, "sb-retry")
	old, err := st.Get(ctx, "sb-retry")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.MarkRollbackPending(ctx, "sb-retry"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-retry")
	if err != nil {
		t.Fatalf("retry of a failed create with a leader back = %v, want a fresh create", err)
	}
	if resp.Replayed {
		t.Fatal("retry replayed the failed create's sandbox")
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-retry" {
		t.Fatalf("runtime destroys = %v, want the failed create's one", rt.destroyIDs)
	}
	if rt.createCalls != 2 {
		t.Fatalf("runtime creates = %d, want the original and the fresh one", rt.createCalls)
	}
	row, err := st.Get(ctx, "sb-retry")
	if err != nil || row.RollbackPending || row.AuditIncarnationID == old.AuditIncarnationID {
		t.Fatalf("row after the retry = %+v, %v; want a fresh, unmarked lifetime", row, err)
	}
	if _, ok := fc.PlacementOf("sb-retry"); ok {
		t.Fatal("the failed create's reservation survived the inline rollback")
	}
}

// TestCreateRetryAndRollbackSweepDestroyOnce runs a create retry and the
// reconcile sweep at the same time on one marked row, many times. Whichever
// gets there first destroys the failed create; the other must neither
// destroy it again nor destroy the fresh sandbox the retry made, and the
// retry creates exactly one fresh sandbox.
func TestCreateRetryAndRollbackSweepDestroyOnce(t *testing.T) {
	for round := 0; round < 8; round++ {
		ctx := context.Background()
		id := fmt.Sprintf("sb-race-%d", round)
		svc, st, rt, _ := newRollbackHarness(t, id)
		if err := svc.MarkRollbackPending(ctx, id); err != nil {
			t.Fatalf("mark: %v", err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var retryErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, retryErr = svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, id)
		}()
		go func() {
			defer wg.Done()
			<-start
			svc.reconcileRollbackPending(ctx)
		}()
		close(start)
		wg.Wait()
		if retryErr != nil {
			t.Fatalf("round %d: retry = %v, want a fresh create", round, retryErr)
		}
		if len(rt.destroyIDs) != 1 {
			t.Fatalf("round %d: runtime destroys = %v, want exactly one", round, rt.destroyIDs)
		}
		if rt.createCalls != 2 {
			t.Fatalf("round %d: runtime creates = %d, want the original and one fresh", round, rt.createCalls)
		}
		if row, err := st.Get(ctx, id); err != nil || row.RollbackPending {
			t.Fatalf("round %d: row = %+v, %v; want the fresh, unmarked sandbox", round, row, err)
		}
	}
}

// TestRollbackSweepSparesTheFreshSandbox is the one interleaving the race
// test above can miss: the sweep lists the marked id, a create retry then
// finishes the rollback and creates afresh under the same id, and only then
// does the sweep act on its list. It must find the new row unmarked and leave
// the fresh sandbox alone.
func TestRollbackSweepSparesTheFreshSandbox(t *testing.T) {
	ctx := context.Background()
	const id = "sb-stale-list"
	svc, st, rt, _ := newRollbackHarness(t, id)
	if err := svc.MarkRollbackPending(ctx, id); err != nil {
		t.Fatalf("mark: %v", err)
	}
	var once sync.Once
	svc.testBeforeRollbackSweepDestroy = func(string) {
		once.Do(func() {
			if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, id); err != nil {
				t.Errorf("retry inside the sweep window: %v", err)
			}
		})
	}
	svc.reconcileRollbackPending(ctx)
	if len(rt.destroyIDs) != 1 {
		t.Fatalf("runtime destroys = %v, want only the failed create's (the sweep destroyed the fresh sandbox)", rt.destroyIDs)
	}
	if row, err := st.Get(ctx, id); err != nil || row.RollbackPending {
		t.Fatalf("row after the sweep = %+v, %v; want the fresh sandbox, unmarked", row, err)
	}
}

// TestFinishRollbackPendingFailures: an attempt that cannot get the row's
// lifecycle lock within the rollback budget, or cannot read the row, answers
// ErrCreateRollbackPending and leaves the row marked.
func TestFinishRollbackPendingFailures(t *testing.T) {
	ctx := context.Background()
	restore := createRollbackTimeout
	createRollbackTimeout = 50 * time.Millisecond
	t.Cleanup(func() { createRollbackTimeout = restore })

	svc, st, rt, _ := newRollbackHarness(t, "sb-locked")
	if err := svc.MarkRollbackPending(ctx, "sb-locked"); err != nil {
		t.Fatal(err)
	}
	unlock, err := svc.lifecycleLocks.lockCtx(ctx, "sb-locked")
	if err != nil {
		t.Fatal(err)
	}
	err = svc.FinishRollbackPending(ctx, "sb-locked")
	unlock()
	if !errors.Is(err, ErrCreateRollbackPending) {
		t.Fatalf("attempt while a start or stop holds the lock = %v, want ErrCreateRollbackPending", err)
	}
	if row, err := st.Get(ctx, "sb-locked"); err != nil || !row.RollbackPending || len(rt.destroyIDs) != 0 {
		t.Fatalf("row = %+v, %v, destroys %v; want it kept, marked, not destroyed", row, err, rt.destroyIDs)
	}

	// Nothing there: nothing pending.
	if err := svc.FinishRollbackPending(ctx, "sb-none"); err != nil {
		t.Fatalf("attempt on a missing row = %v, want nil", err)
	}

	broken, brokenStore, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_ = brokenStore.Close()
	if err := broken.FinishRollbackPending(ctx, "sb-x"); !errors.Is(err, ErrCreateRollbackPending) {
		t.Fatalf("attempt on an unreadable store = %v, want ErrCreateRollbackPending", err)
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
