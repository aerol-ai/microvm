package clustercreate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// leaderLossCluster is a placement FSM whose leader can go away. While the
// leader is gone every write and every authoritative read fails, the way a
// Raft apply or a read-index does during an election. While it is there, the
// writes follow the FSM rules the create and destroy paths depend on:
// RecordPlacement promotes (or places), begin-delete and delete check owner
// and incarnation, and AssertOwnership does what Cluster.AssertOwnership does
// with a local row: place it when no placement exists, and promote a
// reservation this node owns.
type leaderLossCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	leaderDown bool
	// dropLeaderOnPromote takes the leader away as the promote starts: the
	// promote fails, and so does every write the rollback then tries.
	dropLeaderOnPromote bool
}

var errNoLeader = fmt.Errorf("%w: election in progress", cluster.ErrNotLeader)

func newLeaderLossCluster(self string) *leaderLossCluster {
	return &leaderLossCluster{Noop: cluster.NewNoop(self, "http://"+self, ""), placements: map[string]cluster.Placement{}}
}

func (c *leaderLossCluster) reserve(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.placements[id] = cluster.Placement{
		SandboxID: id, OwnerNodeID: c.SelfNodeID(), IncarnationID: "inc-" + id,
		State: cluster.PlacementStateReserved, ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
	}
}

func (c *leaderLossCluster) setLeaderDown(down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaderDown = down
}

func (c *leaderLossCluster) placement(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	return p, ok
}

func (c *leaderLossCluster) PlacementOf(id string) (cluster.Placement, bool) { return c.placement(id) }

func (c *leaderLossCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaderDown {
		return nil, errNoLeader
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *leaderLossCluster) RecordPlacement(_ context.Context, id string, spec *models.CreateSandboxRequest, secrets cluster.PlacementSecrets) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dropLeaderOnPromote {
		c.dropLeaderOnPromote = false
		c.leaderDown = true
	}
	if c.leaderDown {
		return errNoLeader
	}
	p, ok := c.placements[id]
	if !ok {
		p = cluster.Placement{SandboxID: id, OwnerNodeID: c.SelfNodeID(), IncarnationID: secrets.IncarnationID}
	}
	p.State = cluster.PlacementStatePlaced
	p.ExpiresUnix = 0
	p.Spec = spec
	c.placements[id] = p
	return nil
}

func (c *leaderLossCluster) AssertOwnership(ctx context.Context, local []cluster.LocalSandboxState) error {
	var firstErr error
	for _, st := range local {
		p, ok := c.placement(st.ID)
		if !ok || (p.IsReserved() && p.OwnerNodeID == c.SelfNodeID()) {
			if err := c.RecordPlacement(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *leaderLossCluster) BeginDeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaderDown {
		return errNoLeader
	}
	p, ok := c.placements[id]
	if !ok {
		return cluster.ErrUnknownSandbox
	}
	if p.IncarnationID != incarnation || p.OwnerNodeID != owner {
		return cluster.ErrReservationConflict
	}
	p.State = cluster.PlacementStateDeleting
	c.placements[id] = p
	return nil
}

func (c *leaderLossCluster) DeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaderDown {
		return errNoLeader
	}
	if p, ok := c.placements[id]; ok && p.IncarnationID == incarnation && p.OwnerNodeID == owner {
		delete(c.placements, id)
	}
	return nil
}

func (c *leaderLossCluster) CancelReservation(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaderDown {
		return errNoLeader
	}
	if p, ok := c.placements[id]; ok && p.IsReserved() {
		delete(c.placements, id)
	}
	return nil
}

// TestFailedPromoteAndRollbackDuringElectionLeavesNothing is plan item C5
// (invariant I8): a create the client was told failed must leave no sandbox
// and no placement once the cluster has a leader again. The promote fails
// because the leader is gone, and so does the rollback's destroy, which needs
// the same leader; the local row stays. Before the fix nothing retried that
// destroy, and the ownership replay then promoted the reservation from the
// leftover row: the failed create became a live, billed sandbox.
func TestFailedPromoteAndRollbackDuringElectionLeavesNothing(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const id = "sb-c5-failed-rollback"
	fc := newLeaderLossCluster("node-a")
	fc.reserve(id)
	rt := newFakeRuntime()
	svc, st := newCreateServiceWithRuntime(t, fc, rt, true)

	fc.dropLeaderOnPromote = true
	_, err := OverlapCreateAndPromote(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, id, OverlapOptions{PromoteWithSpec: true})
	if of, ok := AsOverlapFailure(err); !ok || of.Phase != OverlapPhasePromote || !errors.Is(err, cluster.ErrNotLeader) {
		t.Fatalf("create = %v, want a promote failure from the lost leader", err)
	}
	// The rollback could not reach a leader either, so the local row and
	// the runtime are still here: that much is expected.
	if _, err := st.Get(ctx, id); err != nil {
		t.Fatalf("local row after the failed rollback = %v; this test needs the rollback to have failed", err)
	}

	// A leader is elected. The boot-time ownership replay and the periodic
	// reconcile run, in that order (a restart, or just the next ticks).
	fc.setLeaderDown(false)
	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Errorf("ReplayClusterOwnership: %v", err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Errorf("Reconcile: %v", err)
	}

	if p, ok := fc.placement(id); ok {
		t.Errorf("placement after replay and reconcile = state %q, want none (the failed create came back)", p.State)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("local row after replay and reconcile = %v, want ErrNotFound", err)
	}
	if states, _ := rt.ListManaged(ctx); states[id] != nil {
		t.Errorf("runtime instance still running after replay and reconcile: %+v", states[id])
	}
}

// TestRetractReservedCreateKeepsLiveRowForReconcile is the seal-leg twin of
// the promote case: the create leg made a sandbox, the seal failed, and the
// rollback's destroy finds no leader. The row is marked before the destroy,
// so the replay does not publish it and reconcile destroys it, reservation
// included, once a leader is back.
func TestRetractReservedCreateKeepsLiveRowForReconcile(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const id = "sb-c5-seal-failed"
	fc := newLeaderLossCluster("node-a")
	fc.reserve(id)
	rt := newFakeRuntime()
	svc, st := newCreateServiceWithRuntime(t, fc, rt, true)
	if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, id); err != nil {
		t.Fatalf("create leg: %v", err)
	}

	fc.setLeaderDown(true)
	retractReservedCreate(ctx, svc, fc, logger, id, nil)
	row, err := st.Get(ctx, id)
	if err != nil || !row.RollbackPending {
		t.Fatalf("row after a rollback with no leader = %+v, %v; want it kept and marked rollback-pending", row, err)
	}

	fc.setLeaderDown(false)
	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if p, _ := fc.placement(id); !p.IsReserved() {
		t.Fatalf("replay published the failed create: placement state %q", p.State)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if p, ok := fc.placement(id); ok {
		t.Fatalf("placement after reconcile = state %q, want none", p.State)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("local row after reconcile = %v, want ErrNotFound", err)
	}
}

// TestOverlapRetryOfFailedCreateIsNotReplayed: a keyed retry routed back to
// the owner while the failed create is still being rolled back must not be
// told the leftover sandbox is its result. It gets the retryable
// ErrCreateRollbackPending (503) and nothing new is created.
func TestOverlapRetryOfFailedCreateIsNotReplayed(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const id = "sb-c5-keyed-retry"
	fc := newLeaderLossCluster("node-a")
	fc.reserve(id)
	rt := newFakeRuntime()
	svc, _ := newCreateServiceWithRuntime(t, fc, rt, true)
	fc.dropLeaderOnPromote = true
	if _, err := OverlapCreateAndPromote(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, id, OverlapOptions{PromoteWithSpec: true}); err == nil {
		t.Fatal("first create succeeded; this test needs the promote and its rollback to fail")
	}
	creates := rt.creates.Load()

	_, err := OverlapCreateAndPromote(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, id, OverlapOptions{PromoteWithSpec: true})
	if !errors.Is(err, service.ErrCreateRollbackPending) {
		t.Fatalf("retry = %v, want ErrCreateRollbackPending", err)
	}
	if got := rt.creates.Load(); got != creates {
		t.Fatalf("runtime creates = %d after the retry, want %d", got, creates)
	}
}

// TestFailedLocalCreatePromoteDuringElectionLeavesNothing is the same story
// on the create path with no reservation (a node-bound local image, and the
// facades' local creates): the promote is the first Raft write, it fails
// without a leader, and so does RollbackLocalCreate's destroy. With no
// placement at all, the replay used to place the leftover row afresh.
func TestFailedLocalCreatePromoteDuringElectionLeavesNothing(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fc := newLeaderLossCluster("node-a")
	rt := newFakeRuntime()
	svc, st := newCreateServiceWithRuntime(t, fc, rt, true)

	fc.dropLeaderOnPromote = true
	if _, err := CreateOnSelectedNode(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "", CreateOptions{}); !errors.Is(err, cluster.ErrNotLeader) {
		t.Fatalf("create = %v, want the promote failure from the lost leader", err)
	}
	rows, err := st.List(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("local rows after the failed rollback = %d, %v; this test needs the rollback to have failed", len(rows), err)
	}
	id := rows[0].ID

	fc.setLeaderDown(false)
	if _, err := svc.ReplayClusterOwnership(ctx); err != nil {
		t.Errorf("ReplayClusterOwnership: %v", err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Errorf("Reconcile: %v", err)
	}
	if p, ok := fc.placement(id); ok {
		t.Errorf("placement after replay and reconcile = state %q, want none (the failed create came back)", p.State)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("local row after replay and reconcile = %v, want ErrNotFound", err)
	}
	if states, _ := rt.ListManaged(ctx); states[id] != nil {
		t.Errorf("runtime instance still running after replay and reconcile: %+v", states[id])
	}
}
