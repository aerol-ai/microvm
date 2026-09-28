package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The missing-local-row sweep used to call Placements(), the unfiltered global
// view. On a worker that is a control-plane GET of every placement in the
// fleet: ~72 MB at 100k sandboxes, past the agent's 16 MiB response cap. The
// decode failed, the agent fell back to an empty cached view, and the sweep
// reclaimed nothing — silently, forever, on all 2,000 workers at once.
//
// These pin the two properties that fix depends on: the sweep reads its own
// rows through the bounded owner page, and an unavailable view skips the sweep
// instead of reading as "nothing is placed."

type ownerPageCluster struct {
	*cluster.Noop
	placements []cluster.Placement
	// authoritative false models a control plane that could not answer.
	authoritative bool
	pageLimit     int
	pageCalls     []cluster.PlacementPageRequest
	fullViewCalls int
	deleteCalls   []string
	nonAdvancing  bool
	// alwaysMore models a control plane whose cursor advances forever.
	alwaysMore     bool
	specByID       map[string]*models.CreateSandboxRequest
	deleteExactErr error
}

func newOwnerPageCluster(placements []cluster.Placement) *ownerPageCluster {
	return &ownerPageCluster{
		Noop:          cluster.NewNoop("node-self", "http://self", ""),
		placements:    placements,
		authoritative: true,
	}
}

// Placements is the unbounded view the sweep must never reach.
func (c *ownerPageCluster) Placements() []cluster.Placement {
	c.fullViewCalls++
	return c.placements
}

func (c *ownerPageCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	c.pageCalls = append(c.pageCalls, req)
	if !c.authoritative {
		return cluster.PlacementPageResponse{Authoritative: false}
	}
	if c.nonAdvancing {
		// A control plane that keeps handing back the same cursor. The token is
		// constant and non-empty, so it never reads as "last page".
		return cluster.PlacementPageResponse{
			Placements:    c.placements[:1],
			NextPageToken: "stuck-cursor",
			Authoritative: true,
		}
	}
	if c.alwaysMore {
		return cluster.PlacementPageResponse{
			Placements:    c.placements[:1],
			NextPageToken: fmt.Sprintf("cursor-%d", len(c.pageCalls)),
			Authoritative: true,
		}
	}
	if c.pageLimit > 0 {
		req.Limit = c.pageLimit
	}
	return stubPlacementPage(c.placements, req)
}

func (c *ownerPageCluster) DeletePlacementExact(_ context.Context, sandboxID, _, _ string) error {
	c.deleteCalls = append(c.deleteCalls, sandboxID)
	return c.deleteExactErr
}

func (c *ownerPageCluster) SpecOf(id string) *models.CreateSandboxRequest {
	if c.specByID == nil {
		return nil
	}
	return c.specByID[id]
}

func placedRow(id, owner string) cluster.Placement {
	return cluster.Placement{
		SandboxID:     id,
		OwnerNodeID:   owner,
		IncarnationID: "inc-" + id,
		OwnerState:    cluster.PlacementOwnerStateActive,
		State:         cluster.PlacementStatePlaced,
	}
}

func TestReconcileReadsOwnRowsThroughTheBoundedOwnerPage(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{
		placedRow("sb-mine-a", "node-self"),
		placedRow("sb-mine-b", "node-self"),
		placedRow("sb-peer-a", "node-peer"),
	})
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if cl.fullViewCalls != 0 {
		t.Fatalf("sweep called the unfiltered Placements() view %d times; at 100k rows that is ~72 MB per worker per sweep", cl.fullViewCalls)
	}
	if len(cl.pageCalls) == 0 {
		t.Fatal("sweep made no PlacementPage call")
	}
	for i, req := range cl.pageCalls {
		if req.OwnerNodeID != "node-self" {
			t.Fatalf("page %d requested OwnerNodeID=%q, want node-self — an unfiltered page is the whole fleet", i, req.OwnerNodeID)
		}
	}
	// Only this node's rows are reclaimable; a peer's row is never ours to delete.
	if len(cl.deleteCalls) != 2 {
		t.Fatalf("delete calls = %v, want both self-owned rows", cl.deleteCalls)
	}
	for _, id := range cl.deleteCalls {
		if id == "sb-peer-a" {
			t.Fatalf("sweep deleted a peer-owned placement: %v", cl.deleteCalls)
		}
	}
}

// An unavailable placement view is indistinguishable from "these sandboxes have
// no placement", and the sweep deletes on exactly that signal. It must skip.
func TestReconcileSkipsSweepWhenPlacementViewUnavailable(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{
		placedRow("sb-mine-a", "node-self"),
		placedRow("sb-mine-b", "node-self"),
	})
	cl.authoritative = false
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.deleteCalls) != 0 {
		t.Fatalf("sweep deleted %v from a non-authoritative view; an unreachable control plane must never read as 'nothing is placed'", cl.deleteCalls)
	}
}

// A partial walk is as dangerous as an empty one: the rows on the pages that
// did arrive would be judged against a local set the sweep never finished
// reading. A cursor that stops advancing aborts the whole sweep.
func TestReconcileSkipsSweepWhenPageCursorStalls(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{
		placedRow("sb-mine-a", "node-self"),
		placedRow("sb-mine-b", "node-self"),
	})
	cl.nonAdvancing = true
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.deleteCalls) != 0 {
		t.Fatalf("sweep acted on a stalled cursor: %v", cl.deleteCalls)
	}
	if len(cl.pageCalls) > maxSelfOwnedReconcilePages {
		t.Fatalf("sweep made %d page calls, want it to bail at the %d budget", len(cl.pageCalls), maxSelfOwnedReconcilePages)
	}
}

// The sweep must follow the cursor to the end, or rows past the first page
// would never be reclaimed — a slow leak rather than a total stall.
func TestReconcileWalksEveryPageOfOwnedRows(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	rows := make([]cluster.Placement, 0, 25)
	for i := range 25 {
		rows = append(rows, placedRow(fmt.Sprintf("sb-%03d", i), "node-self"))
	}
	cl := newOwnerPageCluster(rows)
	cl.pageLimit = 4
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.pageCalls) < 2 {
		t.Fatalf("page calls = %d, want the sweep to follow the cursor across pages", len(cl.pageCalls))
	}
	if len(cl.deleteCalls) != 25 {
		t.Fatalf("reclaimed %d of 25 rows; rows past the first page leak", len(cl.deleteCalls))
	}
}

// Single-node and any non-cluster deployment must not touch this path at all.
func TestReconcileOwnerPageIsNoOpWithoutCluster(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false

	cl := newOwnerPageCluster([]cluster.Placement{placedRow("sb-mine-a", "node-self")})
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.pageCalls) != 0 || len(cl.deleteCalls) != 0 {
		t.Fatalf("single-node reconcile touched the cluster: pages=%d deletes=%v", len(cl.pageCalls), cl.deleteCalls)
	}
}

// A cursor that advances forever is as unusable as one that never does: the
// sweep must give up on a budget rather than page indefinitely against the
// control plane, and must not act on the prefix it managed to read.
func TestReconcileSkipsSweepWhenPageBudgetIsExhausted(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{placedRow("sb-mine-a", "node-self")})
	cl.alwaysMore = true
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.deleteCalls) != 0 {
		t.Fatalf("sweep acted on a never-ending page walk: %v", cl.deleteCalls)
	}
	if len(cl.pageCalls) != maxSelfOwnedReconcilePages {
		t.Fatalf("page calls = %d, want exactly the %d budget", len(cl.pageCalls), maxSelfOwnedReconcilePages)
	}
}

// A sweep racing daemon shutdown must abandon the walk, not finish it against
// a store the daemon is closing.
func TestReconcileStopsPagingOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{placedRow("sb-mine-a", "node-self")})
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.pageCalls) != 0 {
		t.Fatalf("page calls = %d on a cancelled context, want 0", len(cl.pageCalls))
	}
	if len(cl.deleteCalls) != 0 {
		t.Fatalf("sweep deleted %v during shutdown", cl.deleteCalls)
	}
}

// knownIDs is the sweep's local-row snapshot. A placement whose sandbox is in
// it is live and must never be reclaimed.
func TestReconcileKeepsPlacementPresentInKnownIDs(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{
		placedRow("sb-live", "node-self"),
		placedRow("sb-gone", "node-self"),
	})
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{"sb-live": {}})

	if len(cl.deleteCalls) != 1 || cl.deleteCalls[0] != "sb-gone" {
		t.Fatalf("delete calls = %v, want only sb-gone", cl.deleteCalls)
	}
}

// If the local-row recheck itself fails, the sweep cannot tell "row absent"
// from "store unreadable". Deleting on an unreadable store would retire live
// sandboxes wholesale, so the row is skipped and retried next tick.
func TestReconcileSkipsRowWhenLocalRecheckErrors(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	cl := newOwnerPageCluster([]cluster.Placement{placedRow("sb-unknown", "node-self")})
	svc.AttachCluster(cl)

	// A closed store makes Get fail with something other than ErrNotFound.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.deleteCalls) != 0 {
		t.Fatalf("sweep deleted %v while the local store was unreadable", cl.deleteCalls)
	}
}

// A failover-recreate spec normally protects a placement from reclamation —
// the owner watcher will rebuild it elsewhere. A row already in deleting state
// is the exception: someone committed to the delete and crashed mid-finalize,
// so the exact deletion is the only step left. Honouring recreate here would
// strand the anchor forever, which is the vacuum this sweep exists to close.
func TestReconcileDeletesDeletingRowEvenWithRecreateSpec(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	deleting := placedRow("sb-deleting", "node-self")
	deleting.State = cluster.PlacementStateDeleting
	cl := newOwnerPageCluster([]cluster.Placement{
		deleting,
		placedRow("sb-recreate", "node-self"),
	})
	cl.specByID = map[string]*models.CreateSandboxRequest{
		"sb-deleting": {Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}},
		"sb-recreate": {Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}},
	}
	svc.AttachCluster(cl)

	svc.reconcileMissingSelfOwnedPlacements(ctx, map[string]struct{}{})

	if len(cl.deleteCalls) != 1 || cl.deleteCalls[0] != "sb-deleting" {
		t.Fatalf("delete calls = %v, want only sb-deleting (recreate protects sb-recreate, not a committed delete)", cl.deleteCalls)
	}
}
