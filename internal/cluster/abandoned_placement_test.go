package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// Regression tests for sandboxes left on a deleted node
// (abandoned_placement.go). A live drill force-deleted a worker while one of
// its sandboxes was being deleted: opOrphanOwner skips a deleting placement,
// so the placement stayed on the deleted node, and every DELETE after that
// was forwarded to a node with no InternalURL and answered 503 until the
// cluster was torn down.

// abandonedSetup seeds one sandbox on owner in one of the states a node can
// hold a sandbox in when it is deleted.
type abandonedSetup func(t *testing.T, c *Cluster, id, owner string)

func abandonedPlace(t *testing.T, c *Cluster, id, owner string) {
	t.Helper()
	applyRaftCommand(t, c, command{
		Op: opPlace, SandboxID: id, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner,
		IncarnationID: "inc-" + id, Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
}

func abandonedRunState(state RunState) abandonedSetup {
	return func(t *testing.T, c *Cluster, id, owner string) {
		abandonedPlace(t, c, id, owner)
		applyRaftCommand(t, c, command{Op: opSetRunStates, RunStates: []RunStateReport{
			{SandboxID: id, IncarnationID: "inc-" + id, OwnerNodeID: owner, State: state},
		}})
	}
}

// abandonedBeginDelete is the owner's delete fence, committed before the
// node was deleted: the live case.
func abandonedBeginDelete(t *testing.T, c *Cluster, id, owner string) {
	t.Helper()
	applyRaftCommand(t, c, command{
		Op: opBeginDelete, SandboxID: id, ExpectedOwnerNodeID: owner, ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID: "inc-" + id, ExpiresUnix: placementDeleteExpiryUnix(),
	})
}

func abandonedDeleting(t *testing.T, c *Cluster, id, owner string) {
	abandonedPlace(t, c, id, owner)
	abandonedBeginDelete(t, c, id, owner)
}

func abandonedRecreate(t *testing.T, c *Cluster, id, owner string) {
	placeFailoverPlacement(t, c, id, owner)
}

func abandonedRecreateDeleting(t *testing.T, c *Cluster, id, owner string) {
	placeFailoverPlacement(t, c, id, owner)
	abandonedBeginDelete(t, c, id, owner)
}

func abandonedReserved(t *testing.T, c *Cluster, id, owner string) {
	t.Helper()
	applyRaftCommand(t, c, command{
		Op: opReserve, SandboxID: id, OwnerNodeID: owner, IncarnationID: "inc-" + id,
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 256}, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
}

// What a node delete leaves of one sandbox.
const (
	handOffGone       = "gone"
	handOffOrphaned   = "orphaned"
	handOffReassigned = "reassigned"
)

// abandonedStates is every state a deleted node can hold a sandbox in, and
// what the delete must leave of it.
var abandonedStates = []struct {
	name  string
	setup abandonedSetup
	want  string
}{
	{name: "running", setup: abandonedRunState(RunStateRunning), want: handOffOrphaned},
	{name: "stopped", setup: abandonedRunState(RunStateSuspended), want: handOffOrphaned},
	{name: "failed", setup: abandonedRunState(RunStateFailed), want: handOffOrphaned},
	{name: "no run state reported", setup: abandonedPlace, want: handOffOrphaned},
	// The live case: a DELETE had fenced it, and the node went before the
	// delete finished.
	{name: "deleting", setup: abandonedDeleting, want: handOffGone},
	{name: "deleting with the recreate policy", setup: abandonedRecreateDeleting, want: handOffGone},
	{name: "reservation", setup: abandonedReserved, want: handOffGone},
	{name: "recreate policy", setup: abandonedRecreate, want: handOffReassigned},
}

func abandonedID(i int) string { return fmt.Sprintf("sb-abandoned-%d", i) }

// requireHandOff checks one sandbox against what the node delete must leave
// of it.
func requireHandOff(t *testing.T, c *Cluster, name, id, owner, want string) {
	t.Helper()
	p, ok := c.fsm.get(id)
	switch want {
	case handOffGone:
		if ok {
			t.Fatalf("%s: placement = %+v, want it deleted with the node", name, p)
		}
	case handOffOrphaned:
		if !ok || !p.IsOrphaned() || p.OrphanedOwnerNodeID != owner || p.IsDeleting() {
			t.Fatalf("%s: placement = %+v (found %v), want orphaned from %s", name, p, ok, owner)
		}
	case handOffReassigned:
		if !ok || p.OwnerNodeID != c.nodeID || p.IsOrphaned() {
			t.Fatalf("%s: placement = %+v (found %v), want it moved to %s", name, p, ok, c.nodeID)
		}
	}
}

// TestDeleteNodeHandsOffEveryPlacementItHeld is the live case as a unit
// test: aerolvm delete node --force on a worker holding a sandbox in every
// state. Nothing may stay on the deleted node, a deleting sandbox's delete
// is finished, and the counts report what really happened. Then a DELETE of
// each orphan deletes it, and a second DELETE finds nothing.
func TestDeleteNodeHandsOffEveryPlacementItHeld(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-abandoned-handoff")
	defer cleanup()
	ctx := context.Background()
	const owner = "wkr-force-deleted"
	wantOrphaned, wantReassigned := 0, 0
	for i, st := range abandonedStates {
		st.setup(t, c, abandonedID(i), owner)
		switch st.want {
		case handOffOrphaned:
			wantOrphaned++
		case handOffReassigned:
			wantReassigned++
		}
	}

	res, err := c.DeleteNode(ctx, owner, true)
	if err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if !res.Denied || res.Orphaned != wantOrphaned || res.Reassigned != wantReassigned {
		t.Fatalf("DeleteNode = %+v, want denied, %d orphaned and %d reassigned", res, wantOrphaned, wantReassigned)
	}
	if n := c.fsm.ownedCount(owner); n != 0 {
		t.Fatalf("the deleted node still owns %d placements", n)
	}
	for i, st := range abandonedStates {
		requireHandOff(t, c, st.name, abandonedID(i), owner, st.want)
	}
	if bad := checkFSMInvariants(c.nodeID, c.fsm, time.Now().Unix()); len(bad) > 0 {
		t.Fatalf("FSM invariants broken: %v", bad)
	}

	// A retried delete finds nothing left to hand off.
	res, err = c.DeleteNode(ctx, owner, false)
	if err != nil || !res.AlreadyDeleted || res.Orphaned != 0 || res.Reassigned != 0 {
		t.Fatalf("repeat DeleteNode = %+v %v", res, err)
	}

	// The DELETE a client sends next: a server deletes each orphan, and the
	// same call again (a retry, or a duplicate in flight) changes nothing.
	for i, st := range abandonedStates {
		if st.want != handOffOrphaned {
			continue
		}
		id := abandonedID(i)
		p, _ := c.fsm.get(id)
		if !PlacementAbandoned(c, p) {
			t.Fatalf("%s: orphan of a deleted node not seen as abandoned: %+v", st.name, p)
		}
		for attempt := range 2 {
			if err := c.DeleteAbandonedPlacement(ctx, p); err != nil {
				t.Fatalf("%s: DELETE %d: %v", st.name, attempt+1, err)
			}
			if got, ok := c.fsm.get(id); ok {
				t.Fatalf("%s: DELETE %d left %+v", st.name, attempt+1, got)
			}
		}
	}
	if bad := checkFSMInvariants(c.nodeID, c.fsm, time.Now().Unix()); len(bad) > 0 {
		t.Fatalf("FSM invariants broken after the deletes: %v", bad)
	}
}

// The dead-owner loop shares the eviction. A node that only died may be cut
// off but still finishing its delete, so its fence stays for the TTL; a
// deleted node whose delete never ran the eviction (the backstop) has its
// delete finished like the operator path does. Either way a deleting
// placement is never counted as orphaned.
func TestEvictionFinishesOnlyADeletedNodesDeletes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	cases := []struct {
		name          string
		deleted       bool
		wantDeleting  bool
		wantOrphaned  int
		wantOwnedLeft int
	}{
		{name: "deleted node", deleted: true, wantDeleting: false, wantOrphaned: 1, wantOwnedLeft: 0},
		{name: "node that only died", deleted: false, wantDeleting: true, wantOrphaned: 1, wantOwnedLeft: 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newEvictFenceCluster(t, fmt.Sprintf("srv-abandoned-evict-%d", i))
			defer cleanup()
			const owner = "wkr-gone"
			abandonedDeleting(t, c, "sb-deleting", owner)
			abandonedPlace(t, c, "sb-running", owner)
			if tc.deleted {
				denyNodeForTest(t, c, owner)
			}

			_, orphaned, err := c.evictOwnerPlacements(context.Background(), owner)
			if err != nil {
				t.Fatalf("evictOwnerPlacements: %v", err)
			}
			if orphaned != tc.wantOrphaned {
				t.Fatalf("orphaned = %d, want %d: a deleting placement is not orphaned", orphaned, tc.wantOrphaned)
			}
			p, ok := c.fsm.get("sb-deleting")
			if tc.wantDeleting != ok || (ok && (!p.IsDeleting() || p.OwnerNodeID != owner)) {
				t.Fatalf("deleting placement = %+v (found %v), want found=%v and still on %s", p, ok, tc.wantDeleting, owner)
			}
			if n := c.fsm.ownedCount(owner); n != tc.wantOwnedLeft {
				t.Fatalf("owned left = %d, want %d", n, tc.wantOwnedLeft)
			}
			if p, _ := c.fsm.get("sb-running"); !p.IsOrphaned() {
				t.Fatalf("running placement = %+v, want orphaned", p)
			}
		})
	}
}

// One delete the eviction cannot finish does not stop the rest. A deleting
// placement with no lifetime ID cannot take the exact delete, so finishing
// it fails every time; before, that error ended the eviction, and the
// node's other sandboxes were never handed off (and the operator's node
// delete failed on every retry). Now that one sandbox is logged and left,
// and the rest of the hand-off runs. It sorts first, so it is tried first.
func TestEvictionSkipsADeleteItCannotFinish(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-abandoned-skip")
	defer cleanup()
	const owner, stuck = "wkr-skip-deleted", "sb-0-no-lifetime"
	applyRaftCommand(t, c, command{Op: opPlace, SandboxID: stuck, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner,
		Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	applyRaftCommand(t, c, command{Op: opBeginDelete, SandboxID: stuck, ExpectedOwnerNodeID: owner, ExpectedOwnerNodeIDSet: true,
		ExpiresUnix: placementDeleteExpiryUnix()})
	if p, _ := c.fsm.get(stuck); !p.IsDeleting() || p.IncarnationID != "" {
		t.Fatalf("precondition: %+v, want a deleting placement with no lifetime ID", p)
	}
	abandonedDeleting(t, c, "sb-1-deleting", owner)
	abandonedPlace(t, c, "sb-2-running", owner)
	var mu sync.Mutex
	var steps []string
	c.evictDeadOwnerStepHook = func(step evictDeadOwnerStep, id string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, fmt.Sprintf("%v:%s", step, id))
	}

	res, err := c.DeleteNode(context.Background(), owner, true)
	if err != nil {
		t.Fatalf("DeleteNode: %v: one delete it cannot finish stopped the hand-off", err)
	}
	if res.Orphaned != 1 {
		t.Fatalf("DeleteNode = %+v, want the running sandbox orphaned", res)
	}
	if p, ok := c.fsm.get(stuck); !ok || !p.IsDeleting() || p.OwnerNodeID != owner {
		t.Fatalf("skipped placement = %+v (found %v), want it left deleting on %s", p, ok, owner)
	}
	requireHandOff(t, c, "deleting", "sb-1-deleting", owner, handOffGone)
	requireHandOff(t, c, "running", "sb-2-running", owner, handOffOrphaned)
	// The stuck one was tried first, and the hand-off went on past it.
	mu.Lock()
	got := strings.Join(steps, " ")
	mu.Unlock()
	want := fmt.Sprintf("%v:%s %v:sb-1-deleting %v:", evictStepFinishDelete, stuck, evictStepFinishDelete, evictStepOrphan)
	if !strings.HasPrefix(got, want) {
		t.Fatalf("eviction steps = %q, want them to start %q", got, want)
	}
	if bad := checkFSMInvariants(c.nodeID, c.fsm, time.Now().Unix()); len(bad) > 0 {
		t.Fatalf("FSM invariants broken: %v", bad)
	}
}

// The backstop through the loop itself: the deny landed and the eviction
// never ran. The leader's dead-owner tick finishes the delete.
func TestDeadOwnerLoopFinishesADeletedNodesDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-abandoned-loop")
	defer cleanup()
	const owner = "wkr-half-deleted"
	abandonedDeleting(t, c, "sb-left-deleting", owner)
	denyNodeForTest(t, c, owner)
	c.cfg.ClusterDeadOwnerGrace = time.Millisecond
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.reconcileDeadOwners(context.Background())
		if _, ok := c.fsm.get("sb-left-deleting"); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p, _ := c.fsm.get("sb-left-deleting")
	t.Fatalf("deleting placement of a deleted node = %+v, want deleted", p)
}

// TestDeleteAbandonedPlacement pins the server-side delete a client's DELETE
// reaches: only a placement left on a deleted node goes, each round is the
// exact owner+incarnation delete, and a race with the leader's hand-off or a
// new lifetime under the same ID is settled by reading again.
func TestDeleteAbandonedPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-abandoned-delete")
	defer cleanup()
	ctx := context.Background()
	const deleted, died, live = "wkr-deleted", "wkr-died", "wkr-live"
	denyNodeForTest(t, c, deleted)
	orphan := func(t *testing.T, id, owner string) {
		abandonedPlace(t, c, id, owner)
		applyRaftCommand(t, c, command{Op: opOrphanOwner, NodeID: owner})
	}

	cases := []struct {
		name  string
		seed  func(t *testing.T, id string)
		arg   func(t *testing.T, id string) Placement // what the caller read
		after func(t *testing.T, id string)           // a write that lands before the delete
		want  error
		gone  bool
		check func(t *testing.T, id string)
	}{
		{name: "still on the deleted node", seed: func(t *testing.T, id string) { abandonedPlace(t, c, id, deleted) }, gone: true},
		{name: "deleting on the deleted node", seed: func(t *testing.T, id string) { abandonedDeleting(t, c, id, deleted) }, gone: true},
		{name: "orphaned from the deleted node", seed: func(t *testing.T, id string) { orphan(t, id, deleted) }, gone: true},
		{name: "orphaned from a node that only died", seed: func(t *testing.T, id string) { orphan(t, id, died) }, want: ErrPlacementNotAbandoned},
		{name: "on a live node", seed: func(t *testing.T, id string) { abandonedPlace(t, c, id, live) }, want: ErrPlacementNotAbandoned},
		{name: "a reservation on the deleted node", seed: func(t *testing.T, id string) { abandonedReserved(t, c, id, deleted) }, want: ErrPlacementNotAbandoned},
		{
			// The leader orphaned it between the caller's read and its
			// write: the first round's delete names the old owner and
			// changes nothing, the second deletes the orphan.
			name: "orphaned since it was read",
			seed: func(t *testing.T, id string) { abandonedPlace(t, c, id, deleted) },
			after: func(t *testing.T, id string) {
				applyRaftCommand(t, c, command{Op: opOrphanOwner, NodeID: deleted})
			},
			gone: true,
		},
		{
			// A recreate retry moved it to a live node first: that node owns
			// it now, and the client's retry is routed there.
			name: "moved to a live node since it was read",
			seed: func(t *testing.T, id string) { orphan(t, id, deleted) },
			after: func(t *testing.T, id string) {
				// The write retryOrphan sends.
				applyRaftCommand(t, c, command{
					Op: opReassign, SandboxID: id, OwnerNodeID: live, OwnerAPIURL: "http://" + live,
					ExpectedIncarnationID: "inc-" + id, ExpectedOwnerNodeIDSet: true, ReassignCause: reassignCauseFailover,
				})
			},
			want: ErrPlacementNotAbandoned,
		},
		{
			// The ID was deleted and reused: the new lifetime is not this
			// delete's, and is left alone.
			name: "a new lifetime under the same ID",
			seed: func(t *testing.T, id string) { abandonedPlace(t, c, id, deleted) },
			after: func(t *testing.T, id string) {
				p, _ := c.fsm.get(id)
				applyRaftCommand(t, c, command{Op: opDelete, SandboxID: id, ExpectedOwnerNodeID: deleted, ExpectedOwnerNodeIDSet: true, ExpectedIncarnationID: p.IncarnationID})
				applyRaftCommand(t, c, command{Op: opPlace, SandboxID: id, OwnerNodeID: live, IncarnationID: "inc-new-" + id})
			},
			check: func(t *testing.T, id string) {
				if p, ok := c.fsm.get(id); !ok || p.IncarnationID != "inc-new-"+id || p.OwnerNodeID != live {
					t.Fatalf("new lifetime = %+v (found %v), want it untouched", p, ok)
				}
			},
		},
		{
			name: "already deleted",
			seed: func(t *testing.T, id string) { abandonedPlace(t, c, id, deleted) },
			after: func(t *testing.T, id string) {
				applyRaftCommand(t, c, command{Op: opDelete, SandboxID: id, ExpectedOwnerNodeID: deleted, ExpectedOwnerNodeIDSet: true, ExpectedIncarnationID: "inc-" + id})
			},
			gone: true,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("sb-abandoned-del-%d", i)
			tc.seed(t, id)
			p, _ := c.fsm.get(id)
			if tc.after != nil {
				tc.after(t, id)
			}
			err := c.DeleteAbandonedPlacement(ctx, p)
			if !errors.Is(err, tc.want) {
				t.Fatalf("DeleteAbandonedPlacement = %v, want %v", err, tc.want)
			}
			_, found := c.fsm.get(id)
			if tc.gone && found {
				t.Fatal("placement still there")
			}
			if tc.want != nil && !found {
				t.Fatal("a refused delete removed the placement")
			}
			if tc.check != nil {
				tc.check(t, id)
			}
		})
	}
	if err := c.DeleteAbandonedPlacement(ctx, Placement{SandboxID: "sb-x"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("no lifetime = %v, want ErrIncarnationConflict", err)
	}
}

// Concurrent duplicate DELETEs of one abandoned sandbox all succeed or find
// it gone; none fails, and the placement goes exactly once.
func TestDeleteAbandonedPlacementConcurrentDuplicates(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newEvictFenceCluster(t, "srv-abandoned-dup")
	defer cleanup()
	const owner = "wkr-dup-deleted"
	abandonedDeleting(t, c, "sb-dup", owner)
	denyNodeForTest(t, c, owner)
	p, _ := c.fsm.get("sb-dup")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.DeleteAbandonedPlacement(context.Background(), p)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("duplicate DELETE: %v", err)
		}
	}
	if _, ok := c.fsm.get("sb-dup"); ok {
		t.Fatal("placement still there")
	}
}

func TestPlacementAbandonedNeedsADenySet(t *testing.T) {
	// Noop has no deny set: single-node mode never sees an abandoned
	// placement, and never asks a server to delete one.
	n := NewNoop("self", "http://self", "")
	if NodeDeleted(n, "wkr") || PlacementAbandoned(n, Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: "wkr"}) {
		t.Fatal("Noop reported a deleted node")
	}
	if _, ok := any(n).(AbandonedPlacementDeleter); ok {
		t.Fatal("Noop must not delete placements for other nodes")
	}
	c := nodeDetailCluster(t)
	applyOp(t, c.fsm, denyCmd("wkr", 1))
	for _, tc := range []struct {
		p    Placement
		want bool
	}{
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: "wkr"}, true},
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerState: PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "wkr"}, true},
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerState: PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "other"}, false},
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerState: PlacementOwnerStateOrphaned}, false},
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: "other"}, false},
		{Placement{SandboxID: "sb", IncarnationID: "inc", OwnerNodeID: "wkr", State: PlacementStateReserved}, false},
		{Placement{SandboxID: "sb", OwnerNodeID: "wkr"}, false},
	} {
		if got := PlacementAbandoned(c, tc.p); got != tc.want {
			t.Fatalf("PlacementAbandoned(%+v) = %v, want %v", tc.p, got, tc.want)
		}
	}
	if NodeDeleted(c, " ") || !NodeDeleted(c, " wkr ") {
		t.Fatal("NodeDeleted disagrees with the deny set")
	}
}

// TestDeleteNodeHandOffSurvivesALeaderChange runs the node delete on three
// Raft servers and moves leadership away in the middle of it, just before
// the leader finishes the deleted node's delete. Whatever the first call
// answers, a retry on the new leader finishes the hand-off; every server then
// holds the same state, a server restarted from its own log replays to it,
// and a DELETE sent to a follower deletes the orphan on every server.
func TestDeleteNodeHandOffSurvivesALeaderChange(t *testing.T) {
	fc := newFaultCluster(t, "abn", 3)
	for _, s := range fc.up() {
		serveAuthoritativeByIDs(s.cluster())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*faultWait)
	defer cancel()
	const owner = "wkr-abn-deleted"
	old := fc.leader()
	lc := old.cluster()
	abandonedDeleting(t, lc, "sb-abn-deleting", owner)
	abandonedRunState(RunStateRunning)(t, lc, "sb-abn-running", owner)
	abandonedRunState(RunStateSuspended)(t, lc, "sb-abn-stopped", owner)
	abandonedReserved(t, lc, "sb-abn-reserved", owner)
	fc.settle()

	var moved sync.Once
	lc.evictDeadOwnerStepHook = func(step evictDeadOwnerStep, _ string) {
		if step == evictStepFinishDelete {
			moved.Do(func() { fc.transferLeadership(nil) })
		}
	}
	if _, err := lc.DeleteNode(ctx, owner, true); err != nil {
		t.Logf("delete across the leader change: %v (the retry finishes it)", err)
	}
	if fc.leader() == old {
		t.Fatal("leadership never moved during the delete")
	}
	err := retryLeaderChange(ctx, 50*time.Millisecond, func(ctx context.Context) error {
		_, err := fc.leader().cluster().DeleteNode(ctx, owner, true)
		return err
	})
	if err != nil {
		t.Fatalf("retried DeleteNode on the new leader: %v", err)
	}

	want := map[string]string{
		"sb-abn-deleting": handOffGone,
		"sb-abn-running":  handOffOrphaned,
		"sb-abn-stopped":  handOffOrphaned,
		"sb-abn-reserved": handOffGone,
	}
	requireAll := func(context string) {
		t.Helper()
		fc.requireInvariants(context)
		fc.requireIdenticalServers(context)
		for _, s := range fc.up() {
			c := s.cluster()
			for id, w := range want {
				requireHandOff(t, c, context+" on "+s.id, id, owner, w)
			}
			if n := c.fsm.ownedCount(owner); n != 0 {
				t.Fatalf("%s: %s says the deleted node still owns %d", context, s.id, n)
			}
		}
	}
	requireAll("after the node delete")

	// The client's DELETE, taken by a follower: the write goes to the
	// leader, and every server drops the orphan.
	var follower *faultServer
	for _, s := range fc.up() {
		if s != fc.leader() {
			follower = s
			break
		}
	}
	fol := follower.cluster()
	for _, id := range []string{"sb-abn-running", "sb-abn-stopped"} {
		p, _ := fol.fsm.get(id)
		err := retryLeaderChange(ctx, 50*time.Millisecond, func(ctx context.Context) error {
			return fol.DeleteAbandonedPlacement(ctx, p)
		})
		if err != nil {
			t.Fatalf("DELETE %s through a follower: %v", id, err)
		}
		want[id] = handOffGone
	}
	fc.settle()
	requireAll("after the DELETEs")

	// Replay: a server restarted on its own log rebuilds the same state.
	fc.restartServer(follower, 0)
	requireAll("after a restart replayed the log")
}

// serveAuthoritativeByIDs stands in for the v1 route a follower's
// authoritative read reaches on the leader (pkg/api/v1
// clusterInternalPlacementsByIDs): the harness runs no API server.
func serveAuthoritativeByIDs(c *Cluster) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PublicInternalPlacementsByIDsPath, func(w http.ResponseWriter, r *http.Request) {
		if c.raft.raft.State() != raft.Leader {
			http.Error(w, "cluster: not leader", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.fsm.placementsByIDs(req.IDs))
	})
	c.AttachInternalHandler(mux)
}

// With no leader to take the write, the eviction's finish step and the
// server-side delete change nothing: the placement stays for the retry (the
// operator's, the dead-owner loop's or the client's). The finish step skips
// that one sandbox, and the orphan step after it fails the same way, so the
// eviction reports the error and orphans nothing.
func TestAbandonedDeletesFailClosedWithoutALeader(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	lone, cleanup := newTestCluster(t, "srv-abandoned-lone", false, nil)
	defer cleanup()
	const owner = "wkr-lone-deleted"
	applyOp(t, lone.fsm, command{Op: opPlace, SandboxID: "sb-lone-deleting", OwnerNodeID: owner, IncarnationID: "inc-lone-deleting"})
	applyOp(t, lone.fsm, command{Op: opBeginDelete, SandboxID: "sb-lone-deleting", ExpectedOwnerNodeID: owner, ExpectedOwnerNodeIDSet: true, ExpectedIncarnationID: "inc-lone-deleting", ExpiresUnix: placementDeleteExpiryUnix()})
	applyOp(t, lone.fsm, command{Op: opPlace, SandboxID: "sb-lone-running", OwnerNodeID: owner, IncarnationID: "inc-lone-running"})
	applyOp(t, lone.fsm, denyCmd(owner, 1))
	ctx := context.Background()

	if _, _, err := lone.evictOwnerPlacements(ctx, owner); err == nil {
		t.Fatal("eviction with no leader reported success")
	}
	if p, ok := lone.fsm.get("sb-lone-deleting"); !ok || !p.IsDeleting() || p.OwnerNodeID != owner {
		t.Fatalf("deleting placement = %+v (found %v), want it kept for the retry", p, ok)
	}
	if p, _ := lone.fsm.get("sb-lone-running"); p.IsOrphaned() {
		t.Fatal("the eviction orphaned a placement with no leader")
	}
	p, _ := lone.fsm.get("sb-lone-running")
	if err := lone.DeleteAbandonedPlacement(ctx, p); err == nil {
		t.Fatal("delete with no leader reported success")
	}
	if _, ok := lone.fsm.get("sb-lone-running"); !ok {
		t.Fatal("a failed delete removed the placement")
	}
}
