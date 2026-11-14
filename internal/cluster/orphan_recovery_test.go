package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// applyOrFail applies cmd to fsm and fails on an error answer.
func applyOrFail(t *testing.T, fsm *placementFSM, cmd command) {
	t.Helper()
	raw, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Data: raw}); got != nil {
		if err, ok := got.(error); ok {
			t.Fatalf("apply %v: %v", cmd.Op, err)
		}
	}
}

func orphanedRecoveryIDs(fsm *placementFSM) []string {
	keys, _ := fsm.orphanedRecoveryPage(orphanKey{}, 1000)
	return keyIDs(keys)
}

// quietOrphanLoop stops c's own orphan loop and waits out a pass it may
// be in, so a test's passes are the only ones.
func quietOrphanLoop(c *Cluster) {
	if c.orphanRetryLoopStop != nil {
		c.orphanRetryLoopStop()
	}
	c.orphanRetry.mu.Lock()
	c.orphanRetry.mu.Unlock() //nolint:staticcheck // waits for a pass in flight
}

func keyIDs(keys []orphanKey) []string {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.id)
	}
	return ids
}

// applyOrphanAt applies cmd as an entry appended at unix, the time the FSM
// stamps on what it changes.
func applyOrphanAt(t *testing.T, fsm *placementFSM, unix int64, cmd command) {
	t.Helper()
	raw, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := fsm.Apply(&raft.Log{Data: raw, AppendedAt: time.Unix(unix, 0)}); got != nil {
		if err, ok := got.(error); ok {
			t.Fatalf("apply %v: %v", cmd.Op, err)
		}
	}
}

// The backlog index holds exactly the orphaned placements that want a
// failover recreate (R14), through every way a row is orphaned, given an
// owner again or deleted, and a snapshot restore rebuilds it.
func TestOrphanedRecoveryIndex(t *testing.T) {
	fsm := newPlacementFSM()
	recreate := &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	plain := &models.CreateSandboxRequest{Image: "alpine"}
	for _, p := range []struct {
		id   string
		spec *models.CreateSandboxRequest
	}{{"sb-a", recreate}, {"sb-b", recreate}, {"sb-c", recreate}, {"sb-plain", plain}} {
		applyOrFail(t, fsm, command{Op: opPlace, SandboxID: p.id, OwnerNodeID: "dead", IncarnationID: "inc-" + p.id, Spec: p.spec})
	}
	if got := orphanedRecoveryIDs(fsm); len(got) != 0 {
		t.Fatalf("placed rows in the backlog: %v", got)
	}
	// The owner dies with no room anywhere: every row is orphaned, and the
	// recreate-policy ones join the backlog.
	applyOrFail(t, fsm, command{Op: opOrphanOwner, NodeID: "dead"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-a", "sb-b", "sb-c"}) {
		t.Fatalf("after the owner died: %v", got)
	}
	// Paging walks it in order from a cursor.
	page, end := fsm.orphanedRecoveryPage(orphanKey{}, 2)
	if !slices.Equal(keyIDs(page), []string{"sb-a", "sb-b"}) || end {
		t.Fatalf("first page %v end %v", page, end)
	}
	if page, end := fsm.orphanedRecoveryPage(page[1], 2); !slices.Equal(keyIDs(page), []string{"sb-c"}) || !end {
		t.Fatalf("second page %v end %v", page, end)
	}
	// One finds a node; one is deleted.
	applyOrFail(t, fsm, command{Op: opReassign, SandboxID: "sb-a", OwnerNodeID: "fresh", ExpectedIncarnationID: "inc-sb-a",
		ExpectedOwnerNodeIDSet: true, ReassignCause: reassignCauseFailover})
	applyOrFail(t, fsm, command{Op: opDelete, SandboxID: "sb-b", ExpectedIncarnationID: "inc-sb-b"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-c"}) {
		t.Fatalf("after a recovery and a delete: %v", got)
	}
	// A target refusing it for capacity hands it back as an orphan.
	applyOrFail(t, fsm, command{Op: opReassign, SandboxID: "sb-a", ExpectedIncarnationID: "inc-sb-a",
		ExpectedOwnerNodeID: "fresh", ExpectedOwnerNodeIDSet: true})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-a", "sb-c"}) {
		t.Fatalf("after a hand-back: %v", got)
	}

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if got := orphanedRecoveryIDs(restored); !slices.Equal(got, []string{"sb-a", "sb-c"}) || restored.orphanedRecoveryLen() != 2 {
		t.Fatalf("after a restore: %v", got)
	}
}

// The reviewer's case (R14): a worker dies while no node has room, so its
// recreate-policy sandbox is orphaned. The autoscaler then adds a worker
// with room, and the leader's next pass moves the sandbox to it.
func TestFailoverMustRetryAfterCapacityReturns(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-backlog", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	p := placeFailoverPlacement(t, c, "sb-no-capacity", "permanently-dead-worker")
	c.evictDeadOwner(context.Background(), p.OwnerNodeID)
	if after, _ := c.fsm.get(p.SandboxID); !after.IsOrphaned() {
		t.Fatalf("expected an orphan for want of room, got owner %q", after.OwnerNodeID)
	}
	// Still no room: the pass leaves it, and the backlog shows it.
	c.reconcileDeadOwners(context.Background())
	c.retryOrphanedRecoveries(context.Background())
	if after, _ := c.fsm.get(p.SandboxID); !after.IsOrphaned() || failoverRecoveryBacklog.Value() != 1 {
		t.Fatalf("moved with no room: owner %q backlog %d", after.OwnerNodeID, failoverRecoveryBacklog.Value())
	}

	seedGossipView(t, c, []Member{recreateCandidate("new-capacity", config.NodeRoleWorker, 100)})
	before := failoverRecoveryRecovered.Value()
	c.retryOrphanedRecoveries(context.Background())
	after, _ := c.fsm.get(p.SandboxID)
	if after.IsOrphaned() || after.OwnerNodeID != "new-capacity" || after.IncarnationID != p.IncarnationID {
		t.Fatalf("still orphaned after capacity returned: owner=%q orphanedFrom=%q", after.OwnerNodeID, after.OrphanedOwnerNodeID)
	}
	if failoverRecoveryRecovered.Value() != before+1 || failoverRecoveryBacklog.Value() != 0 {
		t.Fatalf("recovered %d (want +1), backlog %d", failoverRecoveryRecovered.Value()-before, failoverRecoveryBacklog.Value())
	}
}

// An orphan whose previous owner is alive (it refused the sandbox for
// capacity, or it came back and may reclaim it) waits first, then moves to
// another node, never back to that one.
func TestOrphanRetryWaitsForALiveOwnerThenGoesElsewhere(t *testing.T) {
	old := orphanRetryAliveWait
	t.Cleanup(func() { orphanRetryAliveWait = old })
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-alive", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	// The refuser has the most room on paper, as a node whose heartbeat is
	// behind its admission does.
	seedGossipView(t, c, []Member{
		recreateCandidate("refuser", config.NodeRoleWorker, 120),
		recreateCandidate("other", config.NodeRoleWorker, 20),
	})
	p := placeFailoverPlacement(t, c, "sb-refused", "refuser")
	// handBackRefusedPlacement's write: the refuser gives it back.
	if err := c.applyCommand(context.Background(), command{Op: opReassign, SandboxID: p.SandboxID,
		ExpectedIncarnationID: p.IncarnationID, ExpectedOwnerNodeID: "refuser", ExpectedOwnerNodeIDSet: true}); err != nil {
		t.Fatal(err)
	}

	orphanRetryAliveWait = time.Hour
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 {
		t.Fatalf("moved %d before the live owner's wait", moved)
	}
	orphanRetryAliveWait = 0
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 1 {
		t.Fatalf("moved %d after the wait, want 1", moved)
	}
	if after, _ := c.fsm.get(p.SandboxID); after.OwnerNodeID != "other" {
		t.Fatalf("owner %q, want other: never back to the node that refused it", after.OwnerNodeID)
	}
}

// One pass walks a backlog bigger than one page, up to the moves its rate
// allows in a tick; the next pass carries on from there.
func TestOrphanRetryPassIsBoundedByTheRate(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-pages", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	n := orphanRetryPage + 3
	for i := range n {
		placeFailoverPlacement(t, c, "sb-"+string(rune('a'+i/26))+string(rune('a'+i%26)), "gone-worker")
	}
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone-worker"}); err != nil {
		t.Fatal(err)
	}
	// Room for all of them: the FSM counts each move against its target
	// until that target's next heartbeat.
	seedGossipView(t, c, []Member{
		recreateCandidate("room-1", config.NodeRoleWorker, 128),
		recreateCandidate("room-2", config.NodeRoleWorker, 128),
		recreateCandidate("room-3", config.NodeRoleWorker, 128),
	})
	c.cfg.ClusterOrphanRetryRate = 50
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 50 {
		t.Fatalf("first pass moved %d, want the rate's 50", moved)
	}
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != n-50 {
		t.Fatalf("second pass moved %d, want the last %d", moved, n-50)
	}
	if c.fsm.orphanedRecoveryLen() != 0 || failoverRecoveryBacklog.Value() != 0 || failoverRecoveryOldest.Value() != 0 {
		t.Fatalf("backlog left: %d (gauges %d, %ds)", c.fsm.orphanedRecoveryLen(), failoverRecoveryBacklog.Value(), failoverRecoveryOldest.Value())
	}
}

// A zone-sized backlog drains in passes that each stay within the rate
// and the time budget, so recovery never takes the whole leader from the
// creates that run alongside it (N6: one page of 64 every 5 s capped it at
// 12.8 sandboxes a second).
func TestOrphanRetryDrainsALargeBacklogWithinItsBudget(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-zone", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	const n = 300
	for i := range n {
		placeFailoverPlacement(t, c, fmt.Sprintf("sb-zone-%03d", i), "lost-zone-worker")
	}
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "lost-zone-worker"}); err != nil {
		t.Fatal(err)
	}
	var room []Member
	for i := range 6 {
		room = append(room, recreateCandidate(fmt.Sprintf("room-%d", i), config.NodeRoleWorker, 512))
	}
	seedGossipView(t, c, room)
	c.cfg.ClusterOrphanRetryRate = 100
	before := failoverRecoveryRecovered.Value()
	total, passes := 0, 0
	for c.fsm.orphanedRecoveryLen() > 0 && passes < 30 {
		started := time.Now()
		moved := c.retryOrphanedRecoveries(context.Background())
		took := time.Since(started)
		passes++
		total += moved
		if moved > 100 {
			t.Fatalf("pass %d moved %d, over the rate's 100", passes, moved)
		}
		// The budget is checked before each move, so a pass may run one
		// move past it.
		if took > orphanRetryBudget+time.Second {
			t.Fatalf("pass %d took %s, budget %s", passes, took, orphanRetryBudget)
		}
	}
	if total != n || failoverRecoveryRecovered.Value()-before != n || c.fsm.orphanedRecoveryLen() != 0 {
		t.Fatalf("moved %d of %d in %d passes (counter +%d), %d left", total, n, passes, failoverRecoveryRecovered.Value()-before, c.fsm.orphanedRecoveryLen())
	}
}

// The backlog is walked oldest orphan first (G1), whatever the IDs, and a
// row orphaned again (handed back) goes to the back.
func TestOrphanedRecoveryOldestFirst(t *testing.T) {
	fsm := newPlacementFSM()
	recreate := &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	for _, p := range []struct{ id, owner string }{{"sb-z", "early"}, {"sb-y", "early"}, {"sb-a", "late"}} {
		applyOrphanAt(t, fsm, 900, command{Op: opPlace, SandboxID: p.id, OwnerNodeID: p.owner, IncarnationID: "inc-" + p.id, Spec: recreate})
	}
	applyOrphanAt(t, fsm, 1000, command{Op: opOrphanOwner, NodeID: "early"})
	applyOrphanAt(t, fsm, 2000, command{Op: opOrphanOwner, NodeID: "late"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-y", "sb-z", "sb-a"}) {
		t.Fatalf("order %v, want the earlier orphans first", got)
	}
	if unix, ok := fsm.orphanedRecoveryOldest(); !ok || unix != 1000 {
		t.Fatalf("oldest %d %v", unix, ok)
	}
	// sb-y finds a node, which refuses it later: orphaned again at 3000.
	applyOrphanAt(t, fsm, 2500, command{Op: opReassign, SandboxID: "sb-y", OwnerNodeID: "fresh", ExpectedIncarnationID: "inc-sb-y",
		ExpectedOwnerNodeIDSet: true, ReassignCause: reassignCauseFailover})
	applyOrphanAt(t, fsm, 3000, command{Op: opReassign, SandboxID: "sb-y", ExpectedIncarnationID: "inc-sb-y",
		ExpectedOwnerNodeID: "fresh", ExpectedOwnerNodeIDSet: true})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-z", "sb-a", "sb-y"}) {
		t.Fatalf("after a hand-back: %v", got)
	}
	// A delete takes it out under its own key.
	applyOrphanAt(t, fsm, 3100, command{Op: opDelete, SandboxID: "sb-z", ExpectedIncarnationID: "inc-sb-z"})
	if got := orphanedRecoveryIDs(fsm); !slices.Equal(got, []string{"sb-a", "sb-y"}) || fsm.orphanedRecoveryLen() != 2 || len(fsm.orphanedRecoveryKeys) != 2 {
		t.Fatalf("after a delete: %v (keys %v)", got, fsm.orphanedRecoveryKeys)
	}
}

// With no room anywhere, a pass looks at no more than orphanRetryScanCap
// rows and returns; the next pass carries on, and one that reaches the end
// starts the next from the oldest. A pass with no time left moves nothing.
func TestOrphanRetryBoundsAWalkThatFindsNoRoom(t *testing.T) {
	oldCap, oldBudget := orphanRetryScanCap, orphanRetryBudget
	t.Cleanup(func() { orphanRetryScanCap, orphanRetryBudget = oldCap, oldBudget })
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-noroom", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	for i := range 5 {
		placeFailoverPlacement(t, c, fmt.Sprintf("sb-noroom-%d", i), "gone")
	}
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone"}); err != nil {
		t.Fatal(err)
	}
	orphanRetryScanCap = 3
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 || c.orphanRetry.after.id != "sb-noroom-2" {
		t.Fatalf("first pass: moved %d, stopped at %q", moved, c.orphanRetry.after.id)
	}
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 || c.orphanRetry.after != (orphanKey{}) {
		t.Fatalf("second pass: moved %d, stopped at %+v, want the end", moved, c.orphanRetry.after)
	}
	// No time left: nothing moves, even with room, and the place is kept.
	seedGossipView(t, c, []Member{recreateCandidate("room", config.NodeRoleWorker, 128)})
	orphanRetryBudget = 0
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 || c.fsm.orphanedRecoveryLen() != 5 {
		t.Fatalf("a pass with no time moved %d", moved)
	}
	if failoverRecoveryBacklog.Value() != 5 || failoverRecoveryOldest.Value() < 0 {
		t.Fatalf("gauges: backlog %d, oldest %ds", failoverRecoveryBacklog.Value(), failoverRecoveryOldest.Value())
	}
}

// Creates keep landing while a backlog drains: each pass gives the leader
// back the rest of its tick, so a create waits at most about one pass's
// budget behind recovery, not the whole drain.
func TestOrphanRetryLeavesRoomForCreates(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-creates", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	const n = 300
	for i := range n {
		placeFailoverPlacement(t, c, fmt.Sprintf("sb-backlog-%03d", i), "lost-zone")
	}
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "lost-zone"}); err != nil {
		t.Fatal(err)
	}
	var room []Member
	for i := range 6 {
		room = append(room, recreateCandidate(fmt.Sprintf("room-%d", i), config.NodeRoleWorker, 512))
	}
	seedGossipView(t, c, room)
	c.cfg.ClusterOrphanRetryRate = 100

	// Foreground creates, one after another, for as long as the drain runs.
	stop := make(chan struct{})
	type result struct {
		n       int
		slowest time.Duration
		err     error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- r
				return
			default:
			}
			started := time.Now()
			err := c.applyCommand(context.Background(), command{Op: opPlace, SandboxID: fmt.Sprintf("sb-create-%04d", i),
				OwnerNodeID: "room-0", IncarnationID: fmt.Sprintf("inc-create-%04d", i), Spec: &models.CreateSandboxRequest{Image: "alpine"}})
			if err != nil {
				r.err = err
				done <- r
				return
			}
			r.n++
			r.slowest = max(r.slowest, time.Since(started))
		}
	}()
	passes := 0
	for c.fsm.orphanedRecoveryLen() > 0 && passes < 30 {
		c.retryOrphanedRecoveries(context.Background())
		passes++
	}
	close(stop)
	r := <-done
	if r.err != nil {
		t.Fatalf("a create failed during the drain: %v", r.err)
	}
	if c.fsm.orphanedRecoveryLen() != 0 {
		t.Fatalf("%d orphans left after %d passes", c.fsm.orphanedRecoveryLen(), passes)
	}
	if r.n == 0 || r.slowest > orphanRetryBudget+2*time.Second {
		t.Fatalf("creates during the drain: %d, slowest %s", r.n, r.slowest)
	}
	t.Logf("%d orphans moved in %d passes alongside %d creates (slowest %s)", n, passes, r.n, r.slowest)
}

// The index keeps one entry per row: the same orphan time again changes
// nothing, a new one re-keys it, and a machine without an index (a zero
// value) answers empty. A row gone before its retry is skipped.
func TestOrphanedRecoveryKeyUpdates(t *testing.T) {
	var f placementFSM
	f.dropOrphanedRecoveryLocked("sb")
	if _, ok := f.orphanedRecoveryOldest(); ok {
		t.Fatal("a zero-value machine has an oldest orphan")
	}
	orphan := func(unix int64) Placement {
		return Placement{OwnerState: PlacementOwnerStateOrphaned, FailoverRecreate: true, OrphanedUnix: unix}
	}
	f.indexOrphanedRecoveryLocked("sb", orphan(5))
	f.indexOrphanedRecoveryLocked("sb", orphan(5))
	f.indexOrphanedRecoveryLocked("sb", orphan(9))
	keys, _ := f.orphanedRecoveryPage(orphanKey{}, 10)
	if len(keys) != 1 || keys[0] != (orphanKey{9, "sb"}) || f.orphanedRecoveryKeys["sb"] != 9 {
		t.Fatalf("keys %v, map %v", keys, f.orphanedRecoveryKeys)
	}
	f.indexOrphanedRecoveryLocked("sb", Placement{OwnerNodeID: "back"})
	if f.orphanedRecoveryLen() != 0 || len(f.orphanedRecoveryKeys) != 0 {
		t.Fatalf("a row with an owner is still indexed: %d", f.orphanedRecoveryLen())
	}

	c, cleanup := newTestClusterWithRole(t, "srv-recovery-gone", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	if moved, stop := c.retryOrphan(context.Background(), "sb-never-placed", time.Now()); moved || stop {
		t.Fatalf("a missing row: moved %v stop %v", moved, stop)
	}
}

// The loop's tick passes on the leader only; a server that is not the
// leader forgets its place, so a new leader starts from the oldest. An
// empty backlog still publishes its gauges.
func TestOrphanRetryTick(t *testing.T) {
	follower := &Cluster{fsm: newPlacementFSM()}
	follower.orphanRetry.after = orphanKey{unix: 1, id: "sb-x"}
	if moved := follower.orphanRetryTick(context.Background()); moved != 0 || follower.orphanRetry.after != (orphanKey{}) {
		t.Fatalf("follower tick: moved %d, place %+v", moved, follower.orphanRetry.after)
	}

	c, cleanup := newTestClusterWithRole(t, "srv-recovery-tick", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	failoverRecoveryBacklog.Set(99)
	failoverRecoveryOldest.Set(99)
	if moved := c.orphanRetryTick(context.Background()); moved != 0 || failoverRecoveryBacklog.Value() != 0 || failoverRecoveryOldest.Value() != 0 {
		t.Fatalf("empty tick: moved %d, gauges %d %d", moved, failoverRecoveryBacklog.Value(), failoverRecoveryOldest.Value())
	}
	seedGossipView(t, c, []Member{recreateCandidate("room", config.NodeRoleWorker, 128)})
	placeFailoverPlacement(t, c, "sb-tick", "gone")
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone"}); err != nil {
		t.Fatal(err)
	}
	if moved := c.orphanRetryTick(context.Background()); moved != 1 {
		t.Fatalf("leader tick moved %d, want 1", moved)
	}
	// A rate of 0 (a Cluster built without config) still moves.
	if got := orphanRetryMoves(0); got != defaultOrphanRetryRate {
		t.Fatalf("moves at rate 0: %d", got)
	}
}

// A write that lands between the retry's read and its move wins: the fenced
// move fails and the retry leaves the row to whoever moved it. A move that
// fails for any other reason ends the pass, and the row stays orphaned for
// the next one.
func TestOrphanRetryLosesRacesAndStopsOnErrors(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-recovery-race", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	quietOrphanLoop(c)
	seedGossipView(t, c, []Member{recreateCandidate("room", config.NodeRoleWorker, 128)})
	p := placeFailoverPlacement(t, c, "sb-race", "gone")
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone"}); err != nil {
		t.Fatal(err)
	}

	// Another path gives it an owner first.
	c.orphanRetryBeforeApply = func(id string) {
		if err := c.applyCommand(context.Background(), command{Op: opReassign, SandboxID: id, OwnerNodeID: "elsewhere",
			ExpectedIncarnationID: p.IncarnationID, ExpectedOwnerNodeIDSet: true}); err != nil {
			t.Errorf("racing move: %v", err)
		}
	}
	if moved := c.retryOrphanedRecoveries(context.Background()); moved != 0 {
		t.Fatalf("counted %d moves of a row another path moved", moved)
	}
	if after, _ := c.fsm.get(p.SandboxID); after.OwnerNodeID != "elsewhere" {
		t.Fatalf("owner %q, want the racing move's", after.OwnerNodeID)
	}

	// A move that fails outright (here: its context is gone) ends the pass.
	q := placeFailoverPlacement(t, c, "sb-fail", "gone-too")
	if err := c.applyCommand(context.Background(), command{Op: opOrphanOwner, NodeID: "gone-too"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.orphanRetryBeforeApply = func(string) { cancel() }
	if moved := c.retryOrphanedRecoveries(ctx); moved != 0 {
		t.Fatalf("moved %d with the context gone", moved)
	}
	if after, _ := c.fsm.get(q.SandboxID); !after.IsOrphaned() {
		t.Fatalf("a failed move changed the row: owner %q", after.OwnerNodeID)
	}
}

// A placement state machine built without its indexes (a zero value)
// reads as an empty backlog.
func TestOrphanedRecoveryIndexZeroValue(t *testing.T) {
	var f placementFSM
	if f.orphanedRecoveryLen() != 0 {
		t.Fatal("zero-value backlog not empty")
	}
	if ids, end := f.orphanedRecoveryPage(orphanKey{}, 10); len(ids) != 0 || !end {
		t.Fatalf("zero-value page %v end %v", ids, end)
	}
	f.indexOrphanedRecoveryLocked("sb", Placement{OwnerState: PlacementOwnerStateOrphaned, FailoverRecreate: true})
	if ids, _ := f.orphanedRecoveryPage(orphanKey{}, 0); ids != nil {
		t.Fatalf("a zero limit returned %v", ids)
	}
	if _, ok := f.orphanedRecoveryOldest(); !ok || f.orphanedRecoveryLen() != 1 {
		t.Fatal("an orphan written into a zero-value machine is not indexed")
	}
}
