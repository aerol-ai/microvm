package cluster

import (
	"bytes"
	"context"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func applyAt(t *testing.T, f *placementFSM, index uint64, cmd command) {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Apply(&raft.Log{Index: index, Data: payload}); got != nil {
		t.Fatalf("apply %v@%d: %v", cmd.Op, index, got)
	}
}

func changedIDs(resp PlacementChangesResponse) (present, deleted []string) {
	for _, c := range resp.Changes {
		if c.Deleted {
			deleted = append(deleted, c.SandboxID)
		} else {
			present = append(present, c.SandboxID)
		}
	}
	sort.Strings(present)
	sort.Strings(deleted)
	return present, deleted
}

func place(id, owner string) command {
	return command{Op: opPlace, SandboxID: id, OwnerNodeID: owner, IncarnationID: "inc-" + id}
}

// The feed returns the latest state of every id changed after the cursor,
// deduped: deletes read as Deleted, and the cursor jumps to the FSM version.
func TestPlacementChangesSinceCursor(t *testing.T) {
	f := newPlacementFSM()
	applyAt(t, f, 1, place("sb1", "w1"))
	applyAt(t, f, 2, place("sb2", "w1"))
	applyAt(t, f, 3, command{Op: opDelete, SandboxID: "sb1", ExpectedIncarnationID: "inc-sb1"})

	tests := []struct {
		since       uint64
		wantPresent []string
		wantDeleted []string
		wantNext    uint64
	}{
		{since: 0, wantPresent: []string{"sb2"}, wantDeleted: []string{"sb1"}, wantNext: 3},
		{since: 1, wantPresent: []string{"sb2"}, wantDeleted: []string{"sb1"}, wantNext: 3},
		{since: 2, wantDeleted: []string{"sb1"}, wantNext: 3},
		{since: 3, wantNext: 3},
	}
	for _, tc := range tests {
		resp := f.placementChanges(tc.since)
		if resp.Resnapshot {
			t.Fatalf("since=%d: unexpected resnapshot (floor %d)", tc.since, resp.Floor)
		}
		present, deleted := changedIDs(resp)
		if !equalStrings(present, tc.wantPresent) || !equalStrings(deleted, tc.wantDeleted) || resp.Next != tc.wantNext {
			t.Errorf("since=%d: present=%v deleted=%v next=%d; want %v %v %d",
				tc.since, present, deleted, resp.Next, tc.wantPresent, tc.wantDeleted, tc.wantNext)
		}
	}
	// A deleted placement's change carries the index of its delete.
	for _, c := range f.placementChanges(2).Changes {
		if c.SandboxID == "sb1" && c.Index != 3 {
			t.Fatalf("delete change index = %d, want 3", c.Index)
		}
	}
	// Applies that record nothing (non-placement ops) still advance Next,
	// so a caught-up client does not replay.
	f.mu.Lock()
	f.version = 9
	f.mu.Unlock()
	if resp := f.placementChanges(3); resp.Next != 9 || len(resp.Changes) != 0 {
		t.Fatalf("caught-up cursor: next=%d changes=%d, want 9 and 0", resp.Next, len(resp.Changes))
	}
}

// When the ring evicts past a cursor, that cursor must get resnapshot, never
// a silent gap.
func TestPlacementChangesEvictionForcesResnapshot(t *testing.T) {
	f := newPlacementFSM()
	f.changes = newPlacementChangeLog(2)
	applyAt(t, f, 1, place("a", "w1"))
	applyAt(t, f, 2, place("b", "w1"))
	applyAt(t, f, 3, place("c", "w1")) // evicts a@1: floor = 1

	if resp := f.placementChanges(0); !resp.Resnapshot || resp.Next != 3 {
		t.Fatalf("since=0 after eviction: %+v, want resnapshot with next=3", resp)
	}
	resp := f.placementChanges(1)
	if resp.Resnapshot {
		t.Fatal("since=1 is still covered (floor=1)")
	}
	if present, _ := changedIDs(resp); !equalStrings(present, []string{"b", "c"}) {
		t.Fatalf("since=1 present = %v, want [b c]", present)
	}
}

// Restore rebuilds rows but must not claim to cover history it doesn't
// have: the floor becomes the snapshot version.
func TestPlacementChangesRestoreRaisesFloor(t *testing.T) {
	src := newPlacementFSM()
	applyAt(t, src, 5, place("sb1", "w1"))
	applyAt(t, src, 6, place("sb2", "w1"))
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if resp := dst.placementChanges(5); !resp.Resnapshot || resp.Floor != 6 {
		t.Fatalf("since=5 on a restored FSM: %+v, want resnapshot with floor 6", resp)
	}
	if resp := dst.placementChanges(6); resp.Resnapshot || len(resp.Changes) != 0 {
		t.Fatalf("since=6 (the snapshot version): %+v, want an empty delta", resp)
	}
	applyAt(t, dst, 7, place("sb3", "w1"))
	if present, _ := changedIDs(dst.placementChanges(6)); !equalStrings(present, []string{"sb3"}) {
		t.Fatalf("post-restore delta = %v, want [sb3]", present)
	}
}

// A multi-row op writes several changes at ONE index. Pagination must not
// split that group, or a client could skip half of the op.
func TestPlacementChangesNeverSplitAnIndexGroup(t *testing.T) {
	old := placementChangesByteBudget
	defer func() { placementChangesByteBudget = old }()
	placementChangesByteBudget = 2 * placementChangeSize("sbX")

	f := newPlacementFSM()
	applyAt(t, f, 1, place("sbA", "wX"))
	applyAt(t, f, 2, place("sbB", "wX"))
	applyAt(t, f, 3, place("sbC", "wX"))
	applyAt(t, f, 4, command{Op: opOrphanOwner, NodeID: "wX"}) // 3 changes @4

	first := f.placementChanges(0)
	if first.Next != 2 || len(first.Changes) != 2 {
		t.Fatalf("first page: next=%d changes=%d, want 2 and 2 (budget = 2 rows)", first.Next, len(first.Changes))
	}
	second := f.placementChanges(first.Next)
	if second.Next != 3 {
		t.Fatalf("second page next=%d, want 3 (index 4's group does not fit after 3)", second.Next)
	}
	// Index 4's group (3 rows) is larger than the budget on its own. It is
	// still sent whole, so the feed always makes progress.
	third := f.placementChanges(second.Next)
	if third.Next != 4 || len(third.Changes) != 3 {
		t.Fatalf("third page: next=%d changes=%d, want the whole @4 group (3)", third.Next, len(third.Changes))
	}
	for _, c := range third.Changes {
		if c.Index != 4 || c.Placement == nil || c.Placement.OwnerNodeID != "" {
			t.Fatalf("group change = %+v, want an orphaned row at index 4", c)
		}
	}
}

// An index going backwards (tests applying Index 0, or a restarted log)
// resets the log instead of mis-ordering what it retains.
func TestPlacementChangeLogResetsOnBackwardsIndex(t *testing.T) {
	l := newPlacementChangeLog(8)
	l.record(10, "a", false)
	l.record(11, "b", false)
	l.record(4, "c", false)
	if l.floor != 3 || l.n != 1 || l.at(0).id != "c" {
		t.Fatalf("after a backwards index: floor=%d n=%d, want floor 3 with only c retained", l.floor, l.n)
	}
	l.record(0, "d", false)
	if l.floor != 0 || l.n != 1 {
		t.Fatalf("after index 0: floor=%d n=%d, want a full reset to floor 0", l.floor, l.n)
	}
}

func TestPlacementChangesOnAFreshFSM(t *testing.T) {
	f := &placementFSM{placements: map[string]Placement{}, version: 7}
	if resp := f.placementChanges(3); !resp.Resnapshot || resp.Next != 7 {
		t.Fatalf("fresh FSM since=3: %+v, want resnapshot next=7", resp)
	}
	if resp := f.placementChanges(7); resp.Resnapshot {
		t.Fatalf("fresh FSM since=version: %+v, want no resnapshot", resp)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Against a real single-node raft cluster: the long-poll returns pending
// changes at once, parks with nothing new and wakes on the next placement,
// and waits (not resnapshots) for a cursor ahead of the applied index.
func TestClusterPlacementChangesLongPoll(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-feed", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	if err := c.applyCommand(ctx, place("sb1", "w1")); err != nil {
		t.Fatalf("place sb1: %v", err)
	}
	v1 := c.fsm.currentVersion()

	resp := c.PlacementChanges(ctx, 0, 0)
	if present, _ := changedIDs(resp); resp.Resnapshot || !equalStrings(present, []string{"sb1"}) {
		t.Fatalf("since=0: %+v, want sb1 without resnapshot", resp)
	}

	// Nothing newer than v1: parks, then wakes on the next apply.
	got := make(chan PlacementChangesResponse, 1)
	start := time.Now()
	go func() { got <- c.PlacementChanges(ctx, v1, 5*time.Second) }()
	time.Sleep(150 * time.Millisecond)
	if err := c.applyCommand(ctx, place("sb2", "w1")); err != nil {
		t.Fatalf("place sb2: %v", err)
	}
	select {
	case r := <-got:
		if present, _ := changedIDs(r); !equalStrings(present, []string{"sb2"}) {
			t.Fatalf("woken poll = %+v, want sb2", r)
		}
		if waited := time.Since(start); waited < 100*time.Millisecond || waited > 4*time.Second {
			t.Fatalf("poll returned after %v; want it parked, then woken by the apply", waited)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("parked poll never woke on a new placement")
	}

	// Empty wait returns promptly, with Next never below since.
	cur := c.fsm.currentVersion()
	r := c.PlacementChanges(ctx, cur, 0)
	if len(r.Changes) != 0 || r.Next < cur || r.Resnapshot {
		t.Fatalf("caught-up zero-wait poll = %+v, want empty with next >= %d", r, cur)
	}

	// A cursor AHEAD of this server (an agent that saw a newer server) waits
	// out the timer and answers without resnapshot or a backwards Next.
	ahead := cur + 1000
	r = c.PlacementChanges(ctx, ahead, 50*time.Millisecond)
	if r.Resnapshot || r.Next != ahead || len(r.Changes) != 0 {
		t.Fatalf("cursor ahead of server = %+v, want a wait with next=%d and no resnapshot", r, ahead)
	}

	// A cursor below the floor resnapshots immediately.
	c.fsm.mu.Lock()
	c.fsm.changes.reset(cur)
	c.fsm.mu.Unlock()
	if r := c.PlacementChanges(ctx, cur-1, 5*time.Second); !r.Resnapshot {
		t.Fatalf("cursor below floor = %+v, want resnapshot", r)
	}

	var nilCluster *Cluster
	if r := nilCluster.PlacementChanges(ctx, 0, 0); !r.Resnapshot {
		t.Fatal("nil cluster must answer resnapshot")
	}
}
