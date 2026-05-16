package cluster

import (
	"bytes"
	"io"
	"testing"
)

// TestFSMSetNodeDrainStateMarksAndClears pins the basic drain lifecycle: an
// opSetNodeDrainState(true) flips the bit, a follow-up (false) clears it,
// and the isNodeDrained accessor reflects both.
func TestFSMSetNodeDrainStateMarksAndClears(t *testing.T) {
	fsm := newPlacementFSM()

	if got := applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "n1", Drained: true}); got != nil {
		t.Fatalf("apply drain: %v", got)
	}
	if !fsm.isNodeDrained("n1") {
		t.Fatal("n1 should report drained after opSetNodeDrainState(true)")
	}
	if fsm.isNodeDrained("n2") {
		t.Fatal("n2 was never drained — accessor must not bleed across nodes")
	}

	if got := applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "n1", Drained: false}); got != nil {
		t.Fatalf("apply uncordon: %v", got)
	}
	if fsm.isNodeDrained("n1") {
		t.Fatal("n1 should be uncordoned after opSetNodeDrainState(false)")
	}
}

// TestFSMSetNodeDrainStateIdempotent guards the contract the handler relies on:
// repeating either edge must not error so an operator's retry policy stays
// simple. Without this, a retried drain after a leadership flip would surface
// a spurious 5xx.
func TestFSMSetNodeDrainStateIdempotent(t *testing.T) {
	fsm := newPlacementFSM()

	for i := 0; i < 3; i++ {
		if got := applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "n1", Drained: true}); got != nil {
			t.Fatalf("iter %d drain: %v", i, got)
		}
	}
	if !fsm.isNodeDrained("n1") {
		t.Fatal("n1 should still be drained after repeated marks")
	}
	for i := 0; i < 3; i++ {
		if got := applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "n1", Drained: false}); got != nil {
			t.Fatalf("iter %d uncordon: %v", i, got)
		}
	}
	if fsm.isNodeDrained("n1") {
		t.Fatal("n1 should be cleared after repeated uncordons")
	}
}

// TestFSMSetNodeDrainStateRequiresNodeID rejects a missing nodeID so a
// malformed command can't silently fail (or worse — drain "" and then later
// re-uncordon "" when the operator meant a real node).
func TestFSMSetNodeDrainStateRequiresNodeID(t *testing.T) {
	fsm := newPlacementFSM()
	got := applyOp(t, fsm, command{Op: opSetNodeDrainState, Drained: true})
	if got == nil {
		t.Fatal("expected error for opSetNodeDrainState with empty NodeID")
	}
}

// TestFSMDrainedNodesSnapshot is the read shape SelectPlacement uses to filter
// candidates. A drift between drainedNodesSnapshot and isNodeDrained would let
// placement see a different drain set than observability does, so we pin both.
func TestFSMDrainedNodesSnapshot(t *testing.T) {
	fsm := newPlacementFSM()
	if snap := fsm.drainedNodesSnapshot(); snap != nil {
		t.Fatalf("empty FSM should snapshot as nil, got %v", snap)
	}
	applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "a", Drained: true})
	applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "b", Drained: true})
	applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "c", Drained: false}) // never drained

	snap := fsm.drainedNodesSnapshot()
	if !snap["a"] || !snap["b"] {
		t.Fatalf("snapshot missing drained entries: %v", snap)
	}
	if snap["c"] {
		t.Fatalf("snapshot contains uncordoned entry: %v", snap)
	}
	// Mutating the snapshot must not affect the FSM — placement's filter pass
	// scribbles on its own copy with no risk of corrupting authoritative state.
	snap["a"] = false
	if !fsm.isNodeDrained("a") {
		t.Fatal("snapshot returned a live reference into the FSM map")
	}
}

// TestFSMDrainStateSurvivesSnapshotRoundtrip guarantees drain state persists
// across the snapshot/restore boundary — otherwise a leader change that
// triggered a fresh snapshot would silently uncordon every drained node.
func TestFSMDrainStateSurvivesSnapshotRoundtrip(t *testing.T) {
	src := newPlacementFSM()
	applyOp(t, src, command{Op: opSetNodeDrainState, NodeID: "drained-1", Drained: true})
	applyOp(t, src, command{Op: opSetNodeDrainState, NodeID: "drained-2", Drained: true})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !dst.isNodeDrained("drained-1") || !dst.isNodeDrained("drained-2") {
		t.Fatalf("drained nodes lost across snapshot: %v", dst.drainedNodes)
	}
	if dst.isNodeDrained("never-drained") {
		t.Fatal("restore invented a drain mark that wasn't in the snapshot")
	}
}
