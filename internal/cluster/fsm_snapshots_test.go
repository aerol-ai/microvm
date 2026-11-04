package cluster

import (
	"bytes"
	"io"
	"testing"

	"github.com/hashicorp/raft"
)

func registerSnapCmd(name, node string) command {
	return command{Op: opRegisterSnapshotNode, SnapshotName: name, NodeID: node}
}

func TestFSMSnapshotNodeRegisterReadForget(t *testing.T) {
	fsm := newPlacementFSM()

	if got := fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, registerSnapCmd("snap-a", "node-1"))}); got != nil {
		t.Fatalf("apply register returned %v", got)
	}
	if node, ok := fsm.snapshotHomeNode("snap-a"); !ok || node != "node-1" {
		t.Fatalf("snapshotHomeNode = %q,%v, want node-1,true", node, ok)
	}
	// Unknown name → not found (serve locally).
	if _, ok := fsm.snapshotHomeNode("missing"); ok {
		t.Fatal("unknown snapshot reported a home node")
	}

	// Re-register moves the home (a snapshot re-committed on another node).
	if got := fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, registerSnapCmd("snap-a", "node-2"))}); got != nil {
		t.Fatalf("apply re-register returned %v", got)
	}
	if node, _ := fsm.snapshotHomeNode("snap-a"); node != "node-2" {
		t.Fatalf("home after re-register = %q, want node-2", node)
	}

	// Forget drops the entry; forgetting again is a no-op.
	if got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, command{Op: opForgetSnapshotNode, SnapshotName: "snap-a"})}); got != nil {
		t.Fatalf("apply forget returned %v", got)
	}
	if _, ok := fsm.snapshotHomeNode("snap-a"); ok {
		t.Fatal("snapshot still has a home after forget")
	}
	if got := fsm.Apply(&raft.Log{Index: 4, Data: mustEncode(t, command{Op: opForgetSnapshotNode, SnapshotName: "snap-a"})}); got != nil {
		t.Fatalf("double forget returned %v", got)
	}
}

func TestFSMSnapshotNodeValidation(t *testing.T) {
	fsm := newPlacementFSM()
	if got := fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, registerSnapCmd("", "node-1"))}); got == nil {
		t.Fatal("register with empty name should error")
	}
	if got := fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, registerSnapCmd("snap-a", ""))}); got == nil {
		t.Fatal("register with empty node should error")
	}
	if got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, command{Op: opForgetSnapshotNode})}); got == nil {
		t.Fatal("forget with empty name should error")
	}
}

func TestFSMSnapshotNodesSurviveSnapshotRoundtrip(t *testing.T) {
	src := newPlacementFSM()
	src.Apply(&raft.Log{Index: 1, Data: mustEncode(t, registerSnapCmd("snap-a", "node-1"))})
	src.Apply(&raft.Log{Index: 2, Data: mustEncode(t, registerSnapCmd("snap-b", "node-2"))})

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
	if node, ok := dst.snapshotHomeNode("snap-a"); !ok || node != "node-1" {
		t.Fatalf("snap-a lost across snapshot: %q,%v", node, ok)
	}
	if node, ok := dst.snapshotHomeNode("snap-b"); !ok || node != "node-2" {
		t.Fatalf("snap-b lost across snapshot: %q,%v", node, ok)
	}
}

// A node leaving the cluster drops its snapshot-home entries (its local
// catalogue rows went with it) while leaving other nodes' entries intact.
func TestFSMSnapshotNodesSweptOnOrphanOwner(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, registerSnapCmd("snap-dead-1", "node-dead"))})
	fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, registerSnapCmd("snap-dead-2", "node-dead"))})
	fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, registerSnapCmd("snap-live", "node-live"))})

	if got := fsm.Apply(&raft.Log{Index: 4, Data: mustEncode(t, command{Op: opOrphanOwner, NodeID: "node-dead"})}); got != nil {
		t.Fatalf("orphan owner returned %v", got)
	}
	if _, ok := fsm.snapshotHomeNode("snap-dead-1"); ok {
		t.Fatal("dead node's snapshot entry survived the orphan sweep")
	}
	if _, ok := fsm.snapshotHomeNode("snap-dead-2"); ok {
		t.Fatal("dead node's second snapshot entry survived the orphan sweep")
	}
	if node, ok := fsm.snapshotHomeNode("snap-live"); !ok || node != "node-live" {
		t.Fatalf("live node's snapshot entry was swept: %q,%v", node, ok)
	}
}
