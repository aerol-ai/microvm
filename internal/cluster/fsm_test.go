package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestFSMApplyPlace(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080"}
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("apply returned %v, want nil", got)
	}
	p, ok := fsm.get("sb1")
	if !ok {
		t.Fatal("expected placement for sb1, got none")
	}
	if p.OwnerNodeID != "nodeA" || p.OwnerAPIURL != "http://a:8080" {
		t.Fatalf("unexpected placement: %+v", p)
	}
}

func TestFSMPlaceIdempotent(t *testing.T) {
	fsm := newPlacementFSM()
	cmd := command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "nodeA", OwnerAPIURL: "http://a:8080"}
	payload, _ := encodeCommand(cmd)
	fsm.Apply(&raft.Log{Data: payload})
	first, _ := fsm.get("sb1")
	// Re-apply same command — version should not bump for the placement,
	// even though the FSM-wide version counter does.
	fsm.Apply(&raft.Log{Data: payload})
	second, _ := fsm.get("sb1")
	if first.Version != second.Version {
		t.Fatalf("idempotent re-place changed placement version: %d -> %d", first.Version, second.Version)
	}
	if first.UpdatedUnix != second.UpdatedUnix {
		t.Fatalf("idempotent re-place changed UpdatedUnix: %d -> %d", first.UpdatedUnix, second.UpdatedUnix)
	}
}

func TestFSMReplaceOwner(t *testing.T) {
	fsm := newPlacementFSM()
	c1, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A", OwnerAPIURL: "http://a"})
	c2, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "B", OwnerAPIURL: "http://b"})
	fsm.Apply(&raft.Log{Data: c1})
	createdFirst, _ := fsm.get("sb1")
	time.Sleep(time.Second) // allow CreatedUnix preservation to be observable
	fsm.Apply(&raft.Log{Data: c2})
	got, _ := fsm.get("sb1")
	if got.OwnerNodeID != "B" {
		t.Fatalf("expected owner B, got %q", got.OwnerNodeID)
	}
	if got.CreatedUnix != createdFirst.CreatedUnix {
		t.Fatalf("CreatedUnix should be preserved across reassign: was %d, now %d", createdFirst.CreatedUnix, got.CreatedUnix)
	}
}

func TestFSMDelete(t *testing.T) {
	fsm := newPlacementFSM()
	c, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb1", OwnerNodeID: "A"})
	fsm.Apply(&raft.Log{Data: c})
	d, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb1"})
	fsm.Apply(&raft.Log{Data: d})
	if _, ok := fsm.get("sb1"); ok {
		t.Fatal("placement should be gone after delete")
	}
	// Idempotent.
	fsm.Apply(&raft.Log{Data: d})
}

// fakeSnapshotSink lets us drive Snapshot/Restore without a real BoltStore.
type fakeSnapshotSink struct {
	*bytes.Buffer
	cancelled bool
}

func (f *fakeSnapshotSink) ID() string  { return "fake" }
func (f *fakeSnapshotSink) Cancel() error { f.cancelled = true; return nil }
func (f *fakeSnapshotSink) Close() error  { return nil }

func TestFSMSnapshotRestoreRoundTrip(t *testing.T) {
	src := newPlacementFSM()
	for _, id := range []string{"a", "b", "c"} {
		c, _ := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: "owner-" + id, OwnerAPIURL: "http://" + id})
		src.Apply(&raft.Log{Data: c})
	}
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if sink.cancelled {
		t.Fatal("sink should not have been cancelled on success")
	}

	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		p, ok := dst.get(id)
		if !ok {
			t.Errorf("missing placement for %s after restore", id)
			continue
		}
		if p.OwnerNodeID != "owner-"+id {
			t.Errorf("wrong owner after restore for %s: %q", id, p.OwnerNodeID)
		}
	}
}
