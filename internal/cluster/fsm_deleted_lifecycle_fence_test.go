package cluster

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// TestPlacementFSMDeletedLifecycleFence walks the opPlace fence case by case.
// Each case starts from one lifecycle (sb-x, inc-sb-x) that was placed and
// then deleted with the given record expiry, runs its extra steps, and
// applies one opPlace.
func TestPlacementFSMDeletedLifecycleFence(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	fenced := func(id, incarnation string) command {
		return command{Op: opPlace, SandboxID: id, OwnerNodeID: "node-a", IncarnationID: incarnation, RefuseDeletedLifecycle: true}
	}
	cases := []struct {
		name    string
		expires int64
		before  []command
		place   command
		refused bool
	}{
		{name: "same lifecycle: refused", expires: future, place: fenced("sb-x", "inc-sb-x"), refused: true},
		{
			name:    "record past its expiry but not pruned yet: still refused",
			expires: 1, place: fenced("sb-x", "inc-sb-x"), refused: true,
		},
		{
			name:    "entry from before the fence (flag unset): applies as it always did",
			expires: future,
			place:   command{Op: opPlace, SandboxID: "sb-x", OwnerNodeID: "node-a", IncarnationID: "inc-sb-x"},
		},
		{name: "new lifecycle of the same id: placed", expires: future, place: fenced("sb-x", "inc-new")},
		{name: "lifecycle never deleted: placed", expires: future, place: fenced("sb-other", "inc-other")},
		{name: "no incarnation to match: placed", expires: future, place: fenced("sb-x", "")},
		{
			name: "record pruned: nothing proves the delete any more", expires: future,
			before: []command{{Op: opPruneAuditACL, ExpiresUnix: future}},
			place:  fenced("sb-x", "inc-sb-x"),
		},
		{
			name: "grace 0 kept no record: placed", expires: 0,
			place: fenced("sb-x", "inc-sb-x"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsm := newPlacementFSM()
			var idx uint64
			placeAndDelete(t, fsm, &idx, "sb-x", "tenant", tc.expires, 0)
			for _, cmd := range tc.before {
				payload, _ := encodeCommand(cmd)
				idx++
				if got := fsm.Apply(&raft.Log{Index: idx, Data: payload}); got != nil {
					t.Fatalf("before step %v: %v", cmd.Op, got)
				}
			}
			payload, _ := encodeCommand(tc.place)
			idx++
			got := fsm.Apply(&raft.Log{Index: idx, Data: payload})
			_, placed := fsm.get(tc.place.SandboxID)
			if !tc.refused {
				if got != nil || !placed {
					t.Fatalf("opPlace = %v placed=%v, want accepted", got, placed)
				}
				return
			}
			err, _ := got.(error)
			if !errors.Is(err, ErrPlacementDeleted) {
				t.Fatalf("opPlace = %v, want ErrPlacementDeleted", got)
			}
			if placed {
				t.Fatal("refused opPlace still wrote the placement")
			}
			if fsm.version != idx {
				t.Fatalf("FSM version = %d, want %d: a refused entry still advances the index", fsm.version, idx)
			}
			if _, kept := fsm.auditACLForSandbox("sb-x", "inc-sb-x", 0); !kept {
				t.Fatal("refusal consumed the post-delete record")
			}
		})
	}
}

// TestPlacementFSMDeletedLifecycleFenceSurvivesRestore: a server that
// restarts from a snapshot taken after the delete gives the same answer as
// the servers that applied the delete live, because the record is in the
// snapshot and the check reads no clock.
func TestPlacementFSMDeletedLifecycleFenceSurvivesRestore(t *testing.T) {
	src := newPlacementFSM()
	var idx uint64
	placeAndDelete(t, src, &idx, "sb-x", "tenant", time.Now().Add(time.Hour).Unix(), 0)
	snap, err := src.Snapshot()
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
	payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-x", OwnerNodeID: "node-a", IncarnationID: "inc-sb-x", RefuseDeletedLifecycle: true})
	for name, fsm := range map[string]*placementFSM{"live": src, "restored": restored} {
		got := fsm.Apply(&raft.Log{Index: idx + 1, Data: payload})
		if err, _ := got.(error); !errors.Is(err, ErrPlacementDeleted) {
			t.Fatalf("%s replica: opPlace = %v, want ErrPlacementDeleted", name, got)
		}
	}
}

// TestRecordPlacementSetsFenceOnlyWhenEveryServerAppliesIt is the rolling
// upgrade rule: an older server ignores RefuseDeletedLifecycle and would
// apply an entry a newer one refuses, so a proposer sets it only once every
// Raft server reports deletedLifecycleFenceFSMOpsVersion.
func TestRecordPlacementSetsFenceOnlyWhenEveryServerAppliesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "fence-gate")
	defer cleanup()
	if !c.deletedLifecycleFenceReplicated() {
		t.Fatal("a single current server must enable the fence")
	}
	if err := c.raft.raft.AddNonvoter("old-server", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	if c.deletedLifecycleFenceReplicated() {
		t.Fatal("a server that does not report the fence version must keep it off")
	}
	if (*Cluster)(nil).deletedLifecycleFenceReplicated() || (&Cluster{}).deletedLifecycleFenceReplicated() {
		t.Fatal("a cluster without raft cannot enable the fence")
	}
	if (*Agent)(nil).deletedLifecycleFenceReplicated() {
		t.Fatal("a nil agent cannot enable the fence")
	}
}
