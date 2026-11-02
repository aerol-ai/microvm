package cluster

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func pendingRuntimesAt(f *placementFSM, now time.Time) map[string]map[string]int {
	_, byRuntime := f.pendingReservationLoadByNode(now.Unix())
	return byRuntime
}

// The per-runtime pending counts placement subtracts from a worker's free
// network slots are derived FSM state, like the pending capacity aggregate:
// every transition that releases or moves a reservation must move its count
// too, and a snapshot restore must rebuild exactly the same counts, or two
// replicas (or a leader before and after a restart) would admit differently.
func TestFSMPendingReservationRuntimesFollowEveryTransition(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now()
	live := now.Add(60 * time.Second).Unix()

	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb-docker", OwnerNodeID: "B", IncarnationID: "inc-d", Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: live})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb-gvisor", OwnerNodeID: "B", IncarnationID: "inc-g", Spec: &models.CreateSandboxRequest{CPU: 1, Runtime: models.RuntimeGvisor}, ExpiresUnix: live})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb-fc", OwnerNodeID: "B", IncarnationID: "inc-f", Spec: &models.CreateSandboxRequest{CPU: 1, TemplateID: "tpl"}, ExpiresUnix: live})
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb-old", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: now.Add(-time.Second).Unix()})
	// A placed row has already taken its slot; the heartbeat shows it.
	applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-placed", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1}})

	want := map[string]map[string]int{"B": {models.RuntimeDocker: 1, models.RuntimeGvisor: 1, models.RuntimeFirecracker: 1}}
	if got := pendingRuntimesAt(fsm, now); !reflect.DeepEqual(got, want) {
		t.Fatalf("pending runtimes = %v, want %v (expired and placed rows excluded)", got, want)
	}

	// Snapshot -> Restore rebuilds the same counts from the reserved rows.
	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSMWithRecoveryStore(fsm.recoveryStore)
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if got := pendingRuntimesAt(restored, now); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored pending runtimes = %v, want %v", got, want)
	}

	// Promote, cancel, reassign, spec upsert and delete each move the count.
	if got := applyOp(t, fsm, command{Op: opPlace, SandboxID: "sb-docker", OwnerNodeID: "B", IncarnationID: "inc-d", ExpectedIncarnationID: "inc-d"}); got != nil {
		t.Fatalf("promote: %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opCancelReserve, SandboxID: "sb-fc", ExpectedIncarnationID: "inc-f"}); got != nil {
		t.Fatalf("cancel: %v", got)
	}
	if got := applyOp(t, fsm, command{Op: opUpsertSpec, SandboxID: "sb-gvisor", ExpectedIncarnationID: "inc-g", Spec: &models.CreateSandboxRequest{CPU: 1, Runtime: models.RuntimeDocker}}); got != nil {
		t.Fatalf("upsert: %v", got)
	}
	if got := pendingRuntimesAt(fsm, now); !reflect.DeepEqual(got, map[string]map[string]int{"B": {models.RuntimeDocker: 1}}) {
		t.Fatalf("after promote/cancel/upsert = %v, want B docker=1", got)
	}
	if got := applyOp(t, fsm, command{Op: opReassign, SandboxID: "sb-gvisor", OwnerNodeID: "C", ExpectedIncarnationID: "inc-g"}); got != nil {
		t.Fatalf("reassign: %v", got)
	}
	if got := pendingRuntimesAt(fsm, now); !reflect.DeepEqual(got, map[string]map[string]int{"C": {models.RuntimeDocker: 1}}) {
		t.Fatalf("after reassign = %v, want the count moved to C", got)
	}
	if got := applyOp(t, fsm, command{Op: opDelete, SandboxID: "sb-gvisor", ExpectedIncarnationID: "inc-g"}); got != nil {
		t.Fatalf("delete: %v", got)
	}
	if got := pendingRuntimesAt(fsm, now); len(got) != 0 {
		t.Fatalf("after the last reservation went = %v, want empty", got)
	}
	if len(fsm.pendingReservationsByNode(now.Unix())) != 0 {
		t.Fatal("the capacity aggregate and the runtime counts disagree")
	}
}

// A reservation that simply expires leaves both indexes together.
func TestFSMPendingReservationRuntimesPruneOnExpiry(t *testing.T) {
	fsm := newPlacementFSM()
	now := time.Now()
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: now.Add(10 * time.Second).Unix()})
	if got := pendingRuntimesAt(fsm, now)["B"][models.RuntimeDocker]; got != 1 {
		t.Fatalf("live reservation count = %d, want 1", got)
	}
	if got := pendingRuntimesAt(fsm, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("expired reservation still counted: %v", got)
	}
	// The read returns copies: a caller cannot reach the FSM's maps.
	applyOp(t, fsm, command{Op: opReserve, SandboxID: "sb2", OwnerNodeID: "B", Spec: &models.CreateSandboxRequest{CPU: 1}, ExpiresUnix: now.Add(time.Hour).Unix()})
	pendingRuntimesAt(fsm, now)["B"][models.RuntimeDocker] = 99
	if got := pendingRuntimesAt(fsm, now)["B"][models.RuntimeDocker]; got != 1 {
		t.Fatalf("caller mutation reached the FSM index: %d", got)
	}
}
