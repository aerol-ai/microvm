package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func recreateSpec() *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
}

// The failover policy must ride the HOT row, like PublicTraffic: an ingress
// reads only redacted pages and feed rows with no Spec, and its age limit
// puts only the sandboxes the leader may move (failover.policy=recreate) in
// flux. Without the flag it could not tell them apart.
func TestFailoverRecreateRidesTheHotRow(t *testing.T) {
	f := newPlacementFSM()

	applyForPublicTraffic(t, f, command{
		Op: opReserve, SandboxID: "sb-re", OwnerNodeID: "worker-1", IncarnationID: "inc-re",
		Spec:        recreateSpec(),
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if !hotRow(t, f, "sb-re").FailoverRecreate {
		t.Fatal("reserve of a recreate-policy sandbox left FailoverRecreate false on the hot row")
	}
	// Promotion carries no spec; the flag must survive it.
	applyForPublicTraffic(t, f, command{Op: opPlace, SandboxID: "sb-re", OwnerNodeID: "worker-1", IncarnationID: "inc-re", ExpectedIncarnationID: "inc-re"})
	if !hotRow(t, f, "sb-re").FailoverRecreate {
		t.Fatal("a spec-less promote cleared FailoverRecreate")
	}
	// And it is what the routing rule reads on a Spec-less row.
	if !placementMovableOnFailover(hotRow(t, f, "sb-re")) {
		t.Fatal("placementMovableOnFailover ignored the hot-row flag")
	}

	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-none", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyNone}},
	})
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-default", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	for _, id := range []string{"sb-none", "sb-default"} {
		if p := hotRow(t, f, id); p.FailoverRecreate || placementMovableOnFailover(p) {
			t.Fatalf("%s (no recreate policy) was marked movable", id)
		}
	}

	// A later write with a spec is authoritative: dropping the policy sticks.
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-re", OwnerNodeID: "worker-1", IncarnationID: "inc-re", ExpectedIncarnationID: "inc-re",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	if hotRow(t, f, "sb-re").FailoverRecreate {
		t.Fatal("re-placing without a recreate policy left FailoverRecreate set")
	}
}

// If the recovery join fails (spec unavailable), a spec-less opPlace must keep
// the hot row's flag rather than silently dropping the sandbox out of the
// age limit.
func TestFailoverRecreateSurvivesAMissingRecoveryJoin(t *testing.T) {
	f := newPlacementFSM()
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-re", OwnerNodeID: "worker-1", IncarnationID: "inc-1",
		Spec: recreateSpec(),
	})
	f.mu.Lock()
	delete(f.recovery, "sb-re")
	hot := f.placements["sb-re"]
	hot.RecoveryRef = ""
	hot.State = PlacementStateReserved
	hot.ExpiresUnix = time.Now().Add(time.Minute).Unix()
	f.placements["sb-re"] = hot
	f.mu.Unlock()

	applyForPublicTraffic(t, f, command{Op: opPlace, SandboxID: "sb-re", OwnerNodeID: "worker-1", ExpectedIncarnationID: "inc-1"})
	got := hotRow(t, f, "sb-re")
	if got.IsReserved() {
		t.Fatal("the promote did not write; the test proves nothing")
	}
	if !got.FailoverRecreate {
		t.Fatal("a spec-less promote after a lost recovery join cleared FailoverRecreate")
	}
}

func TestFailoverRecreateSurvivesSnapshotRestore(t *testing.T) {
	src := newPlacementFSM()
	applyForPublicTraffic(t, src, command{Op: opPlace, SandboxID: "sb-re", OwnerNodeID: "worker-1", Spec: recreateSpec()})
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if !hotRow(t, dst, "sb-re").FailoverRecreate {
		t.Fatal("FailoverRecreate was lost across snapshot/restore")
	}
}

// A row being deleted is never moved, so it never needs the age limit.
func TestPlacementMovableOnFailoverSkipsDeletingRows(t *testing.T) {
	p := Placement{SandboxID: "sb", OwnerNodeID: "w1", FailoverRecreate: true, State: PlacementStateDeleting}
	if !p.IsDeleting() {
		t.Fatal("fixture is not a deleting row")
	}
	if placementMovableOnFailover(p) {
		t.Fatal("a deleting row was marked movable")
	}
	if !placementMovableOnFailover(Placement{SandboxID: "sb", Spec: recreateSpec()}) {
		t.Fatal("a full row with a recreate spec was not movable")
	}
}
