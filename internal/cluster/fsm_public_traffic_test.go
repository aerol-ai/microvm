package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func applyForPublicTraffic(t *testing.T, f *placementFSM, cmd command) {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if res := f.Apply(&raft.Log{Data: payload}); res != nil {
		if err, ok := res.(error); ok && err != nil {
			t.Fatalf("apply %v: %v", cmd.Op, err)
		}
	}
}

func hotRow(t *testing.T, f *placementFSM, id string) Placement {
	t.Helper()
	p, ok := f.placementsByIDs([]string{id})[id]
	if !ok {
		t.Fatalf("no hot row for %s", id)
	}
	if p.Spec != nil {
		t.Fatalf("hot row for %s carries a Spec; the test would not prove the flag rides without it", id)
	}
	return p
}

// The public-traffic flag must live on the HOT row: a dedicated ingress reads
// only redacted pages with no Spec, and without the flag it installed no L4
// route for any remote sandbox (T18, UC-34 raw TCP unreachable).
func TestPublicTrafficRidesTheHotRow(t *testing.T) {
	yes, no := true, false
	f := newPlacementFSM()

	applyForPublicTraffic(t, f, command{
		Op: opReserve, SandboxID: "sb-pub", OwnerNodeID: "worker-1", IncarnationID: "inc-pub",
		Spec:        &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &yes},
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if !hotRow(t, f, "sb-pub").PublicTraffic {
		t.Fatal("reserve of a public sandbox left PublicTraffic false on the hot row")
	}
	// Promotion carries no spec; the flag must survive it.
	applyForPublicTraffic(t, f, command{Op: opPlace, SandboxID: "sb-pub", OwnerNodeID: "worker-1", IncarnationID: "inc-pub", ExpectedIncarnationID: "inc-pub"})
	if !hotRow(t, f, "sb-pub").PublicTraffic {
		t.Fatal("a spec-less promote cleared PublicTraffic")
	}

	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-priv", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &no},
	})
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-default", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine"},
	})
	if hotRow(t, f, "sb-priv").PublicTraffic || hotRow(t, f, "sb-default").PublicTraffic {
		t.Fatal("a private (or default, private-by-default) sandbox was marked public")
	}

	// A later write with a spec is authoritative: flipping to private sticks.
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-pub", OwnerNodeID: "worker-1", IncarnationID: "inc-pub", ExpectedIncarnationID: "inc-pub",
		Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &no},
	})
	if hotRow(t, f, "sb-pub").PublicTraffic {
		t.Fatal("re-placing with AllowPublicTraffic=false left the row public")
	}
}

// If the recovery join fails (spec unavailable), a spec-less opPlace must keep
// the hot row's flag rather than silently making the sandbox private.
func TestPublicTrafficSurvivesAMissingRecoveryJoin(t *testing.T) {
	yes := true
	f := newPlacementFSM()
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-pub", OwnerNodeID: "worker-1", IncarnationID: "inc-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &yes},
	})
	f.mu.Lock()
	delete(f.recovery, "sb-pub")
	hot := f.placements["sb-pub"]
	hot.RecoveryRef = ""
	// A reserved row is what a spec-less opPlace really writes (promotion);
	// an already-placed same-owner re-place is a no-op that never writes.
	hot.State = PlacementStateReserved
	hot.ExpiresUnix = time.Now().Add(time.Minute).Unix()
	f.placements["sb-pub"] = hot
	f.mu.Unlock()

	applyForPublicTraffic(t, f, command{Op: opPlace, SandboxID: "sb-pub", OwnerNodeID: "worker-1", ExpectedIncarnationID: "inc-1"})
	got := hotRow(t, f, "sb-pub")
	if got.IsReserved() {
		t.Fatal("the promote did not write; the test proves nothing")
	}
	if !got.PublicTraffic {
		t.Fatal("a spec-less promote after a lost recovery join cleared PublicTraffic")
	}
}

func TestPublicTrafficSurvivesSnapshotRestore(t *testing.T) {
	yes := true
	src := newPlacementFSM()
	applyForPublicTraffic(t, src, command{
		Op: opPlace, SandboxID: "sb-pub", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &yes},
	})
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
	if !hotRow(t, dst, "sb-pub").PublicTraffic {
		t.Fatal("PublicTraffic was lost across snapshot/restore")
	}
}
