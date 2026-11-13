package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The claim mark rides the hot row (C17): set from the spec's tag on every
// write that carries a spec, kept by a spec-less one, and through a
// snapshot. A row written without it reads as not known.
func TestKubeClaimMarkRidesTheHotRow(t *testing.T) {
	f := newPlacementFSM()
	claim := &models.CreateSandboxRequest{Image: "alpine", Tags: map[string]string{KubeClaimTag: "true"}}
	applyForPublicTraffic(t, f, command{
		Op: opReserve, SandboxID: "sb-claim", OwnerNodeID: "worker-1", IncarnationID: "inc-c",
		Spec: claim, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	})
	if hotRow(t, f, "sb-claim").KubeClaim != KubeClaimYes {
		t.Fatal("a claim's reserve left no mark")
	}
	applyForPublicTraffic(t, f, command{Op: opPlace, SandboxID: "sb-claim", OwnerNodeID: "worker-1", IncarnationID: "inc-c", ExpectedIncarnationID: "inc-c"})
	if hotRow(t, f, "sb-claim").KubeClaim != KubeClaimYes {
		t.Fatal("a spec-less promote cleared the mark")
	}
	applyForPublicTraffic(t, f, command{
		Op: opPlace, SandboxID: "sb-plain", OwnerNodeID: "worker-1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Tags: map[string]string{KubeClaimTag: "no"}},
	})
	if hotRow(t, f, "sb-plain").KubeClaim != KubeClaimNo {
		t.Fatal("a sandbox no claim made is not marked so")
	}

	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if hotRow(t, restored, "sb-claim").KubeClaim != KubeClaimYes || hotRow(t, restored, "sb-plain").KubeClaim != KubeClaimNo {
		t.Fatal("the marks did not survive a snapshot")
	}
	if kubeClaimMarkOf(nil) != KubeClaimNo {
		t.Fatal("no spec, no tags: not a claim")
	}
}
