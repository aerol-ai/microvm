package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// A2 cluster-correctness: opAddExposedPort carries a port's visibility into
// the placement, so a failover recreate gates the port again; a re-add that
// changes only the visibility is applied (not taken for a no-op), and a
// command from before the field (no visibility) replays as public, exactly
// as it did before. The snapshot round trip keeps it.
func TestFSMExposedPortVisibility(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(i uint64, cmd command) {
		t.Helper()
		raw, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if got := fsm.Apply(&raft.Log{Index: i, Data: raw}); got != nil {
			t.Fatalf("apply %d: %v", i, got)
		}
	}
	apply(1, command{Op: opPlace, SandboxID: "sb-v", OwnerNodeID: "n1", OwnerAPIURL: "http://n1", Spec: &models.CreateSandboxRequest{Image: "img"}, IncarnationID: "inc-v"})
	add := command{Op: opAddExposedPort, SandboxID: "sb-v", ExpectedIncarnationID: "inc-v", Port: 3000, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-v-3000.example"}

	// A command without the field: what older nodes wrote.
	legacy, _ := json.Marshal(add)
	var probe map[string]any
	if err := json.Unmarshal(legacy, &probe); err != nil {
		t.Fatal(err)
	}
	if _, ok := probe["visibility"]; ok {
		t.Fatal("a public port's command carries a visibility field")
	}
	apply(2, add)
	if got := portRoute(fsm, "sb-v", 3000); got.Visibility != "" {
		t.Fatalf("legacy add = %+v, want public", got)
	}

	gated := add
	gated.Visibility = models.ExposedPortVisibilityToken
	apply(3, gated)
	if got := portRoute(fsm, "sb-v", 3000); got.Visibility != models.ExposedPortVisibilityToken {
		t.Fatalf("visibility-only change = %+v, want token", got)
	}

	snap, err := fsm.Snapshot()
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
	if got := portRoute(restored, "sb-v", 3000); got.Visibility != models.ExposedPortVisibilityToken {
		t.Fatalf("after snapshot restore = %+v, want token", got)
	}

	// And back to public by an explicit add.
	apply(4, add)
	if got := portRoute(fsm, "sb-v", 3000); got.Visibility != "" {
		t.Fatalf("back to public = %+v", got)
	}
}

func portRoute(f *placementFSM, id string, port int) ExposedPortRoute {
	p, _ := f.get(id)
	return p.ExposedPortRoutes[port]
}
