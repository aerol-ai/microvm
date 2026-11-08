package cluster

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/hashicorp/raft"
)

// ownerEpochWant is the OwnerEpoch the placement must carry after each entry
// of ownerSinceScenario, applied at index i+1. The epoch is the index of the
// entry that last changed the owner: unlike OwnerSinceUnixNano it also moves
// on an orphaning and on a claim back (the owner field changed both times),
// and an entry with no append time still has an index.
var ownerEpochWant = []uint64{
	1,  // reserve on A: the entry that wrote the row
	1,  // promote by A: same owner
	3,  // failover to B
	3,  // port write
	3,  // re-place with a new spec
	3,  // reassign to the same owner
	7,  // failback to A
	8,  // orphaned: the owner field became ""
	9,  // claimed back by A
	10, // reassign with no append time: the index is still known
	11, // orphaned from B
	12, // moved to A
}

func TestFSMOwnerEpochIsTheIndexOfTheLastOwnerChange(t *testing.T) {
	scenario := ownerSinceScenario()
	if len(scenario) != len(ownerEpochWant) {
		t.Fatalf("scenario has %d entries, want table has %d", len(scenario), len(ownerEpochWant))
	}
	fsm := newPlacementFSM()
	for i, e := range scenario {
		if got := fsm.Apply(ownerSinceLog(t, uint64(i+1), e)); got != nil {
			t.Fatalf("%s: apply: %v", e.name, got)
		}
		p, ok := fsm.get("sb-owner-since")
		if !ok {
			t.Fatalf("%s: placement gone", e.name)
		}
		if p.OwnerEpoch != ownerEpochWant[i] {
			t.Fatalf("%s: owner %q epoch %d, want %d", e.name, p.OwnerNodeID, p.OwnerEpoch, ownerEpochWant[i])
		}
	}
}

// A create that runs on its node first records the placement with opPlace:
// that entry wrote the row, so it is the epoch.
func TestFSMOwnerEpochOfAFirstPlace(t *testing.T) {
	fsm := newPlacementFSM()
	e := ownerSinceEntry{name: "place", cmd: command{Op: opPlace, SandboxID: "sb-local", OwnerNodeID: "A", IncarnationID: "inc-local"}}
	if got := fsm.Apply(ownerSinceLog(t, 42, e)); got != nil {
		t.Fatalf("apply: %v", got)
	}
	if p, _ := fsm.get("sb-local"); p.OwnerEpoch != 42 {
		t.Fatalf("epoch %d, want 42", p.OwnerEpoch)
	}
}

// Every server and every replay computes the same epochs, a snapshot carries
// them, and a snapshot from a build without the field restores 0 (unknown).
func TestFSMOwnerEpochIsReplayedAndSnapshotted(t *testing.T) {
	const id = "sb-owner-since"
	var entries []*raft.Log
	for i, e := range ownerSinceScenario()[:7] { // ends on the failback to A
		entries = append(entries, ownerSinceLog(t, uint64(i+1), e))
	}
	leader, replay := newPlacementFSM(), newPlacementFSM()
	for _, l := range entries {
		leader.Apply(l)
	}
	for _, l := range entries {
		replay.Apply(l)
	}
	for name, fsm := range map[string]*placementFSM{"leader": leader, "replay": replay} {
		if p, _ := fsm.get(id); p.OwnerEpoch != 7 {
			t.Fatalf("%s: epoch %d, want 7", name, p.OwnerEpoch)
		}
	}

	snap, err := leader.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if p, _ := restored.get(id); p.OwnerEpoch != 7 || p.OwnerNodeID != "A" {
		t.Fatalf("restored: owner %q epoch %d, want A epoch 7", p.OwnerNodeID, p.OwnerEpoch)
	}

	type placementBeforeOwnerEpoch struct {
		SandboxID, OwnerNodeID, IncarnationID string
	}
	legacy := map[string]placementBeforeOwnerEpoch{id: {SandboxID: id, OwnerNodeID: "A", IncarnationID: "inc-owner-since"}}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if p, ok := old.get(id); !ok || p.OwnerEpoch != 0 {
		t.Fatalf("legacy snapshot: %+v %v, want epoch 0", p, ok)
	}
}

func TestOwnerEpochAfter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prev    Placement
		existed bool
		owner   string
		index   uint64
		want    uint64
	}{
		{"a new row takes the index", Placement{}, false, "A", 9, 9},
		{"the same owner keeps the epoch", Placement{OwnerNodeID: "A", OwnerEpoch: 4}, true, "A", 9, 4},
		{"the same owner, padded, keeps it", Placement{OwnerNodeID: "A", OwnerEpoch: 4}, true, " A ", 9, 4},
		{"another owner takes the index", Placement{OwnerNodeID: "A", OwnerEpoch: 4}, true, "B", 9, 9},
		{"an orphaning takes the index", Placement{OwnerNodeID: "A", OwnerEpoch: 4}, true, "", 9, 9},
		{"a claim of an orphan takes the index", Placement{OwnerEpoch: 4}, true, "A", 9, 9},
		{"no index records unknown", Placement{OwnerNodeID: "A", OwnerEpoch: 4}, true, "B", 0, 0},
	} {
		if got := ownerEpochAfter(tc.prev, tc.existed, tc.owner, tc.index); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

// A worker learns the epoch from the placement the control plane returns,
// so it works against a server whose OwnerInfo predates the field.
func TestAgentOwnerOfCarriesTheEpoch(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || r.URL.Path != PublicInternalPlacementPath+"sb-epoch" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
			SandboxID: "sb-epoch",
			Placement: Placement{SandboxID: "sb-epoch", OwnerNodeID: "worker-b", OwnerEpoch: 77},
			Owner:     OwnerInfo{NodeID: "worker-b"},
		})
		return true
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	owner, err := agent.OwnerOf("sb-epoch")
	if err != nil || owner.Epoch != 77 || owner.IsSelf {
		t.Fatalf("OwnerOf() = (%+v, %v), want worker-b at epoch 77", owner, err)
	}
}

// The forward stamp carries the epoch only from the request context, and
// clears a copy that came in with the request (a client cannot plant one).
func TestStampForwardCarriesTheOwnerEpochFromContext(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	if ctx := ContextWithOwnerEpoch(in.Context(), 0); ctx != in.Context() {
		t.Fatal("epoch 0 must leave the context unchanged")
	}

	out := in.WithContext(ContextWithOwnerEpoch(in.Context(), 42))
	StampForward(out, controlplane.Access{})
	if got := out.Header.Get(HeaderOwnerEpoch); got != "42" {
		t.Fatalf("stamped epoch %q, want 42", got)
	}
	if got := ForwardedOwnerEpoch(out.Header); got != 42 {
		t.Fatalf("read back %d, want 42", got)
	}

	planted := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-1", nil)
	planted.Header.Set(HeaderOwnerEpoch, "999")
	StampForward(planted, controlplane.Access{})
	if got := planted.Header.Get(HeaderOwnerEpoch); got != "" {
		t.Fatalf("a header with no context epoch survived: %q", got)
	}
	for _, bad := range []string{"", "x", "-3", "18446744073709551616"} {
		h := http.Header{}
		h.Set(HeaderOwnerEpoch, bad)
		if got := ForwardedOwnerEpoch(h); got != 0 {
			t.Errorf("ForwardedOwnerEpoch(%q) = %d, want 0", bad, got)
		}
	}
}
