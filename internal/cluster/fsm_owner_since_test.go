package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// ownerSinceEntry is one raft log entry of an owner-since scenario: the
// command, the leader's append time it carries, and what the placement must
// say after it.
type ownerSinceEntry struct {
	name      string
	at        time.Time
	cmd       command
	wantOwner string
	want      time.Time // zero: OwnerSinceUnixNano must be 0
}

func ownerSinceLog(t *testing.T, index uint64, e ownerSinceEntry) *raft.Log {
	t.Helper()
	payload, err := encodeCommand(e.cmd)
	if err != nil {
		t.Fatalf("%s: encode: %v", e.name, err)
	}
	return &raft.Log{Index: index, Data: payload, AppendedAt: e.at}
}

func wantOwnerSince(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.UnixNano()
}

// ownerSinceScenario is a sandbox's whole ownership story: reserved and
// promoted on A, failed over to B, back to A, orphaned from A and claimed
// back by A, then moved by an entry with no append time. Each step names
// the rule it pins.
func ownerSinceScenario() []ownerSinceEntry {
	const id, inc = "sb-owner-since", "inc-owner-since"
	base := time.Unix(1_800_000_000, 123_456_789)
	at := func(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }
	spec := &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	resized := &models.CreateSandboxRequest{Image: "alpine", CPU: 2, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	return []ownerSinceEntry{
		{"reserve: the first owner is not a takeover", at(1),
			command{Op: opReserve, SandboxID: id, OwnerNodeID: "A", Spec: spec, IncarnationID: inc, ExpiresUnix: time.Now().Add(time.Hour).Unix()},
			"A", time.Time{}},
		{"promote by the reserving node keeps it", at(2),
			command{Op: opPlace, SandboxID: id, OwnerNodeID: "A", ExpectedIncarnationID: inc},
			"A", time.Time{}},
		{"failover to B takes the entry's append time", at(10),
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "B", ExpectedIncarnationID: inc},
			"B", at(10)},
		{"a port write keeps the owner and the time", at(11),
			command{Op: opAddExposedPort, SandboxID: id, Port: 3000, Protocol: "http", ExpectedIncarnationID: inc},
			"B", at(10)},
		{"a re-place with a new spec keeps it", at(12),
			command{Op: opPlace, SandboxID: id, OwnerNodeID: "B", Spec: resized, ExpectedIncarnationID: inc},
			"B", at(10)},
		{"a reassign to the same owner keeps it", at(13),
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "B", ExpectedIncarnationID: inc},
			"B", at(10)},
		{"failback to A takes the new entry's time", at(20),
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "A", ExpectedIncarnationID: inc},
			"A", at(20)},
		{"orphaning hands it to nobody and keeps it", at(30),
			command{Op: opOrphanOwner, NodeID: "A"},
			"", at(20)},
		{"a claim back by the node it was orphaned from keeps it", at(40),
			command{Op: opClaimOrphan, SandboxID: id, OwnerNodeID: "A", IncarnationID: inc},
			"A", at(20)},
		{"a takeover with no append time records unknown", time.Time{},
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "B", ExpectedIncarnationID: inc},
			"B", time.Time{}},
		{"orphaned from B and moved to A is a takeover", at(60),
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "", ExpectedIncarnationID: inc},
			"", time.Time{}},
		{"... once it lands on A", at(61),
			command{Op: opReassign, SandboxID: id, OwnerNodeID: "A", ExpectedIncarnationID: inc},
			"A", at(61)},
	}
}

// The FSM stamps an owner change with the leader's append time from the raft
// entry, keeps it across writes that leave the owner alone, and never counts
// the first owner, an orphaning or a claim back by the same node.
func TestFSMOwnerSinceFollowsTakeovers(t *testing.T) {
	fsm := newPlacementFSM()
	for i, e := range ownerSinceScenario() {
		if got := fsm.Apply(ownerSinceLog(t, uint64(i+1), e)); got != nil {
			t.Fatalf("%s: apply: %v", e.name, got)
		}
		p, ok := fsm.get("sb-owner-since")
		if !ok {
			t.Fatalf("%s: placement gone", e.name)
		}
		if p.OwnerNodeID != e.wantOwner || p.OwnerSinceUnixNano != wantOwnerSince(e.want) {
			t.Fatalf("%s: owner %q since %d, want %q since %d", e.name, p.OwnerNodeID, p.OwnerSinceUnixNano, e.wantOwner, wantOwnerSince(e.want))
		}
	}
}

// A create that runs on its node first writes the sandbox row and only then
// records the placement with opPlace. That first owner must not be stamped:
// the owner watcher would take the row for one from an earlier ownership
// and refuse the tokens issued right after the create.
func TestFSMOwnerSinceFirstPlaceIsNotATakeover(t *testing.T) {
	fsm := newPlacementFSM()
	e := ownerSinceEntry{name: "place", at: time.Unix(1_800_000_000, 0),
		cmd: command{Op: opPlace, SandboxID: "sb-local", OwnerNodeID: "A", IncarnationID: "inc-local"}}
	if got := fsm.Apply(ownerSinceLog(t, 1, e)); got != nil {
		t.Fatalf("apply: %v", got)
	}
	if p, _ := fsm.get("sb-local"); p.OwnerSinceUnixNano != 0 {
		t.Fatalf("first owner stamped %d, want 0", p.OwnerSinceUnixNano)
	}
}

// Replaying the same entries (a follower, a restart, a new voter) gives the
// same value, because it comes from the entries and not from the clock of
// the node applying them; a snapshot carries it, and a snapshot written
// before the field existed restores it as 0.
func TestFSMOwnerSinceIsReplayedAndSnapshotted(t *testing.T) {
	var entries []*raft.Log
	for i, e := range ownerSinceScenario()[:7] { // ends on the failback to A
		entries = append(entries, ownerSinceLog(t, uint64(i+1), e))
	}
	const id = "sb-owner-since"
	want := ownerSinceScenario()[6].at.UnixNano()

	leader, replay := newPlacementFSM(), newPlacementFSM()
	for _, l := range entries {
		leader.Apply(l)
	}
	time.Sleep(10 * time.Millisecond) // a later apply clock must not matter
	for _, l := range entries {
		replay.Apply(l)
	}
	for name, fsm := range map[string]*placementFSM{"leader": leader, "replay": replay} {
		if p, _ := fsm.get(id); p.OwnerSinceUnixNano != want {
			t.Fatalf("%s: owner since %d, want %d", name, p.OwnerSinceUnixNano, want)
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
	if p, _ := restored.get(id); p.OwnerSinceUnixNano != want || p.OwnerNodeID != "A" {
		t.Fatalf("restored: owner %q since %d, want A since %d", p.OwnerNodeID, p.OwnerSinceUnixNano, want)
	}

	// A snapshot from a build without the field: a placement shape that
	// lacks it, in the bare-map format Restore still reads.
	type placementBeforeOwnerSince struct {
		SandboxID, OwnerNodeID, IncarnationID string
	}
	legacy := map[string]placementBeforeOwnerSince{id: {SandboxID: id, OwnerNodeID: "A", IncarnationID: "inc-owner-since"}}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(legacy); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if p, ok := old.get(id); !ok || p.OwnerSinceUnixNano != 0 {
		t.Fatalf("legacy snapshot: %+v %v, want owner since 0", p, ok)
	}
}

// The rule itself, for the rows a log rarely produces: a legacy orphan with
// no recorded owner, a reservation promoted by another node, a nil entry.
func TestOwnerSinceAfter(t *testing.T) {
	at := time.Unix(1_800_000_100, 5)
	entry := &raft.Log{AppendedAt: at}
	for _, tc := range []struct {
		name    string
		prev    Placement
		existed bool
		owner   string
		log     *raft.Log
		want    int64
	}{
		{"a new row", Placement{}, false, "A", entry, 0},
		{"same owner", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "A", entry, 7},
		{"other owner", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "B", entry, at.UnixNano()},
		{"owner padded with spaces", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, " A ", entry, 7},
		{"orphaning", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "", entry, 7},
		{"claim back by the orphaned owner", Placement{OwnerState: PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "A", entry, 7},
		{"orphan moved to another node", Placement{OwnerState: PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "B", entry, at.UnixNano()},
		{"legacy orphan with no recorded owner", Placement{OwnerState: PlacementOwnerStateOrphaned}, true, "A", entry, at.UnixNano()},
		{"reservation promoted by another node", Placement{OwnerNodeID: "A", State: PlacementStateReserved}, true, "B", entry, at.UnixNano()},
		{"no entry", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "B", nil, 0},
		{"entry without an append time", Placement{OwnerNodeID: "A", OwnerSinceUnixNano: 7}, true, "B", &raft.Log{}, 0},
	} {
		if got := ownerSinceAfter(tc.prev, tc.existed, tc.owner, tc.log); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// Both owner watchers hand the placement's takeover time to the service with
// the placement they already read: the server from its FSM, a worker from the
// control plane's page (so it must survive the JSON hop). Reading it again in
// the service would cost a worker a round trip per sandbox per tick.
func TestOwnerWatchersPassOwnerSince(t *testing.T) {
	const since = int64(1_800_000_000_123_456_789)
	p := failoverRecreatePlacement("sb-since", "worker-self")
	p.OwnerSinceUnixNano = since

	rec := newRecordingRecreator()
	recreateOwnedPlacement(context.Background(), ownerRecreateDeps{recreator: rec}, p.SandboxID, p)
	if got, ok := rec.get(p.SandboxID); !ok || got.ownerSince != since {
		t.Fatalf("server watcher passed %+v %v, want owner since %d", got, ok, since)
	}

	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalOwnedRecoveryPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OwnedRecoveryResponse{Placements: []Placement{p}, Authoritative: true})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	workerRec := newRecordingRecreator()
	agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	agent.AttachRecreator(workerRec)
	agent.recreateOwnedSandboxes(context.Background())
	if got, ok := workerRec.get(p.SandboxID); !ok || got.ownerSince != since {
		t.Fatalf("worker watcher passed %+v %v, want owner since %d", got, ok, since)
	}
}
