package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// placeForSpecFence places sb-x (incarnation inc-x, CPU 1) at log index 1,
// so the placement's version is 1.
func placeForSpecFence(t *testing.T, f *placementFSM) {
	t.Helper()
	got := applyDenyLogAt(t, f, 1, command{Op: opPlace, SandboxID: "sb-x", OwnerNodeID: "node-a", IncarnationID: "inc-x",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1}})
	if got != nil {
		t.Fatalf("place: %v", got)
	}
}

func specWrite(cpu float64, expected uint64) command {
	return command{Op: opUpsertSpec, SandboxID: "sb-x", IncarnationID: "inc-x", ExpectedIncarnationID: "inc-x",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: cpu}, ExpectedPlacementVersion: expected}
}

// TestPlacementFSMSpecVersionFence walks opUpsertSpec's version check case
// by case. Each case places sb-x at index 1, applies its earlier entries
// from index 2, then one spec write of CPU 9.
func TestPlacementFSMSpecVersionFence(t *testing.T) {
	cases := []struct {
		name     string
		before   []command
		expected uint64
		refused  bool
	}{
		{name: "entry from before the fence (no version): applies as it always did", expected: 0},
		{name: "the version the writer read: applies", expected: 1},
		{name: "spec written since the read: refused", before: []command{specWrite(4, 0)}, expected: 1, refused: true},
		{name: "a port added since the read moves the version too: refused",
			before:   []command{{Op: opAddExposedPort, SandboxID: "sb-x", ExpectedIncarnationID: "inc-x", Port: 8080, Protocol: "http"}},
			expected: 1, refused: true},
		{name: "a version this placement never had: refused", expected: 99, refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlacementFSM()
			placeForSpecFence(t, f)
			idx := uint64(1)
			for _, cmd := range tc.before {
				idx++
				if got := applyDenyLogAt(t, f, idx, cmd); got != nil {
					t.Fatalf("earlier entry %v: %v", cmd.Op, got)
				}
			}
			before, _ := f.get("sb-x")
			idx++
			got := applyDenyLogAt(t, f, idx, specWrite(9, tc.expected))
			after, _ := f.get("sb-x")
			if f.version != idx {
				t.Fatalf("FSM version = %d, want %d: every entry advances the index, refused or not", f.version, idx)
			}
			if !tc.refused {
				if got != nil || after.Spec.CPU != 9 || after.Version != idx {
					t.Fatalf("write = %v, CPU %v version %d; want applied at %d", got, after.Spec.CPU, after.Version, idx)
				}
				return
			}
			if err, _ := got.(error); !errors.Is(err, ErrSpecVersionConflict) {
				t.Fatalf("write = %v, want ErrSpecVersionConflict", got)
			}
			if after.Spec.CPU != before.Spec.CPU || after.Version != before.Version {
				t.Fatalf("refused write changed the placement: CPU %v→%v version %d→%d", before.Spec.CPU, after.Spec.CPU, before.Version, after.Version)
			}
		})
	}
}

// TestPlacementFSMSpecVersionFenceSurvivesRestore: a server that restarts
// from a snapshot holds the same placement versions as the ones that applied
// the log live, so it gives every versioned write the same answer.
func TestPlacementFSMSpecVersionFenceSurvivesRestore(t *testing.T) {
	src := newPlacementFSM()
	placeForSpecFence(t, src)
	if got := applyDenyLogAt(t, src, 2, specWrite(4, 0)); got != nil {
		t.Fatal(got)
	}
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
	for name, f := range map[string]*placementFSM{"live": src, "restored": restored} {
		if got := applyDenyLogAt(t, f, 3, specWrite(9, 1)); !errors.Is(asError(got), ErrSpecVersionConflict) {
			t.Fatalf("%s replica: stale write = %v, want ErrSpecVersionConflict", name, got)
		}
		if got := applyDenyLogAt(t, f, 4, specWrite(9, 2)); got != nil {
			t.Fatalf("%s replica: current write = %v, want applied", name, got)
		}
	}
}

func asError(v any) error {
	err, _ := v.(error)
	return err
}

// TestClusterSpecWritesCarryTheVersionCheck runs the check through a real
// single-server raft: the leader refuses a stale version before the log, the
// FSM refuses one the leader cannot judge, and an older server in the Raft
// configuration turns the check off on both the proposer and the leader.
func TestClusterSpecWritesCarryTheVersionCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "spec-fence", true, nil, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const id = "sb-v"
	if err := c.RecordPlacement(ctx, id, &models.CreateSandboxRequest{Image: "alpine", CPU: 1}, PlacementSecrets{IncarnationID: "inc-v"}); err != nil {
		t.Fatalf("place: %v", err)
	}
	cpuNow := func() float64 {
		spec, _ := c.SpecAndVersionOf(id)
		return spec.CPU
	}
	spec, v1 := c.SpecAndVersionOf(id)
	if spec == nil || v1 == 0 {
		t.Fatalf("SpecAndVersionOf = %+v %d", spec, v1)
	}
	spec.CPU = 2
	if err := c.UpsertSpecIfVersion(ctx, id, spec, v1); err != nil {
		t.Fatalf("write at the read version: %v", err)
	}
	_, v2 := c.SpecAndVersionOf(id)
	if v2 <= v1 || cpuNow() != 2 {
		t.Fatalf("after the write: version %d (was %d), CPU %v", v2, v1, cpuNow())
	}

	last := c.raft.raft.LastIndex()
	spec.CPU = 3
	if err := c.UpsertSpecIfVersion(ctx, id, spec, v1); !errors.Is(err, ErrSpecVersionConflict) {
		t.Fatalf("write at an old version = %v, want ErrSpecVersionConflict", err)
	}
	if got := c.raft.raft.LastIndex(); got != last {
		t.Fatalf("raft last index %d → %d: the leader must refuse a stale version before the log", last, got)
	}
	if err := c.UpsertSpecIfVersion(ctx, id, spec, v2+1000); !errors.Is(err, ErrSpecVersionConflict) {
		t.Fatalf("write at a version past the leader's copy = %v, want the FSM's ErrSpecVersionConflict", err)
	}
	if got := c.raft.raft.LastIndex(); got != last+1 {
		t.Fatalf("raft last index %d, want %d: a version the leader cannot judge goes to the FSM", got, last+1)
	}
	forwarded, _ := encodeCommand(command{Op: opUpsertSpec, SandboxID: id, IncarnationID: "inc-v", ExpectedIncarnationID: "inc-v",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 3}, ExpectedPlacementVersion: v1})
	if err := c.ApplyEncoded(ctx, forwarded); !errors.Is(err, ErrSpecVersionConflict) {
		t.Fatalf("forwarded write at an old version = %v, want ErrSpecVersionConflict", err)
	}
	if cpuNow() != 2 {
		t.Fatalf("CPU %v after refused writes, want 2", cpuNow())
	}
	spec.CPU = 5
	if err := c.UpsertSpec(ctx, id, spec, PlacementSecrets{}); err != nil || cpuNow() != 5 {
		t.Fatalf("unversioned write = %v, CPU %v; want applied", err, cpuNow())
	}
	if s, v := c.SpecAndVersionOf("sb-missing"); s != nil || v != 0 {
		t.Fatalf("missing sandbox = %+v %d", s, v)
	}
	if s, v := (*Cluster)(nil).SpecAndVersionOf(id); s != nil || v != 0 {
		t.Fatalf("nil cluster = %+v %d", s, v)
	}

	// An older server joins: no version may reach the log any more.
	if err := c.raft.raft.AddNonvoter("old-server", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	if c.specVersionFenceReplicated() {
		t.Fatal("a server that does not report the fence version must keep it off")
	}
	spec.CPU = 6
	if err := c.UpsertSpecIfVersion(ctx, id, spec, v1); err != nil || cpuNow() != 6 {
		t.Fatalf("write during the upgrade = %v, CPU %v; want applied without the check", err, cpuNow())
	}
	// A worker's gate sees only live members, so the leader drops a
	// version that reaches it anyway.
	if err := c.ApplyEncoded(ctx, forwarded); err != nil || cpuNow() != 3 {
		t.Fatalf("forwarded versioned write during the upgrade = %v, CPU %v; want applied without the check", err, cpuNow())
	}
	if (*Cluster)(nil).specVersionFenceReplicated() || (&Cluster{}).specVersionFenceReplicated() {
		t.Fatal("a cluster without raft cannot enable the fence")
	}
}

// TestAgentSpecWritesCarryTheVersion: a worker reads the version with the
// spec in its one control-plane read, and sends it with the write only when
// every live member runs the fence.
func TestAgentSpecWritesCarryTheVersion(t *testing.T) {
	spec := models.CreateSandboxRequest{Image: "alpine", CPU: 2, Tags: map[string]string{"k": "v"}}
	// newAgent's control-plane server reports serverFV, and one more live
	// member, a worker, reports workerFV: the gate needs every live member.
	newAgent := func(t *testing.T, sent *[]uint64, serverFV, workerFV int) *Agent {
		var mu sync.Mutex
		agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-a":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: "sb-a",
					Placement: Placement{SandboxID: "sb-a", IncarnationID: "inc-a", Version: 42, Spec: &spec}})
			case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-broken":
				http.Error(w, "boom", http.StatusInternalServerError)
			case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
				body, _ := io.ReadAll(r.Body)
				cmd, err := decodeCommand(body)
				if err != nil || cmd.Op != opUpsertSpec || cmd.ExpectedIncarnationID != "inc-a" {
					http.Error(w, "bad command", http.StatusBadRequest)
					return
				}
				mu.Lock()
				*sent = append(*sent, cmd.ExpectedPlacementVersion)
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
			default:
				http.NotFound(w, r)
			}
		}), Member{NodeID: "worker-2", Alive: true, Role: config.NodeRoleWorker, FSMOpsVersion: workerFV})
		server, ok := agent.gossip.lookupMember("server-1")
		if !ok {
			t.Fatal("harness has no server-1")
		}
		server.FSMOpsVersion = serverFV
		agent.gossip.memberIndex.upsert(server)
		return agent
	}
	const fv = specVersionFenceFSMOpsVersion

	var sent []uint64
	agent := newAgent(t, &sent, fv, fv)
	got, version := agent.SpecAndVersionOf("sb-a")
	if got == nil || version != 42 || got.CPU != 2 {
		t.Fatalf("SpecAndVersionOf = %+v %d, want CPU 2 at 42", got, version)
	}
	got.Tags["k"] = "changed"
	if again, _ := agent.SpecAndVersionOf("sb-a"); again.Tags["k"] != "v" {
		t.Fatal("SpecAndVersionOf must return a copy")
	}
	if s, v := agent.SpecAndVersionOf("sb-missing"); s != nil || v != 0 {
		t.Fatalf("missing = %+v %d", s, v)
	}
	if s, v := agent.SpecAndVersionOf("sb-broken"); s != nil || v != 0 {
		t.Fatalf("failed read = %+v %d", s, v)
	}
	if err := agent.UpsertSpecIfVersion(context.Background(), "sb-a", got, version); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(sent) != 1 || sent[0] != 42 {
		t.Fatalf("sent versions %v, want [42]", sent)
	}

	var oldSent []uint64
	old := newAgent(t, &oldSent, fv, fv-1)
	if err := old.UpsertSpecIfVersion(context.Background(), "sb-a", got, 42); err != nil {
		t.Fatalf("write during the upgrade: %v", err)
	}
	if len(oldSent) != 1 || oldSent[0] != 0 {
		t.Fatalf("sent versions %v during the upgrade, want [0]", oldSent)
	}
	if (*Agent)(nil).specVersionFenceReplicated() {
		t.Fatal("a nil agent cannot enable the fence")
	}
}
