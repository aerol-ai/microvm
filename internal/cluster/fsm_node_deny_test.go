package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/raft"
)

// Regression tests for the node deny records (fsm_node_deny.go): apply,
// idempotency, snapshot/restore, replay, the mixed-version rule and the
// rolling-upgrade gate (CLAUDE.md rule 6).

func denyCmd(nodeID string, stamp int64) command {
	return command{Op: opDenyNode, StampUnixNano: stamp, NodeDeny: &NodeDenyRecord{NodeID: nodeID, Role: config.NodeRoleWorker}}
}

func applyDenyLogAt(t *testing.T, f *placementFSM, index uint64, cmd command) any {
	t.Helper()
	data, err := encodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return f.Apply(&raft.Log{Index: index, Data: data})
}

func TestFSMDenyNodeApplyIsIdempotent(t *testing.T) {
	f := newPlacementFSM()
	res, ok := applyDenyLogAt(t, f, 5, denyCmd(" wkr-1 ", 100)).(nodeDenyApplyResult)
	if !ok || !res.Changed || res.Record.NodeID != "wkr-1" || res.Record.DeniedUnixNano != 100 || res.Record.Role != config.NodeRoleWorker {
		t.Fatalf("first deny = %+v", res)
	}
	if !f.isNodeDenied("wkr-1") || f.isNodeDenied("wkr-2") || f.isNodeDenied("") {
		t.Fatal("isNodeDenied disagrees with the record")
	}
	// A retried delete changes nothing: same stamp, same cursor.
	res, _ = applyDenyLogAt(t, f, 9, denyCmd("wkr-1", 200)).(nodeDenyApplyResult)
	if res.Changed || res.Record.DeniedUnixNano != 100 {
		t.Fatalf("second deny = %+v, want the original record unchanged", res)
	}
	nodes, version := f.deniedNodesView()
	if len(nodes) != 1 || version != 5 {
		t.Fatalf("view = %+v at %d, want one record at index 5", nodes, version)
	}
	for _, bad := range []command{{Op: opDenyNode}, {Op: opDenyNode, NodeDeny: &NodeDenyRecord{NodeID: "  "}}} {
		if err := asApplyErr(applyDenyLogAt(t, f, 10, bad)); err == nil || !strings.Contains(err.Error(), "requires a node id") {
			t.Fatalf("deny without a node id = %v", err)
		}
	}
	var nilFSM *placementFSM
	if nilFSM.isNodeDenied("wkr-1") {
		t.Fatal("nil FSM denied a node")
	}
	// A literal FSM (tests elsewhere build them) gets its map on first use.
	lit := &placementFSM{}
	if res, _ := applyDenyLogAt(t, lit, 1, denyCmd("wkr-9", 1)).(nodeDenyApplyResult); !res.Changed {
		t.Fatalf("literal FSM deny = %+v", res)
	}
}

func TestFSMDenyNodeSnapshotRestore(t *testing.T) {
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 3, denyCmd("wkr-b", 30))
	applyDenyLogAt(t, f, 4, denyCmd("wkr-a", 40))
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	got, version := restored.deniedNodesView()
	want, _ := f.deniedNodesView()
	if !reflect.DeepEqual(got, want) || got[0].NodeID != "wkr-a" {
		t.Fatalf("restored = %+v, want %+v sorted by id", got, want)
	}
	if version != 4 {
		t.Fatalf("restored version = %d, want the snapshot's index 4", version)
	}

	// An older build's snapshot has no records: none denied, cursor 0, and
	// anything the FSM held before is cleared. Blank ids are dropped.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 7, DeniedNodes: []NodeDenyRecord{{NodeID: " "}}}); err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if nodes, v := restored.deniedNodesView(); len(nodes) != 0 || v != 0 {
		t.Fatalf("old snapshot restored %+v at %d", nodes, v)
	}
}

// denyTestLog is a log that touches the state a deny sits beside: a
// placement on the node, a drain mark, an orphaning and the deny itself.
func denyTestLog() []command {
	return []command{
		{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-1", OwnerAPIURL: "http://wkr-1", IncarnationID: "inc-1"},
		{Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "wkr-2", OwnerAPIURL: "http://wkr-2", IncarnationID: "inc-2"},
		denyCmd("wkr-1", 50),
		{Op: opSetNodeDrainState, NodeID: "wkr-1", Drained: true, StampUnixNano: 51},
		{Op: opOrphanOwner, NodeID: "wkr-1"},
		denyCmd("wkr-1", 60), // a retried delete
		denyCmd("wkr-3", 70),
	}
}

type fsmView struct {
	placements map[string]Placement
	drained    map[string]bool
	denied     []NodeDenyRecord
	deniedAt   uint64
}

func viewOf(f *placementFSM) fsmView {
	denied, at := f.deniedNodesView()
	placements := f.snapshot()
	for id, p := range placements {
		// UpdatedUnix / CreatedUnix read the applier's wall clock today;
		// they are not what this test compares.
		p.UpdatedUnix, p.CreatedUnix, p.OrphanedUnix = 0, 0, 0
		placements[id] = p
	}
	return fsmView{placements: placements, drained: f.drainedNodesSnapshot(), denied: denied, deniedAt: at}
}

// Replay: applying the log from scratch, and restoring a snapshot taken
// part way then applying the rest, reach the same deny set and cursor.
func TestFSMDenyNodeReplay(t *testing.T) {
	log := denyTestLog()
	full := newPlacementFSM()
	for i, cmd := range log {
		applyDenyLogAt(t, full, uint64(i+1), cmd)
	}
	for cut := 1; cut < len(log); cut++ {
		prefix := newPlacementFSM()
		for i := 0; i < cut; i++ {
			applyDenyLogAt(t, prefix, uint64(i+1), log[i])
		}
		snap, err := prefix.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		sink := &memSnapshotSink{}
		if err := snap.Persist(sink); err != nil {
			t.Fatal(err)
		}
		snap.Release()
		resumed := newPlacementFSM()
		if err := resumed.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
			t.Fatal(err)
		}
		for i := cut; i < len(log); i++ {
			applyDenyLogAt(t, resumed, uint64(i+1), log[i])
		}
		got, want := viewOf(resumed), viewOf(full)
		if !reflect.DeepEqual(got.denied, want.denied) || !reflect.DeepEqual(got.drained, want.drained) || !reflect.DeepEqual(got.placements, want.placements) {
			t.Fatalf("cut at %d: resumed %+v, want %+v", cut, got, want)
		}
		if got.deniedAt != want.deniedAt {
			t.Fatalf("cut at %d: cursor %d, want %d", cut, got.deniedAt, want.deniedAt)
		}
	}
	if denied := viewOf(full).denied; len(denied) != 2 || denied[0].DeniedUnixNano != 50 {
		t.Fatalf("full replay denied %+v", denied)
	}
}

// applyAsOldBuild is a build with fv below nodeDenyFSMOpsVersion: its switch
// has no case for opDenyNode, so the op lands on the default branch.
func applyAsOldBuild(t *testing.T, f *placementFSM, index uint64, cmd command) any {
	t.Helper()
	if cmd.Op == opDenyNode {
		cmd.Op = opCode(255)
	}
	return applyDenyLogAt(t, f, index, cmd)
}

// Mixed versions. The gate means an old leader never commits opDenyNode
// and a new leader commits it only once every server can apply it, so the
// log an old FSM sees has none: on such a log old and new end in exactly the
// same state. The second half shows what the gate prevents: an old FSM fed
// the op fails it and diverges from the new one by the deny records.
func TestFSMDenyNodeMixedVersionDeterminism(t *testing.T) {
	var gated []command
	for _, cmd := range denyTestLog() {
		if cmd.Op != opDenyNode {
			gated = append(gated, cmd)
		}
	}
	oldFSM, newFSM := newPlacementFSM(), newPlacementFSM()
	for i, cmd := range gated {
		if err := asApplyErr(applyAsOldBuild(t, oldFSM, uint64(i+1), cmd)); err != nil {
			t.Fatalf("old build, entry %d: %v", i, err)
		}
		if err := asApplyErr(applyDenyLogAt(t, newFSM, uint64(i+1), cmd)); err != nil {
			t.Fatalf("new build, entry %d: %v", i, err)
		}
	}
	if o, n := viewOf(oldFSM), viewOf(newFSM); !reflect.DeepEqual(o, n) {
		t.Fatalf("same log, different state:\n old %+v\n new %+v", o, n)
	}

	oldFSM, newFSM = newPlacementFSM(), newPlacementFSM()
	sawUnknown := false
	for i, cmd := range denyTestLog() {
		if err := asApplyErr(applyAsOldBuild(t, oldFSM, uint64(i+1), cmd)); err != nil {
			if cmd.Op != opDenyNode || !strings.Contains(err.Error(), "unknown op") {
				t.Fatalf("old build, entry %d: %v", i, err)
			}
			sawUnknown = true
		}
		applyDenyLogAt(t, newFSM, uint64(i+1), cmd)
	}
	o, n := viewOf(oldFSM), viewOf(newFSM)
	if !sawUnknown || len(o.denied) != 0 || len(n.denied) != 2 {
		t.Fatalf("ungated log: old denied %+v, new denied %+v", o.denied, n.denied)
	}
	o.denied, o.deniedAt, n.denied, n.deniedAt = nil, 0, nil, 0
	if !reflect.DeepEqual(o, n) {
		t.Fatalf("outside the deny records the state must match:\n old %+v\n new %+v", o, n)
	}
}

// The gate on the write path: with a Raft server on an older build the
// leader refuses, and the op never reaches the log.
func TestWriteNodeDenyRefusedDuringRollingUpgrade(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newTestCluster(t, "deny-gate", true, nil)
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	if err := leader.raft.raft.AddNonvoter("old-server", raft.ServerAddress("127.0.0.1:1"), 0, time.Second).Error(); err != nil {
		t.Fatalf("add old server: %v", err)
	}
	leader.gossip.memberIndex.upsert(Member{NodeID: "old-server", Alive: false, Role: config.NodeRoleServer, FSMOpsVersion: nodeDenyFSMOpsVersion - 1})
	if _, err := leader.writeNodeDeny(ctx, "wkr-1", config.NodeRoleWorker); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("deny with an old server = %v, want ErrClusterVersion", err)
	}
	if nodes, v := leader.fsm.deniedNodesView(); len(nodes) != 0 || v != 0 {
		t.Fatalf("a refused deny reached the FSM: %+v at %d", nodes, v)
	}
	leader.gossip.memberIndex.upsert(Member{NodeID: "old-server", Alive: false, Role: config.NodeRoleServer, FSMOpsVersion: nodeDenyFSMOpsVersion})
	res, err := leader.writeNodeDeny(ctx, "wkr-1", config.NodeRoleWorker)
	if err != nil || !res.Changed {
		t.Fatalf("deny once upgraded = %+v %v", res, err)
	}
	if again, err := leader.writeNodeDeny(ctx, "wkr-1", config.NodeRoleWorker); err != nil || again.Changed || again.Record.DeniedUnixNano != res.Record.DeniedUnixNano {
		t.Fatalf("repeat deny = %+v %v, want the first record unchanged", again, err)
	}
	if !leader.IsNodeDenied("wkr-1") {
		t.Fatal("IsNodeDenied after the write")
	}

	// No peer can carry the op past the gate on the generic forward path.
	payload, _ := encodeCommand(denyCmd("wkr-2", 1))
	if err := leader.ApplyEncoded(ctx, payload); !errors.Is(err, errDenyNodeNotForwardable) {
		t.Fatalf("forwarded opDenyNode = %v", err)
	}
	if leader.IsNodeDenied("wkr-2") {
		t.Fatal("a forwarded deny landed")
	}
}

func TestWriteNodeDenyWithoutRaft(t *testing.T) {
	var nilCluster *Cluster
	if _, err := nilCluster.writeNodeDeny(context.Background(), "wkr-1", ""); err == nil {
		t.Fatal("nil cluster wrote a deny")
	}
	if nilCluster.IsNodeDenied("wkr-1") {
		t.Fatal("nil cluster denied a node")
	}
	if resp, changed := nilCluster.DeniedNodes(0); changed || resp.Nodes == nil {
		t.Fatalf("nil cluster DeniedNodes = %+v %v", resp, changed)
	}
}

// DeniedNodes answers "no change" for a cursor at or past this server's
// version, so a lagging server never hands an agent an older set as news.
func TestClusterDeniedNodesCursor(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	if _, changed := c.DeniedNodes(0); changed {
		t.Fatal("an empty set at version 0 is not news")
	}
	applyDenyLogAt(t, c.fsm, 12, denyCmd("wkr-1", 1))
	resp, changed := c.DeniedNodes(0)
	if !changed || resp.Version != 12 || len(resp.Nodes) != 1 || resp.Nodes[0].NodeID != "wkr-1" {
		t.Fatalf("DeniedNodes(0) = %+v %v", resp, changed)
	}
	for _, since := range []uint64{12, 40} {
		if _, changed := c.DeniedNodes(since); changed {
			t.Fatalf("DeniedNodes(%d) reported a change", since)
		}
	}
}
