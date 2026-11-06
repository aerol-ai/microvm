package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// reclaimFSM is an FSM with a delete_with_sandbox volume "vol-d" held by
// sb-1 alone, a second one "vol-s" shared by sb-1 and sb-2, and a plain
// volume "vol-k" on sb-1.
func reclaimFSM(t *testing.T) (*placementFSM, func(command) any) {
	t.Helper()
	f := newPlacementFSM()
	idx := uint64(0)
	apply := func(cmd command) any {
		t.Helper()
		idx++
		return f.Apply(&raft.Log{Index: idx, Data: mustEncode(t, cmd)})
	}
	must := func(cmd command) {
		t.Helper()
		if got := apply(cmd); got != nil {
			t.Fatalf("apply %d: %v", cmd.Op, got)
		}
	}
	must(volCmd(models.Volume{ID: "vol-d", Tenant: "t-a", Name: "d", Backend: "s3", Source: "b/d", DeleteWithSandbox: true}, 0))
	must(volCmd(models.Volume{ID: "vol-s", Tenant: "t-a", Name: "s", Backend: "s3", Source: "b/s", DeleteWithSandbox: true}, 0))
	must(volCmd(models.Volume{ID: "vol-k", Tenant: "t-a", Name: "k", Backend: "s3", Source: "b/k"}, 0))
	must(command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "wkr-a", IncarnationID: "inc-1"})
	must(command{Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "wkr-b", IncarnationID: "inc-2"})
	must(command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{
		{Tenant: "t-a", VolumeID: "vol-d", SandboxID: "sb-1", IncarnationID: "inc-1", Target: "/d", Source: "b/d"},
		{Tenant: "t-a", VolumeID: "vol-s", SandboxID: "sb-1", IncarnationID: "inc-1", Target: "/s", Source: "b/s"},
		{Tenant: "t-a", VolumeID: "vol-k", SandboxID: "sb-1", IncarnationID: "inc-1", Target: "/k", Source: "b/k"},
		{Tenant: "t-a", VolumeID: "vol-s", SandboxID: "sb-2", IncarnationID: "inc-2", Target: "/s", Source: "b/s"},
	}})
	return f, apply
}

func deleteWithReclaims(sandboxID, incarnationID, node string, stamp int64) command {
	return command{Op: opDelete, SandboxID: sandboxID, ExpectedIncarnationID: incarnationID, VolumeReclaimNodeID: node, StampUnixNano: stamp}
}

func reclaimIDs(rs []VolumeReclaim) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.VolumeID)
	}
	return out
}

// Review 2 finding 7, cluster half: the placement delete that releases the
// last attachment of a delete_with_sandbox volume records the obligation in
// the same apply, for exactly the volumes it was the last holder of, and a
// snapshot carries it to any replica (a restarted server, a new leader).
func TestFSMPlacementDeleteRecordsVolumeReclaim(t *testing.T) {
	f, apply := reclaimFSM(t)
	if got := apply(deleteWithReclaims("sb-1", "inc-1", "wkr-a", 100)); got != nil {
		t.Fatalf("opDelete: %v", got)
	}
	got := f.VolumeReclaims()
	if len(got) != 1 {
		t.Fatalf("reclaims = %+v, want only vol-d (vol-s is still held by sb-2, vol-k is not delete_with_sandbox)", got)
	}
	want := VolumeReclaim{Tenant: "t-a", VolumeID: "vol-d", Name: "d", Backend: "s3", Source: "b/d", SandboxID: "sb-1", NodeID: "wkr-a", RecordedUnixNano: 100}
	if got[0] != want {
		t.Fatalf("reclaim = %+v, want %+v", got[0], want)
	}
	if n := f.VolumeAttachmentCount("t-a", "vol-d"); n != 0 {
		t.Fatalf("vol-d still attached: %d", n)
	}

	// The second holder's delete records the shared volume.
	if got := apply(deleteWithReclaims("sb-2", "inc-2", "wkr-b", 200)); got != nil {
		t.Fatalf("opDelete sb-2: %v", got)
	}
	if ids := reclaimIDs(f.VolumeReclaims()); len(ids) != 2 || ids[0] != "vol-d" || ids[1] != "vol-s" {
		t.Fatalf("reclaims after sb-2 = %v, want [vol-d vol-s] oldest first", ids)
	}

	snap, err := f.Snapshot()
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
	if got, want := restored.VolumeReclaims(), f.VolumeReclaims(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("restored reclaims = %+v, want %+v", got, want)
	}
}

// No field, no record: a delete proposed while some server is older, or by
// an older build, leaves the FSM exactly as before (the mixed-version and
// single-node no-op). A stale incarnation's delete changes nothing either.
func TestFSMPlacementDeleteWithoutReclaimFieldRecordsNothing(t *testing.T) {
	f, apply := reclaimFSM(t)
	if got := apply(deleteWithReclaims("sb-1", "inc-stale", "wkr-a", 1)); got != nil {
		t.Fatalf("stale opDelete: %v", got)
	}
	if got := f.VolumeReclaims(); len(got) != 0 {
		t.Fatalf("a stale incarnation's delete recorded %+v", got)
	}
	if n := f.VolumeAttachmentCount("t-a", "vol-d"); n != 1 {
		t.Fatalf("a stale incarnation's delete released attachments: %d", n)
	}
	if got := apply(command{Op: opDelete, SandboxID: "sb-1", ExpectedIncarnationID: "inc-1"}); got != nil {
		t.Fatalf("opDelete: %v", got)
	}
	if got := f.VolumeReclaims(); len(got) != 0 {
		t.Fatalf("a delete without the field recorded %+v", got)
	}
	f.recordVolumeReclaimsLocked("", "wkr-a", 1)
	f.recordVolumeReclaimsLocked("sb-2", "", 1)
	if got := f.VolumeReclaims(); len(got) != 0 {
		t.Fatalf("blank sandbox or node recorded %+v", got)
	}
}

// An ack drops only the version it names; a claim moves only the entry it
// read, from the node it read.
func TestFSMVolumeReclaimAckAndClaim(t *testing.T) {
	f, apply := reclaimFSM(t)
	if got := apply(deleteWithReclaims("sb-1", "inc-1", "wkr-a", 100)); got != nil {
		t.Fatal(got)
	}
	entry := f.VolumeReclaims()[0]

	cases := []struct {
		name    string
		cmd     command
		wantErr error
		wantAny bool
		node    string
	}{
		{"claim from the wrong node", command{Op: opClaimVolumeReclaim, VolumeReclaim: &VolumeReclaim{Tenant: "t-a", VolumeID: "vol-d", NodeID: "wkr-x", RecordedUnixNano: 100}, NodeID: "wkr-c"}, ErrVolumeReclaimMoved, false, "wkr-a"},
		{"claim of an older version", command{Op: opClaimVolumeReclaim, VolumeReclaim: &VolumeReclaim{Tenant: "t-a", VolumeID: "vol-d", NodeID: "wkr-a", RecordedUnixNano: 99}, NodeID: "wkr-c"}, ErrVolumeReclaimMoved, false, "wkr-a"},
		{"claim of a missing entry", command{Op: opClaimVolumeReclaim, VolumeReclaim: &VolumeReclaim{Tenant: "t-a", VolumeID: "nope", NodeID: "wkr-a", RecordedUnixNano: 100}, NodeID: "wkr-c"}, ErrVolumeReclaimMoved, false, "wkr-a"},
		{"claim without a target", command{Op: opClaimVolumeReclaim, VolumeReclaim: &entry}, nil, true, "wkr-a"},
		{"claim without an entry", command{Op: opClaimVolumeReclaim, NodeID: "wkr-c"}, nil, true, "wkr-a"},
		{"claim", command{Op: opClaimVolumeReclaim, VolumeReclaim: &entry, NodeID: "wkr-c"}, nil, false, "wkr-c"},
		{"ack of an older version", command{Op: opAckVolumeReclaim, VolumeReclaim: &VolumeReclaim{Tenant: "t-a", VolumeID: "vol-d", RecordedUnixNano: 99}}, nil, false, "wkr-c"},
		{"ack without tenant", command{Op: opAckVolumeReclaim, VolumeReclaim: &VolumeReclaim{VolumeID: "vol-d", RecordedUnixNano: 100}}, nil, true, "wkr-c"},
	}
	for _, tc := range cases {
		got := apply(tc.cmd)
		err, _ := got.(error)
		switch {
		case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.wantErr)
		case tc.wantAny && err == nil:
			t.Fatalf("%s: want a validation error", tc.name)
		case tc.wantErr == nil && !tc.wantAny && got != nil:
			t.Fatalf("%s: %v", tc.name, got)
		}
		if rs := f.VolumeReclaims(); len(rs) != 1 || rs[0].NodeID != tc.node {
			t.Fatalf("%s: reclaims = %+v, want one held by %s", tc.name, rs, tc.node)
		}
	}
	if got := apply(command{Op: opAckVolumeReclaim, VolumeReclaim: &entry}); got != nil {
		t.Fatal(got)
	}
	if rs := f.VolumeReclaims(); len(rs) != 0 {
		t.Fatalf("after ack = %+v", rs)
	}
	if got := apply(command{Op: opAckVolumeReclaim, VolumeReclaim: &entry}); got != nil {
		t.Fatalf("a repeated ack must be a no-op: %v", got)
	}
}

func TestFSMVolumeReclaimsForOwnThenAdoptable(t *testing.T) {
	f := newPlacementFSM()
	now := time.Unix(10_000, 0)
	young := now.Add(-time.Minute).UnixNano()
	old := now.Add(-2 * volumeReclaimAdoptAfter).UnixNano()
	f.restoreVolumeReclaimsLocked([]VolumeReclaim{
		{Tenant: "t", VolumeID: "own-new", NodeID: "me", RecordedUnixNano: young},
		{Tenant: "t", VolumeID: "own-old", NodeID: "me", RecordedUnixNano: old},
		{Tenant: "t", VolumeID: "dead-old", NodeID: "dead", RecordedUnixNano: old},
		{Tenant: "t", VolumeID: "dead-young", NodeID: "dead", RecordedUnixNano: young},
		{Tenant: "t", VolumeID: "server-young", NodeID: "srv", RecordedUnixNano: young},
		{Tenant: "t", VolumeID: "busy-old", NodeID: "busy", RecordedUnixNano: old},
		{Tenant: "", VolumeID: "bad"},
	})
	state := func(node string) (bool, bool) {
		switch node {
		case "busy":
			return true, true // a live worker drains its own
		case "srv":
			return true, false // a live server never drains
		}
		return false, false // dead or unknown
	}
	if ids := reclaimIDs(f.volumeReclaimsFor(" me ", state, now, 0)); len(ids) != 4 || ids[0] != "own-old" || ids[1] != "own-new" || ids[2] != "dead-old" || ids[3] != "server-young" {
		t.Fatalf("for me = %v, want own oldest first, then the dead node's old entry and the server's", ids)
	}
	if ids := reclaimIDs(f.volumeReclaimsFor("me", state, now, 1)); len(ids) != 1 || ids[0] != "own-old" {
		t.Fatalf("limited = %v", ids)
	}
	if ids := reclaimIDs(f.volumeReclaimsFor("me", nil, now, 0)); len(ids) != 2 {
		t.Fatalf("no membership view = %v, want own only", ids)
	}
	// The index follows a claim and an ack.
	busy := f.VolumeReclaims()
	for _, r := range busy {
		if r.VolumeID == "busy-old" {
			f.mu.Lock()
			if err := f.applyClaimVolumeReclaimLocked(command{VolumeReclaim: &r, NodeID: "me"}); err != nil {
				t.Fatal(err)
			}
			f.mu.Unlock()
			r.NodeID = "me"
			if ids := reclaimIDs(f.volumeReclaimsFor("me", state, now, 0)); len(ids) != 5 {
				t.Fatalf("after claim = %v", ids)
			}
			f.mu.Lock()
			if err := f.applyAckVolumeReclaimLocked(command{VolumeReclaim: &r}); err != nil {
				t.Fatal(err)
			}
			f.mu.Unlock()
		}
	}
	f.mu.RLock()
	_, busyBucket := f.volumeReclaimsByNode["busy"]
	n := len(f.volumeReclaimsByNode["me"])
	f.mu.RUnlock()
	if busyBucket || n != 2 {
		t.Fatalf("index after claim+ack: busy bucket %v, me %d", busyBucket, n)
	}
}

// Who may take an entry over, from this server's membership view: never
// from a live worker; at once from a live node that never drains; from a
// dead or unknown node only once the entry is old.
func TestGossipReclaimNodeState(t *testing.T) {
	index := newGossipMemberIndex()
	index.replace([]Member{
		{NodeID: "wkr-live", Alive: true, Role: string(config.NodeRoleWorker)},
		{NodeID: "mixed-live", Alive: true, Role: string(config.NodeRoleMixed)},
		{NodeID: "srv-live", Alive: true, Role: string(config.NodeRoleServer)},
		{NodeID: "wkr-dead", Alive: false, Role: string(config.NodeRoleWorker)},
	})
	state := gossipReclaimNodeState(&gossipNode{memberIndex: index})
	cases := []struct {
		node          string
		alive, drains bool
	}{
		{"wkr-live", true, true},
		{"mixed-live", true, true},
		{"srv-live", true, false},
		{"wkr-dead", false, false},
		{"gone", false, false},
	}
	for _, tc := range cases {
		if alive, drains := state(tc.node); alive != tc.alive || drains != tc.drains {
			t.Fatalf("%s: alive=%v drains=%v, want %v %v", tc.node, alive, drains, tc.alive, tc.drains)
		}
	}
	if alive, _ := gossipReclaimNodeState(nil)("x"); alive {
		t.Fatal("no gossip view: nothing is alive")
	}
}

// The gate: an opDelete asks for the record only when every replica applies
// it, and names the node that will drain it.
func TestStampVolumeReclaimsGate(t *testing.T) {
	cmd := command{Op: opDelete}
	stampVolumeReclaims(&cmd, false, "wkr-a")
	stampVolumeReclaims(&cmd, true, " ")
	if cmd.VolumeReclaimNodeID != "" || cmd.StampUnixNano != 0 {
		t.Fatalf("stamped without the gate: %+v", cmd)
	}
	stampVolumeReclaims(&cmd, true, " wkr-a ")
	if cmd.VolumeReclaimNodeID != "wkr-a" || cmd.StampUnixNano == 0 {
		t.Fatalf("not stamped: %+v", cmd)
	}
	if _, err := claimVolumeReclaimCommand(VolumeReclaim{}, " "); err == nil {
		t.Fatal("a claim needs a target node")
	}

	// Agent: the gate is every live member on this build.
	index := newGossipMemberIndex()
	index.replace([]Member{{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}, {NodeID: "srv", Alive: true, FSMOpsVersion: fsmOpsVersion}})
	a := &Agent{gossip: &gossipNode{memberIndex: index}}
	if !a.VolumeReclaimsReplicated() {
		t.Fatal("agent gate closed with every member upgraded")
	}
	index.upsert(Member{NodeID: "old", Alive: true, FSMOpsVersion: volumeReclaimFSMOpsVersion - 1})
	if a.VolumeReclaimsReplicated() {
		t.Fatal("agent gate open with an older member live")
	}
	var nilAgent *Agent
	var nilCluster *Cluster
	if nilAgent.VolumeReclaimsReplicated() || nilCluster.VolumeReclaimsReplicated() || (&Cluster{}).VolumeReclaimsReplicated() {
		t.Fatal("a nil client must not ask for the record")
	}
	if rs, err := nilCluster.VolumeReclaimsFor(context.Background(), "x", 1); err != nil || rs == nil || len(rs) != 0 {
		t.Fatalf("nil cluster list = %#v, %v", rs, err)
	}
}

// End to end on a real single-server Raft: a destroy's placement delete
// records the reclaim, the owner lists it, another node takes it over, and
// the ack after the bytes are gone removes it.
func TestClusterPlacementDeleteRecordsVolumeReclaimRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}
	c, cleanup := newTestCluster(t, "ldr-vol-reclaim", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if !c.VolumeReclaimsReplicated() {
		t.Fatal("a single server on this build must open the gate")
	}
	v := models.Volume{ID: "vol-r", Tenant: "t-a", Name: "scratch", Backend: "s3", Source: "bucket/t-a/scratch", DeleteWithSandbox: true}
	if _, _, err := c.VolumeUpsert(ctx, v, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.RecordPlacement(ctx, "sb-r", nil, PlacementSecrets{IncarnationID: "inc-sb-r"}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "vol-r", SandboxID: "sb-r", IncarnationID: "inc-sb-r", Target: "/scratch", Source: v.Source,
	}}); err != nil {
		t.Fatal(err)
	}
	p, ok := c.PlacementOf("sb-r")
	if !ok {
		t.Fatal("no placement")
	}
	if err := c.DeletePlacementExact(ctx, "sb-r", p.OwnerNodeID, p.IncarnationID); err != nil {
		t.Fatal(err)
	}
	mine, err := c.VolumeReclaimsFor(ctx, c.SelfNodeID(), 10)
	if err != nil || len(mine) != 1 || mine[0].VolumeID != "vol-r" || mine[0].NodeID != c.SelfNodeID() {
		t.Fatalf("owner's reclaims = %+v, %v", mine, err)
	}
	if err := c.ClaimVolumeReclaim(ctx, mine[0], " "); err == nil {
		t.Fatal("claim without a node must fail")
	}
	if err := c.ClaimVolumeReclaim(ctx, mine[0], "wkr-other"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := c.ClaimVolumeReclaim(ctx, mine[0], "wkr-third"); !errors.Is(err, ErrVolumeReclaimMoved) {
		t.Fatalf("second claim of the old holder = %v, want ErrVolumeReclaimMoved", err)
	}
	all := c.fsm.VolumeReclaims()
	if len(all) != 1 || all[0].NodeID != "wkr-other" {
		t.Fatalf("after claim = %+v", all)
	}
	if err := c.AckVolumeReclaim(ctx, all[0]); err != nil {
		t.Fatal(err)
	}
	if left := c.fsm.VolumeReclaims(); len(left) != 0 {
		t.Fatalf("after ack = %+v", left)
	}
}
