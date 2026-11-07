package cluster

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Regression tests for the active version and rollout ops
// (fsm_rollout.go): apply, compare-and-set, snapshot/restore, replay and
// the mixed-version rule (CLAUDE.md rule 6).

func newTestRollout(id, target string, nodes ...*RolloutNodeRecord) *RolloutRecord {
	r := &RolloutRecord{
		ID: id, TargetVersion: target, PreviousVersion: "v1", Source: upgradewire.SourceUpload, Caller: "pat:op",
		Batch: "10%", NodeTimeoutNanos: int64(10 * time.Minute),
		Files: map[string]string{"sandboxd_linux_amd64": strings.Repeat("a", 64), "toolboxd_linux_amd64": strings.Repeat("b", 64)},
		Nodes: map[string]*RolloutNodeRecord{},
	}
	for _, n := range nodes {
		r.Nodes[n.NodeID] = n
	}
	return r
}

func applyCmd(id, target string, nodes ...*RolloutNodeRecord) command {
	return command{Op: opRolloutCommand, StampUnixNano: 10, RolloutCmd: &RolloutCommand{Event: evApply, New: newTestRollout(id, target, nodes...), Target: target}}
}

func eventCmd(id, event string, stamp int64) command {
	return command{Op: opRolloutCommand, StampUnixNano: stamp, RolloutCmd: &RolloutCommand{Event: event, RolloutID: id}}
}

func nodeCmd(u RolloutNodeUpdate, stamp int64) command {
	return command{Op: opRolloutNode, StampUnixNano: stamp, RolloutNode: &u}
}

func activeCmd(fv, expect int, release string, stamp int64) command {
	return command{Op: opSetActiveVersion, StampUnixNano: stamp, ActiveVersion: &ActiveVersionCommand{FV: fv, ExpectFV: expect, Release: release}}
}

func rolloutRes(t *testing.T, v any) rolloutApplyResult {
	t.Helper()
	res, ok := v.(rolloutApplyResult)
	if !ok {
		t.Fatalf("apply returned %T %v", v, v)
	}
	return res
}

func twoNodes() []*RolloutNodeRecord {
	return []*RolloutNodeRecord{
		{NodeID: "s1", Tier: rolloutTierServer, Arch: "amd64", State: upgradewire.NodePending, Order: 1},
		{NodeID: "w1", Tier: rolloutTierWorker, Arch: "amd64", State: upgradewire.NodePending, Order: 2, Batch: 1},
	}
}

func TestFSMActiveVersionCompareAndSet(t *testing.T) {
	f := newPlacementFSM()
	if f.activeFVValue() != 0 {
		t.Fatal("a new FSM has an active version")
	}
	res := applyDenyLogAt(t, f, 1, activeCmd(12, 0, "v0.6.12", 100)).(activeVersionApplyResult)
	if !res.Changed || res.Active.FV != 12 || res.Active.SetUnixNano != 100 || f.activeFVValue() != 12 {
		t.Fatalf("first write = %+v", res)
	}
	// A stale compare-and-set, a lower version and a repeat change nothing.
	for _, cmd := range []command{activeCmd(13, 0, "x", 1), activeCmd(11, 12, "x", 1), activeCmd(12, 12, "v0.6.12", 1)} {
		if res := applyDenyLogAt(t, f, 2, cmd).(activeVersionApplyResult); res.Changed || res.Active.FV != 12 {
			t.Fatalf("write %+v = %+v, want unchanged", cmd.ActiveVersion, res)
		}
	}
	if res := applyDenyLogAt(t, f, 3, activeCmd(13, 12, "v0.7.0", 200)).(activeVersionApplyResult); !res.Changed || f.activeFVValue() != 13 {
		t.Fatalf("advance = %+v", res)
	}
	if a, ok := f.activeVersionView(); !ok || a.Release != "v0.7.0" {
		t.Fatalf("view = %+v %v", a, ok)
	}
	if err := asApplyErr(applyDenyLogAt(t, f, 4, command{Op: opSetActiveVersion})); err == nil {
		t.Fatal("an empty active-version write applied")
	}
	var nilFSM *placementFSM
	if nilFSM.activeFVValue() != 0 {
		t.Fatal("nil FSM active")
	}
}

func TestFSMRolloutLifecycle(t *testing.T) {
	f := newPlacementFSM()
	res := rolloutRes(t, applyDenyLogAt(t, f, 1, applyCmd("r1", "v2", twoNodes()...)))
	if !res.Changed || res.Verdict.Outcome != outcomeNew || res.Rollout.State != upgradewire.StateStaging || res.Rollout.CreatedUnixNano != 10 || res.Rollout.StateUnixNano != 10 {
		t.Fatalf("apply = %+v", res)
	}
	// The same apply again answers the existing rollout, writing nothing.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 2, applyCmd("r1-dup", "v2"))); res.Changed || res.Verdict.Outcome != outcomeExisting || res.Rollout.ID != "r1" {
		t.Fatalf("repeat apply = %+v", res)
	}
	// Another target is refused while it runs.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 3, applyCmd("r9", "v3"))); res.Changed || res.Verdict.Outcome != outcomeRefused {
		t.Fatalf("apply other = %+v", res)
	}
	// Nodes stage; a CAS on the wrong state and a move the table refuses
	// change nothing.
	for _, id := range []string{"s1", "w1"} {
		res := rolloutRes(t, applyDenyLogAt(t, f, 4, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: id, State: upgradewire.NodeStaged, ExpectState: upgradewire.NodePending,
			Version: "v1", Arch: "amd64", PrevFiles: map[string]string{"sandboxd_linux_amd64": "old-" + id}}, 20)))
		if !res.Changed || res.Rollout.Nodes[id].State != upgradewire.NodeStaged {
			t.Fatalf("stage %s = %+v", id, res)
		}
	}
	if got := f.rollout.PrevFiles["sandboxd_linux_amd64"]; got != "old-s1" {
		t.Fatalf("prev files = %v, want the first report to win", f.rollout.PrevFiles)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone, ExpectState: upgradewire.NodePending}, 21))); res.Changed {
		t.Fatalf("CAS on the wrong state applied: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeSkipped}, 21))); !res.Changed {
		t.Fatalf("staged -> skipped refused: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeUpgrading}, 21))); res.Changed {
		t.Fatalf("skipped -> upgrading applied: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone, Version: "v2"}, 22))); !res.Changed {
		t.Fatalf("skipped -> done refused: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "ghost", State: upgradewire.NodeDone}, 22))); res.Changed {
		t.Fatalf("unknown node applied: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "other", NodeID: "w1", State: upgradewire.NodeDone}, 22))); res.Changed {
		t.Fatalf("other rollout's node write applied: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 6, eventCmd("r1", evAllStaged, 30))); !res.Changed || res.Rollout.State != upgradewire.StateRunning {
		t.Fatalf("all staged = %+v", res)
	}
	// upgrading carries op, term and the deadline; done clears the deadline.
	res = rolloutRes(t, applyDenyLogAt(t, f, 7, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeUpgrading, Op: "op1", Term: 3, DeadlineUnixNano: 999, Error: "x"}, 31)))
	if n := res.Rollout.Nodes["w1"]; n.Op != "op1" || n.Term != 3 || n.DeadlineUnixNano != 999 || n.Error != "x" {
		t.Fatalf("upgrading = %+v", n)
	}
	if dl, ok := f.upgradingDeadline("w1"); !ok || dl.UnixNano() != 999 {
		t.Fatalf("upgrading deadline = %v %v", dl, ok)
	}
	res = rolloutRes(t, applyDenyLogAt(t, f, 8, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeDone, Version: "v2", ClearError: true}, 32)))
	if n := res.Rollout.Nodes["w1"]; n.DeadlineUnixNano != 0 || n.Error != "" || n.Version != "v2" {
		t.Fatalf("done = %+v", n)
	}
	if _, ok := f.upgradingDeadline("w1"); ok {
		t.Fatal("a done node still has a deadline")
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 9, eventCmd("r1", evAllDone, 40))); res.Rollout.State != upgradewire.StateDone {
		t.Fatalf("all done = %+v", res)
	}
	// Finalize moves the active version in the same entry.
	fin := eventCmd("r1", evFinalize, 50)
	fin.RolloutCmd.Active = &ActiveVersion{FV: 13, Release: "v2"}
	res = rolloutRes(t, applyDenyLogAt(t, f, 10, fin))
	if res.Rollout.State != upgradewire.StateFinalizing || f.activeFVValue() != 13 {
		t.Fatalf("finalize = %+v active %d", res, f.activeFVValue())
	}
	if a, _ := f.activeVersionView(); a.Release != "v2" || a.RolloutID != "r1" || a.SetUnixNano != 50 {
		t.Fatalf("active after finalize = %+v", a)
	}
	for _, id := range []string{"s1", "w1"} {
		applyDenyLogAt(t, f, 11, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: id, Migrated: true}, 51))
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 12, eventCmd("r1", evMigrated, 60))); res.Rollout.State != upgradewire.StateFinalized {
		t.Fatalf("migrated = %+v", res)
	}
	// A finalized rollout lets a new target in.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 13, applyCmd("r2", "v3", twoNodes()...))); res.Verdict.Outcome != outcomeNew || f.rollout.ID != "r2" {
		t.Fatalf("next rollout = %+v", res)
	}
	// A command for a replaced rollout is refused.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 14, eventCmd("r1", evStop, 70))); res.Changed || res.Verdict.Outcome != outcomeRefused {
		t.Fatalf("stale stop = %+v", res)
	}
	for _, bad := range []command{{Op: opRolloutCommand}, {Op: opRolloutNode}, {Op: opRolloutNode, RolloutNode: &RolloutNodeUpdate{RolloutID: "r2"}}} {
		if err := asApplyErr(applyDenyLogAt(t, f, 15, bad)); err == nil {
			t.Fatalf("bad rollout entry %+v applied", bad)
		}
	}
	// A new rollout without its record is an error, not an empty rollout.
	if err := asApplyErr(applyDenyLogAt(t, newPlacementFSM(), 1, command{Op: opRolloutCommand, RolloutCmd: &RolloutCommand{Event: evApply, Target: "zz"}})); err == nil {
		t.Fatal("an apply without its record applied")
	}
}

// stop, restage (apply again), rollback and the node resets they make.
func TestFSMRolloutStopRestageRollback(t *testing.T) {
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 1, applyCmd("r1", "v2", twoNodes()...))
	applyDenyLogAt(t, f, 2, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone}, 11))
	applyDenyLogAt(t, f, 3, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeFailed, Error: "disk"}, 11))
	stop := eventCmd("r1", evStop, 12)
	stop.RolloutCmd.Error = "stopped by pat:op"
	if res := rolloutRes(t, applyDenyLogAt(t, f, 4, stop)); res.Rollout.State != upgradewire.StateStopped || res.Rollout.Error != "stopped by pat:op" {
		t.Fatalf("stop = %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, eventCmd("r1", evStop, 13))); res.Changed || res.Verdict.Outcome != outcomeNoop {
		t.Fatalf("second stop = %+v", res)
	}
	res := rolloutRes(t, applyDenyLogAt(t, f, 6, applyCmd("ignored", "v2")))
	if res.Verdict.Outcome != outcomeRestage || res.Rollout.ID != "r1" || res.Rollout.State != upgradewire.StateStaging || res.Rollout.Attempt != 1 {
		t.Fatalf("apply again = %+v", res)
	}
	if res.Rollout.Nodes["s1"].State != upgradewire.NodeDone || res.Rollout.Nodes["w1"].State != upgradewire.NodePending || res.Rollout.Nodes["w1"].Error != "" {
		t.Fatalf("restage nodes = %+v %+v", res.Rollout.Nodes["s1"], res.Rollout.Nodes["w1"])
	}
	applyDenyLogAt(t, f, 7, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeSkipped}, 14))
	applyDenyLogAt(t, f, 8, eventCmd("r1", evStop, 15))
	res = rolloutRes(t, applyDenyLogAt(t, f, 9, eventCmd("r1", evRollback, 16)))
	if res.Rollout.State != upgradewire.StateRollingBack || res.Rollout.Direction != upgradewire.DirectionRollback || res.Rollout.Attempt != 2 {
		t.Fatalf("rollback = %+v", res)
	}
	if res.Rollout.Nodes["s1"].State != upgradewire.NodePending || res.Rollout.Nodes["w1"].State != upgradewire.NodeSkipped {
		t.Fatalf("rollback nodes = %+v %+v", res.Rollout.Nodes["s1"], res.Rollout.Nodes["w1"])
	}
	// Apply the same target while rolling back is refused.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 10, applyCmd("x", "v2"))); res.Verdict.Outcome != outcomeRefused {
		t.Fatalf("apply during rollback = %+v", res)
	}
	applyDenyLogAt(t, f, 11, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone}, 17))
	if res := rolloutRes(t, applyDenyLogAt(t, f, 12, eventCmd("r1", evRolledBack, 18))); res.Rollout.State != upgradewire.StateRolledBack {
		t.Fatalf("rolled back = %+v", res)
	}
	// After a rollback the same target starts a new rollout.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 13, applyCmd("r3", "v2", twoNodes()...))); res.Verdict.Outcome != outcomeNew || res.Rollout.ID != "r3" {
		t.Fatalf("apply after rollback = %+v", res)
	}
}

func TestFSMRolloutAddNodeAndPause(t *testing.T) {
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 1, applyCmd("r1", "v2", twoNodes()...))
	add := &RolloutNodeRecord{Tier: rolloutTierWorker, State: upgradewire.NodeDone, Order: 3}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 2, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w9", Add: add}, 5))); !res.Changed || res.Rollout.Nodes["w9"].NodeID != "w9" {
		t.Fatalf("add = %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 3, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w9", Add: &RolloutNodeRecord{}}, 6))); res.Changed {
		t.Fatalf("second add applied: %+v", res)
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 4, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w8", Add: &RolloutNodeRecord{}}, 6))); res.Rollout.Nodes["w8"].State != upgradewire.NodePending {
		t.Fatalf("add without a state = %+v", res.Rollout.Nodes["w8"])
	}
	if res := rolloutRes(t, applyDenyLogAt(t, f, 5, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", Pause: true, ManualCommand: "sudo x"}, 7))); !res.Rollout.Paused || res.Rollout.Nodes["w1"].ManualCommand != "sudo x" {
		t.Fatalf("pause mark = %+v", res.Rollout)
	}
}

// rolloutTestLog is a whole rollout: apply, staging, a pause, a node
// failure, apply again, done, finalize with the active version.
func rolloutTestLog() []command {
	nodes := twoNodes()
	nodes[0].State = upgradewire.NodePending
	fin := eventCmd("r1", evFinalize, 90)
	fin.RolloutCmd.Active = &ActiveVersion{FV: 13, Release: "v2"}
	return []command{
		activeCmd(12, 0, "v1", 1),
		applyCmd("r1", "v2", nodes...),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeStaged, Version: "v1", Arch: "amd64", PrevFiles: map[string]string{"sandboxd_linux_amd64": "p"}}, 20),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeStaged}, 21),
		eventCmd("r1", evAllStaged, 22),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeUpgrading, Op: "o", Term: 2, DeadlineUnixNano: 100}, 23),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone, Version: "v2"}, 24),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeUpgrading, Op: "o", Term: 2}, 25),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeFailed, Error: "boom"}, 26),
		eventCmd("r1", evNodeFailed, 27),
		applyCmd("again", "v2"),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeStaged}, 30),
		eventCmd("r1", evAllStaged, 31),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeUpgrading, Op: "o2"}, 32),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeDone, Version: "v2"}, 33),
		eventCmd("r1", evAllDone, 34),
		fin,
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", Migrated: true}, 91),
	}
}

type rolloutFSMView struct {
	active  ActiveVersion
	rollout *RolloutRecord
	fv      int
}

func rolloutViewOf(f *placementFSM) rolloutFSMView {
	r, a := f.rolloutView()
	return rolloutFSMView{active: a, rollout: r, fv: f.activeFVValue()}
}

func TestFSMRolloutSnapshotReplay(t *testing.T) {
	log := rolloutTestLog()
	full := newPlacementFSM()
	for i, cmd := range log {
		if err := asApplyErr(applyDenyLogAt(t, full, uint64(i+1), cmd)); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	want := rolloutViewOf(full)
	if want.rollout.State != upgradewire.StateFinalizing || want.fv != 13 || !want.rollout.Nodes["s1"].Migrated {
		t.Fatalf("full replay = %+v", want.rollout)
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
		if got := rolloutViewOf(resumed); !reflect.DeepEqual(got, want) {
			t.Fatalf("cut at %d: resumed %+v\nwant %+v", cut, got.rollout, want.rollout)
		}
	}
	// A snapshot from before rollouts restores as "never written, none".
	old := newPlacementFSM()
	old.activeVersion = &ActiveVersion{FV: 1}
	old.rollout = &RolloutRecord{ID: "x"}
	old.restoreRolloutLocked(nil, nil)
	if old.activeFVValue() != 0 || old.rollout != nil {
		t.Fatal("restore of an older snapshot kept state")
	}
	old.restoreRolloutLocked(&ActiveVersion{FV: 13}, &RolloutRecord{ID: "y"})
	if old.activeFVValue() != 13 || old.rollout.Nodes == nil {
		t.Fatal("restore without nodes")
	}
}

// applyAsFV12 is a build without the rollout ops: they land on the default
// branch and fail as unknown.
func applyAsFV12(t *testing.T, f *placementFSM, index uint64, cmd command) any {
	t.Helper()
	if isRolloutOp(cmd.Op) {
		cmd.Op = opCode(253)
	}
	return applyDenyLogAt(t, f, index, cmd)
}

// Gated, an old and a new FSM reach the same placement state from the
// same log (the gate keeps rollout ops out until every server runs fv
// 14); ungated, the old one fails only the rollout ops.
func TestFSMRolloutMixedVersionDeterminism(t *testing.T) {
	base := []command{denyCmd("wkr-x", 5), {Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "node-a", OwnerAPIURL: "http://a", IncarnationID: "inc-1"}}
	oldFSM, newFSM := newPlacementFSM(), newPlacementFSM()
	for i, cmd := range base {
		if err := asApplyErr(applyAsFV12(t, oldFSM, uint64(i+1), cmd)); err != nil {
			t.Fatalf("old build: %v", err)
		}
		applyDenyLogAt(t, newFSM, uint64(i+1), cmd)
	}
	if !reflect.DeepEqual(joinViewOf(oldFSM).base.placements, joinViewOf(newFSM).base.placements) {
		t.Fatal("gated log diverged")
	}
	unknown := 0
	for i, cmd := range rolloutTestLog() {
		if err := asApplyErr(applyAsFV12(t, oldFSM, uint64(i+10), cmd)); err != nil {
			if !strings.Contains(err.Error(), "unknown op") {
				t.Fatalf("old build failed a rollout op with %v", err)
			}
			unknown++
		}
		applyDenyLogAt(t, newFSM, uint64(i+10), cmd)
	}
	if unknown != len(rolloutTestLog()) || oldFSM.rollout != nil || newFSM.rollout == nil {
		t.Fatalf("ungated: %d unknown, old rollout %v", unknown, oldFSM.rollout)
	}
	if !reflect.DeepEqual(joinViewOf(oldFSM).base.placements, joinViewOf(newFSM).base.placements) {
		t.Fatal("placements diverged outside the rollout state")
	}
}

func TestRolloutAPIViewAndFiles(t *testing.T) {
	if RolloutAPIView(nil, ActiveVersion{}) != nil {
		t.Fatal("view of no rollout")
	}
	r := newTestRollout("r1", "v2", twoNodes()...)
	r.State, r.Direction = upgradewire.StateRunning, upgradewire.DirectionUpgrade
	r.PrevFiles = map[string]string{"sandboxd_linux_amd64": "p"}
	v := RolloutAPIView(r, ActiveVersion{FV: 13, Release: "v1"})
	if v.ID != "r1" || v.NodeTimeout != "10m0s" || v.ActiveVersion != "v1" || v.ActiveFSMOpsVersion != 13 || len(v.Nodes) != 2 || v.Nodes[0].NodeID != "s1" {
		t.Fatalf("view = %+v", v)
	}
	keep := rolloutFileSet(r)
	if len(keep) != 3 || !keep["p"] || len(rolloutFileSet(nil)) != 0 {
		t.Fatalf("file set = %v", keep)
	}
	if !rolloutTerminal(nil) || rolloutTerminal(r) {
		t.Fatal("terminal")
	}
	if got := sortedKeys(map[string]string{"b": "", "a": ""}); got[0] != "a" {
		t.Fatalf("sortedKeys = %v", got)
	}
	if cloneRollout(nil) != nil || stateOf(nil) != stateNone {
		t.Fatal("nil helpers")
	}
	if !errors.Is(errRolloutOpNotForwardable, errRolloutOpNotForwardable) || !isRolloutOp(opRolloutNode) || isRolloutOp(opDenyNode) {
		t.Fatal("op helpers")
	}
}

// R12: staging, stop, a pause and a failure start no new restart (§6.6).
// The FSM refuses a node's move to upgrading then, so a leader that read
// "running" just before a stop landed cannot mark one. A node already
// upgrading is still followed to its result.
func TestFSMRolloutNoNewRestartOutsideRunning(t *testing.T) {
	f := newPlacementFSM()
	up := func(index uint64, id string) rolloutApplyResult {
		return rolloutRes(t, applyDenyLogAt(t, f, index, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: id, State: upgradewire.NodeUpgrading, Op: "r1-u0", DeadlineUnixNano: 500}, int64(index))))
	}
	applyDenyLogAt(t, f, 1, applyCmd("r1", "v2", twoNodes()...))
	if res := up(2, "s1"); res.Changed || res.Rollout.Nodes["s1"].State != upgradewire.NodePending {
		t.Fatalf("a restart started while staging: %+v", res.Rollout.Nodes["s1"])
	}
	for i, id := range []string{"s1", "w1"} {
		applyDenyLogAt(t, f, uint64(3+i), nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: id, State: upgradewire.NodeStaged}, 12))
	}
	applyDenyLogAt(t, f, 5, eventCmd("r1", evAllStaged, 13))
	if res := up(6, "s1"); !res.Changed || res.Rollout.Nodes["s1"].State != upgradewire.NodeUpgrading {
		t.Fatalf("running refused a restart: %+v", res.Rollout.Nodes["s1"])
	}
	applyDenyLogAt(t, f, 7, eventCmd("r1", evStop, 14))
	if res := up(8, "w1"); res.Changed || res.Rollout.Nodes["w1"].State != upgradewire.NodeStaged {
		t.Fatalf("a stopped rollout started a restart: %+v", res.Rollout.Nodes["w1"])
	}
	// The restart in flight is finished, not dropped.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 9, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone, ExpectState: upgradewire.NodeUpgrading, Version: "v2"}, 15))); !res.Changed {
		t.Fatalf("the restart in flight could not finish: %+v", res.Verdict)
	}
}

// R3: a deleted node leaves the rollout (§5, §6.2). A skipped node then no
// longer holds finalize, a node deleted while finalizing no longer holds
// the migrations, and a node deleted before a rollout's apply or a join's
// add lands never enters it. The drop rides on opDenyNode, so a replay or a
// snapshot reaches the same record.
func TestFSMRolloutDeletedNodeLeavesTheRollout(t *testing.T) {
	f := newPlacementFSM()
	log := []command{
		applyCmd("r1", "v2", twoNodes()...),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeStaged}, 11),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", State: upgradewire.NodeSkipped, Error: "down"}, 12),
		eventCmd("r1", evAllStaged, 13),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeUpgrading, Op: "r1-u0", DeadlineUnixNano: 99}, 14),
		nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "s1", State: upgradewire.NodeDone, Version: "v2"}, 15),
		eventCmd("r1", evAllDone, 16),
	}
	for i, cmd := range log {
		applyDenyLogAt(t, f, uint64(i+1), cmd)
	}
	if v := decideRollout(f.rollout, rolloutEvent{Kind: evFinalize}); v.Code != upgradewire.ErrCodeSkippedNodes {
		t.Fatalf("finalize with w1 skipped = %+v", v)
	}
	// aerolvm delete node w1: what the refusal's own hint says to do.
	applyDenyLogAt(t, f, 20, denyCmd("w1", 30))
	if _, still := f.rollout.Nodes["w1"]; still {
		t.Fatalf("a deleted node stayed in the rollout: %s", describeNodes(f.rollout))
	}
	if v := decideRollout(f.rollout, rolloutEvent{Kind: evFinalize}); v.Outcome != outcomeMove {
		t.Fatalf("finalize after deleting the skipped node = %+v", v)
	}
	// A replica that restores a snapshot taken after the delete holds the
	// same record.
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	back := newPlacementFSM()
	if err := back.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rolloutViewOf(back), rolloutViewOf(f)) {
		t.Fatalf("restored %s, want %s", describeNodes(back.rollout), describeNodes(f.rollout))
	}
	// A join cannot add it back while it is denied.
	if res := rolloutRes(t, applyDenyLogAt(t, f, 21, nodeCmd(RolloutNodeUpdate{RolloutID: "r1", NodeID: "w1", Add: &RolloutNodeRecord{}}, 31))); res.Changed || res.Rollout.Nodes["w1"] != nil {
		t.Fatalf("a denied node was added: %+v", res)
	}
	// Deleted while finalizing: the migrations no longer wait for it.
	g := newPlacementFSM()
	nodes := twoNodes()
	nodes[0].State, nodes[1].State = upgradewire.NodeDone, upgradewire.NodeDone
	fin := eventCmd("r2", evFinalize, 41)
	fin.RolloutCmd.Active = &ActiveVersion{FV: 13, Release: "v2"}
	for i, cmd := range []command{applyCmd("r2", "v2", nodes...), eventCmd("r2", evAllStaged, 40), eventCmd("r2", evAllDone, 40), fin,
		nodeCmd(RolloutNodeUpdate{RolloutID: "r2", NodeID: "s1", Migrated: true}, 42)} {
		applyDenyLogAt(t, g, uint64(i+1), cmd)
	}
	if g.rollout.State != upgradewire.StateFinalizing {
		t.Fatalf("setup: %s", g.rollout.State)
	}
	if v := decideRollout(g.rollout, rolloutEvent{Kind: evMigrated}); v.Outcome != outcomeRefused {
		t.Fatalf("migrated before the delete = %+v", v)
	}
	applyDenyLogAt(t, g, 10, denyCmd("w1", 50))
	if res := rolloutRes(t, applyDenyLogAt(t, g, 11, eventCmd("r2", evMigrated, 51))); res.Rollout.State != upgradewire.StateFinalized {
		t.Fatalf("a node deleted while finalizing still holds the rollout: %s %s", res.Rollout.State, describeNodes(res.Rollout))
	}
	// A rollout whose apply lands after the delete never holds the node.
	h := newPlacementFSM()
	applyDenyLogAt(t, h, 1, denyCmd("w1", 5))
	if res := rolloutRes(t, applyDenyLogAt(t, h, 2, applyCmd("r3", "v2", twoNodes()...))); res.Rollout.Nodes["w1"] != nil || res.Rollout.Nodes["s1"] == nil {
		t.Fatalf("new rollout over a deleted node: %s", describeNodes(res.Rollout))
	}
}
