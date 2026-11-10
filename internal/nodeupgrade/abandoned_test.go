package nodeupgrade

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// J15 follow-through: once the API sees an upgrader is gone it lets a new
// op start, so the new upgrader settles the abandoned op first, as boot
// recovery would. Otherwise the old record would be settled at some later
// boot, after the new op moved the node on, and put its old files back.
func TestRunSettlesAnAbandonedOpFirst(t *testing.T) {
	old := newRelease("v0.6.11")
	next := newRelease("v0.6.12")
	r := newRig(t, old)
	crashAt(t, r, r.from(next), "swapped:toolboxd", "")
	abandoned, err := listStates(r.paths.StateDir)
	if err != nil || len(abandoned) != 1 || abandoned[0].terminal() {
		t.Fatalf("crash left %+v %v", abandoned, err)
	}
	later := newRelease("v0.6.13")
	st, err := r.u.Run(context.Background(), r.from(later))
	if err != nil || st.Result != ResultUpgraded {
		t.Fatalf("new op = %+v, %v\n%s", st, err, r.out)
	}
	r.assertInstalled(later, later.caddy)
	settled, _ := LoadState(r.paths.StateDir, abandoned[0].Op)
	if settled.Phase != PhaseFailed || settled.Result != ResultRevertedAtBoot || !strings.Contains(r.out.String(), "settling it first") {
		t.Fatalf("abandoned op = %+v\n%s", settled, r.out)
	}
	// A later boot finds nothing to do, so it cannot undo the new op.
	if res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out); err != nil || len(res) != 0 {
		t.Fatalf("recover after = %+v %v", res, err)
	}
	r.assertInstalled(later, later.caddy)
}

// A record settled late, after another upgrade moved the node on, never
// brings its stale backup back over the database the newer binary uses,
// even on a single node whose newer binary ran one-way migrations: the
// sandboxd on disk is not the one that op replaced.
func TestLateSettleNeverRestoresAStaleBackup(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	first, err := r.u.Run(context.Background(), r.from(newWithOneWay()))
	if err != nil {
		t.Fatalf("first upgrade: %v\n%s", err, r.out)
	}
	later := newRelease("v0.6.13")
	later.sandboxd = fakeBinary("v0.6.13", true, knowsOneWay)
	if _, err := r.u.Run(context.Background(), r.from(later)); err != nil {
		t.Fatalf("second upgrade: %v\n%s", err, r.out)
	}
	addNote(t, r.paths.DBPath, "written by v0.6.13")
	// The first op's record, as a dead upgrader would have left it mid-revert.
	stale := *first
	stale.Op, stale.Phase, stale.Result = "20261107t130000-0badc0de", PhaseRevert, ""
	raw, _ := json.Marshal(stale)
	if err := os.WriteFile(statePath(r.paths.StateDir, stale.Op), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
	if err != nil || len(res) != 1 {
		t.Fatalf("recover = %+v %v", res, err)
	}
	got, _ := LoadState(r.paths.StateDir, stale.Op)
	if got.BackupRestored || !hasNote(t, r.paths.DBPath, "written by v0.6.13") || !slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) {
		t.Fatalf("a stale backup came back: %+v\n%s", got, r.out)
	}
	r.assertInstalled(later, later.caddy)
}

// Settling an op while sandboxd runs (a retried op, or one abandoned
// under a live daemon) never restores the database under it; it says the
// next start settles it instead.
func TestSettleUnderALiveDaemonNeverRestores(t *testing.T) {
	old := newRelease("v0.6.11")
	r := newRig(t, old)
	singleNodeDB(t, r, "SB_ENABLE_CLUSTER=false\n")
	req := r.from(newWithOneWay("UNHEALTHY"))
	req.Op = "20261107t140000-0000beef"
	crashAt(t, r, req, "reverting", "")
	if !r.host.UnitActive(context.Background(), sandboxdUnit) {
		t.Fatal("the rig's sandboxd should still be running at the crash")
	}
	st, err := r.u.Run(context.Background(), req)
	if err == nil || st.BackupRestored || !strings.Contains(r.out.String(), "was not put back") {
		t.Fatalf("retried op = %+v, %v\n%s", st, err, r.out)
	}
	if !slices.Contains(oneWayOf(t, r.paths.DBPath), fakeOneWay) {
		t.Fatal("the database was restored under a running sandboxd")
	}
}
