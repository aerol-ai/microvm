package cluster

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Tests for the rollout commands (rollout.go): input checks, the batch
// rule, node order, and the commands on a real one-node Raft cluster.

func TestParseRolloutBatch(t *testing.T) {
	cases := []struct {
		batch   string
		workers int
		want    int
		bad     bool
	}{
		{"", 25, 3, false}, {"10%", 25, 3, false}, {"10%", 5, 1, false}, {"10%", 0, 1, false},
		{"3", 25, 3, false}, {"100%", 7, 7, false}, {"50%", 3, 2, false}, {" 2 ", 9, 2, false},
		{"0", 5, 0, true}, {"0%", 5, 0, true}, {"150%", 5, 0, true}, {"-1", 5, 0, true}, {"x", 5, 0, true}, {"abc%", 5, 0, true},
	}
	for _, c := range cases {
		got, err := ParseRolloutBatch(c.batch, c.workers)
		if c.bad != (err != nil) || (!c.bad && got != c.want) {
			t.Fatalf("ParseRolloutBatch(%q, %d) = %d %v, want %d bad=%v", c.batch, c.workers, got, err, c.want, c.bad)
		}
	}
}

func TestOrderRolloutNodes(t *testing.T) {
	m := func(id, role, v string) rolloutMember {
		mm := Member{NodeID: id, Role: role, Version: v, Arch: "arm64"}
		return rolloutMember{Member: mm, tier: rolloutTierOf(mm, role == "server")}
	}
	members := []rolloutMember{m("s2", "server", "v1"), m("s1", "server", "v1"), m("i1", "ingress", "v1")}
	for i := 1; i <= 5; i++ {
		members = append(members, m("w"+string(rune('0'+i)), "worker", "v1"))
	}
	members = append(members, m("w9", "worker", "v2"))
	r := &RolloutRecord{TargetVersion: "v2", Batch: "2", PauseAfter: 1, Nodes: map[string]*RolloutNodeRecord{}}
	if err := orderRolloutNodes(r, members, "s1", false); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, n := range r.sortedNodes() {
		order = append(order, n.NodeID)
	}
	if strings.Join(order, ",") != "s2,s1,i1,w1,w2,w3,w4,w5,w9" {
		t.Fatalf("order = %v (the leader goes last among the servers)", order)
	}
	// --pause-after 1 cuts the first batch to 1, then batches of 2.
	batches := []int{r.Nodes["w1"].Batch, r.Nodes["w2"].Batch, r.Nodes["w3"].Batch, r.Nodes["w4"].Batch, r.Nodes["w5"].Batch}
	if batches[0] != 1 || batches[1] != 2 || batches[2] != 2 || batches[3] != 3 || batches[4] != 3 {
		t.Fatalf("batches = %v", batches)
	}
	if r.Nodes["w9"].State != upgradewire.NodeDone || r.Nodes["w1"].Arch != "arm64" || r.Nodes["s1"].Batch != 0 {
		t.Fatalf("w9 %+v w1 %+v", r.Nodes["w9"], r.Nodes["w1"])
	}
	// One voter: the server goes after every worker.
	r = &RolloutRecord{TargetVersion: "v2", Batch: "10%", Nodes: map[string]*RolloutNodeRecord{}}
	if err := orderRolloutNodes(r, members[1:3], "s1", true); err != nil {
		t.Fatal(err)
	}
	if r.Nodes["s1"].Order < r.Nodes["i1"].Order {
		t.Fatalf("one-voter order: %+v", r.sortedNodes())
	}
	if err := orderRolloutNodes(&RolloutRecord{Batch: "0", Nodes: map[string]*RolloutNodeRecord{}}, members, "s1", false); err == nil {
		t.Fatal("batch 0 accepted")
	}
	// Tiers: a Raft server; an ingress-only node; anything else.
	for _, c := range []struct {
		role   string
		server bool
		want   string
	}{{"worker", true, rolloutTierServer}, {"server", false, rolloutTierServer}, {"ingress", false, rolloutTierIngress}, {"worker,ingress", false, rolloutTierWorker}, {"", false, rolloutTierWorker}} {
		if got := rolloutTierOf(Member{Role: c.role}, c.server); got != c.want {
			t.Fatalf("tier of %q (server %v) = %s, want %s", c.role, c.server, got, c.want)
		}
	}
	if previousVersion([]rolloutMember{m("a", "worker", "v1"), m("b", "worker", "v1"), m("c", "worker", "v0"), m("d", "worker", "v2")}, "v2") != "v1" {
		t.Fatal("previous version is not the most common one")
	}
	if previousVersion(nil, version.Version) != "" || previousVersion(nil, "vX") != version.Version {
		t.Fatal("previous version fallback")
	}
}

func TestNodeFilesPerArch(t *testing.T) {
	h := func(c string) string { return strings.Repeat(c, 64) }
	files := map[string]string{
		"sandboxd_linux_amd64": h("a"), "toolboxd_linux_amd64": h("b"),
		"sandboxd_linux_arm64": h("c"), "toolboxd_linux_arm64": h("d"),
		"caddy": h("e"), release.FileName: h("f"), "junk": h("0"),
	}
	amd := nodeFiles(files, "amd64")
	if len(amd) != 4 || amd["sandboxd_linux_amd64"] == "" || amd["caddy"] == "" || amd[release.FileName] == "" || amd["sandboxd_linux_arm64"] != "" {
		t.Fatalf("amd64 files = %v", amd)
	}
	if err := checkNodeFiles(files, "arm64"); err != nil {
		t.Fatal(err)
	}
	if err := checkNodeFiles(files, "riscv64"); err == nil || !strings.Contains(err.Error(), "no sandboxd") {
		t.Fatalf("missing arch = %v", err)
	}
	dup := map[string]string{"sandboxd": h("a"), "sandboxd_linux_amd64": h("b"), "toolboxd": h("c")}
	if err := checkNodeFiles(dup, "amd64"); err == nil || !strings.Contains(err.Error(), "two sandboxd") {
		t.Fatalf("duplicate = %v", err)
	}
}

// rolloutTestCluster is a one-node Raft cluster with its rollout loop
// stopped (the tests drive it) and its upgrade files in a temp dir.
func rolloutTestCluster(t *testing.T) (*Cluster, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	c, cleanup := newTestCluster(t, "ro-1", true, nil)
	waitForLeader(t, c, 10*time.Second)
	c.rolloutStop()
	dir := t.TempDir()
	p := nodeupgrade.Paths{StateDir: filepath.Join(dir, "upgrade"), DBPath: filepath.Join(dir, "state.db")}
	c.upgrade.paths = func() (nodeupgrade.Paths, error) { return p, nil }
	return c, cleanup
}

func goodApply() upgradewire.ApplyRequest {
	return upgradewire.ApplyRequest{
		Version: "v99.0.0", Source: upgradewire.SourceRelease, AllowDowntime: true,
		Files: map[string]string{"sandboxd": strings.Repeat("a", 64), "toolboxd": strings.Repeat("b", 64)},
	}
}

func rolloutErrCode(err error) (int, string) {
	var re *RolloutError
	if errors.As(err, &re) {
		return re.Status, re.Body.Error
	}
	return 0, ""
}

func TestApplyRolloutOnOneNodeCluster(t *testing.T) {
	c, cleanup := rolloutTestCluster(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := c.GetRollout(ctx); func() bool { s, _ := rolloutErrCode(err); return s != http.StatusNotFound }() {
		t.Fatalf("get with no rollout = %v", err)
	}
	if _, err := c.RolloutCommand(ctx, "pat:op", RolloutStop); func() bool { s, _ := rolloutErrCode(err); return s != http.StatusNotFound }() {
		t.Fatalf("stop with no rollout = %v", err)
	}
	bad := []func(*upgradewire.ApplyRequest){
		func(r *upgradewire.ApplyRequest) { r.Version = "" },
		func(r *upgradewire.ApplyRequest) { r.Version = "not-a-tag" },
		func(r *upgradewire.ApplyRequest) { r.Source = "ftp" },
		func(r *upgradewire.ApplyRequest) { r.Files = nil },
		func(r *upgradewire.ApplyRequest) { r.Files["sandboxd"] = "XYZ" },
		func(r *upgradewire.ApplyRequest) { r.Files["../etc"] = strings.Repeat("c", 64) },
		func(r *upgradewire.ApplyRequest) { r.Batch = "0" },
		func(r *upgradewire.ApplyRequest) { r.Batch = "0%" },
		func(r *upgradewire.ApplyRequest) { r.Batch = "150%" },
		func(r *upgradewire.ApplyRequest) { r.PauseAfter = -1 },
		func(r *upgradewire.ApplyRequest) { r.NodeTimeout = "soon" },
		func(r *upgradewire.ApplyRequest) { delete(r.Files, "toolboxd") },
	}
	for i, edit := range bad {
		req := goodApply()
		edit(&req)
		if _, _, err := c.ApplyRollout(ctx, "pat:op", req); func() bool { s, _ := rolloutErrCode(err); return s != http.StatusBadRequest }() {
			t.Fatalf("bad request %d = %v", i, err)
		}
	}
	req := goodApply()
	req.AllowDowntime = false
	if _, _, err := c.ApplyRollout(ctx, "pat:op", req); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeNeedsDowntime }() {
		t.Fatalf("one voter without allow_downtime = %v", err)
	}
	req = goodApply()
	req.Source = upgradewire.SourceUpload
	if _, _, err := c.ApplyRollout(ctx, "pat:op", req); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeFilesMissing }() {
		t.Fatalf("upload with no files = %v", err)
	}
	out, created, err := c.ApplyRollout(ctx, "pat:op", goodApply())
	if err != nil || !created || out.State != upgradewire.StateStaging || out.Caller != "pat:op" || out.Batch != "10%" || out.NodeTimeout != "10m0s" || len(out.Nodes) != 1 {
		t.Fatalf("apply = %+v %v %v", out, created, err)
	}
	again, created, err := c.ApplyRollout(ctx, "pat:op", goodApply())
	if err != nil || created || again.ID != out.ID {
		t.Fatalf("repeat apply = %+v %v %v", again, created, err)
	}
	other := goodApply()
	other.Files["sandboxd"] = strings.Repeat("9", 64)
	if _, _, err := c.ApplyRollout(ctx, "pat:op", other); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeRolloutConflict }() {
		t.Fatalf("same version, other files = %v", err)
	}
	other = goodApply()
	other.Version = "v100.0.0"
	if _, _, err := c.ApplyRollout(ctx, "pat:op", other); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeRolloutConflict }() {
		t.Fatalf("other target while staging = %v", err)
	}
	got, err := c.GetRollout(ctx)
	if err != nil || got.ID != out.ID {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := c.RolloutCommand(ctx, "pat:op", "dance"); func() bool { s, _ := rolloutErrCode(err); return s != http.StatusBadRequest }() {
		t.Fatalf("unknown command = %v", err)
	}
	if _, err := c.RolloutCommand(ctx, "pat:op", RolloutFinalize); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeRolloutConflict }() {
		t.Fatalf("finalize while staging = %v", err)
	}
	stopped, err := c.RolloutCommand(ctx, "pat:op", RolloutStop)
	if err != nil || stopped.State != upgradewire.StateStopped || !strings.Contains(stopped.Error, "pat:op") {
		t.Fatalf("stop = %+v %v", stopped, err)
	}
	if again, err := c.RolloutCommand(ctx, "pat:op", RolloutStop); err != nil || again.State != upgradewire.StateStopped {
		t.Fatalf("second stop = %+v %v", again, err)
	}
	if _, err := c.RolloutCommand(ctx, "pat:op", RolloutResume); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeRolloutConflict }() {
		t.Fatalf("resume a stopped rollout = %v", err)
	}
	back, err := c.RolloutCommand(ctx, "pat:op", RolloutRollback)
	if err != nil || back.State != upgradewire.StateRollingBack || back.Direction != upgradewire.DirectionRollback {
		t.Fatalf("rollback = %+v %v", back, err)
	}
	// The leader writes rollouts; a raw forward of the op is refused.
	payload, _ := encodeCommand(eventCmd(out.ID, evStop, 1))
	if err := c.ApplyEncoded(ctx, payload); !errors.Is(err, errRolloutOpNotForwardable) {
		t.Fatalf("forwarded rollout op = %v", err)
	}
}

func TestFinalizeCommandMovesActiveVersion(t *testing.T) {
	c, cleanup := rolloutTestCluster(t)
	defer cleanup()
	ctx := context.Background()
	req := goodApply()
	req.Version = version.Version // the node already runs it: done at once
	req.AllowUnversioned = true
	req.Hold = true
	if _, _, err := c.ApplyRollout(ctx, "pat:op", req); err != nil {
		t.Fatal(err)
	}
	r, _ := c.fsm.rolloutView()
	if r.Nodes["ro-1"].State != upgradewire.NodeDone {
		t.Fatalf("node on the target = %+v", r.Nodes["ro-1"])
	}
	if res, err := c.proposeRolloutCommand(ctx, RolloutCommand{Event: evAllStaged, RolloutID: r.ID}); err != nil || res.Rollout.State != upgradewire.StateRunning {
		t.Fatalf("all staged = %+v %v", res, err)
	}
	if res, _ := c.proposeRolloutCommand(ctx, RolloutCommand{Event: evAllDone, RolloutID: r.ID}); res.Rollout.State != upgradewire.StateDone {
		t.Fatalf("all done = %+v", res)
	}
	out, err := c.RolloutCommand(ctx, "pat:op", RolloutFinalize)
	if err != nil || out.State != upgradewire.StateFinalizing || out.ActiveFSMOpsVersion != fsmOpsVersion || out.ActiveVersion != version.Version {
		t.Fatalf("finalize = %+v %v", out, err)
	}
	if again, err := c.RolloutCommand(ctx, "pat:op", RolloutFinalize); err != nil || again.State != upgradewire.StateFinalizing {
		t.Fatalf("second finalize = %+v %v", again, err)
	}
	if a, ok := c.ActiveVersion(); !ok || a.FV != fsmOpsVersion || c.ActiveFSMOpsVersion() != fsmOpsVersion {
		t.Fatalf("active = %+v %v", a, ok)
	}
	if _, err := c.RolloutCommand(ctx, "pat:op", RolloutRollback); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeRolloutConflict }() {
		t.Fatalf("rollback after finalize = %v", err)
	}
	// The finalize step runs this node's one-way migrations.
	runs := 0
	c.AttachOneWayMigrator(func(context.Context) error { runs++; return nil }, false)
	if c.SchemaFinalized() {
		t.Fatal("finished before finalize ran")
	}
	c.driver.inline = true
	c.driver.tick(ctx)
	c.driver.tick(ctx)
	if runs != 1 || !c.SchemaFinalized() {
		t.Fatalf("migrations ran %d times", runs)
	}
	if r, _ := c.fsm.rolloutView(); r.State != upgradewire.StateFinalized {
		t.Fatalf("after finalize steps: %s", r.State)
	}
}

func TestActiveVersionFirstWriteAndGate(t *testing.T) {
	c, cleanup := rolloutTestCluster(t)
	defer cleanup()
	ctx := context.Background()
	// Before the first write the per-server check stands.
	if err := c.raftServersSupport(fsmOpsVersion+1, "a future feature"); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("future feature before the first write = %v", err)
	}
	if err := c.raftServersSupport(joinFSMOpsVersion, "join tokens"); err != nil {
		t.Fatalf("a feature on today = %v", err)
	}
	c.reconcileActiveVersion(ctx)
	a, ok := c.ActiveVersion()
	if !ok || a.FV != fsmOpsVersion || a.Release != version.Version {
		t.Fatalf("first write = %+v %v", a, ok)
	}
	// Nothing that was on turns off; a newer feature waits for finalize.
	for _, v := range []int{egressProfileFSMOpsVersion, apiTokenFSMOpsVersion, nodeDenyFSMOpsVersion, joinFSMOpsVersion, rolloutFSMOpsVersion} {
		if err := c.raftServersSupport(v, "f"); err != nil {
			t.Fatalf("fv %d off after the first write: %v", v, err)
		}
	}
	if err := c.raftServersSupport(fsmOpsVersion+1, "a future feature"); !errors.Is(err, ErrClusterVersion) || !strings.Contains(err.Error(), "finalize") {
		t.Fatalf("future feature = %v", err)
	}
	// A repeat writes nothing; with no rollout the advance needs a higher fv.
	c.reconcileActiveVersion(ctx)
	if b, _ := c.ActiveVersion(); b != a {
		t.Fatalf("second reconcile moved it: %+v", b)
	}
	if c.memberObsolete(fsmOpsVersion) || !c.memberObsolete(fsmOpsVersion-1) || c.membersBelowActive() != 0 {
		t.Fatal("obsolete rule")
	}
	c.refreshRolloutGauges()
	if activeFSMOpsGauge.Value() != int64(fsmOpsVersion) {
		t.Fatalf("gauge = %d", activeFSMOpsGauge.Value())
	}
	if _, err := c.TransferLeadership(ctx, "ro-1"); err != nil {
		t.Fatalf("transfer to self = %v", err)
	}
	if _, err := c.TransferLeadership(ctx, "ghost"); func() bool { s, _ := rolloutErrCode(err); return s != http.StatusBadRequest }() {
		t.Fatalf("transfer to a non-voter = %v", err)
	}
	if _, err := c.TransferLeadership(ctx, ""); err == nil {
		t.Fatal("a one-voter cluster handed off leadership")
	}
}

func TestRolloutCommandsNeedTheLeader(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	if _, _, err := c.ApplyRollout(context.Background(), "x", goodApply()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("apply on a non-leader = %v", err)
	}
	if _, err := c.RolloutCommand(context.Background(), "x", RolloutStop); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("stop on a non-leader = %v", err)
	}
	if _, err := c.TransferLeadership(context.Background(), ""); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("transfer on a non-leader = %v", err)
	}
	if (&RolloutError{Body: upgradewire.ErrorResponse{Error: "e"}}).Error() != "e" {
		t.Fatal("error text")
	}
	if !sameFiles(map[string]string{"a": "1"}, map[string]string{"a": "1"}) || sameFiles(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Fatal("sameFiles")
	}
}

func TestCheckSkew(t *testing.T) {
	c := &Cluster{}
	r := &RolloutRecord{TargetVersion: "v0.6.12", Nodes: map[string]*RolloutNodeRecord{"a": {NodeID: "a", Version: "v0.6.11"}}}
	if err := c.checkSkew(r); err != nil {
		t.Fatalf("upgrade = %v", err)
	}
	r.Nodes["b"] = &RolloutNodeRecord{NodeID: "b", Version: "v0.7.0"}
	if err := c.checkSkew(r); func() bool { _, code := rolloutErrCode(err); return code != upgradewire.ErrCodeSkew }() {
		t.Fatalf("downgrade = %v", err)
	}
	r.AllowUnversioned = true
	if err := c.checkSkew(r); err != nil {
		t.Fatalf("unversioned = %v", err)
	}
}
