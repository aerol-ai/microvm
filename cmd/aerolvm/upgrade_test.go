package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// distDir writes a --from directory: v0.6.13's amd64 files, release.json
// and the release's whole checksums.txt.
func distDir(t *testing.T, version string, meta bool) (string, map[string][]byte) {
	t.Helper()
	var m = releaseMeta(version, "v0.6.12", "install-13", []int{1, 2})
	if !meta {
		m = nil
	}
	all := releaseFiles(version, m, "amd64", "arm64")
	dir := t.TempDir()
	for _, n := range []string{"sandboxd_linux_amd64", "toolboxd_linux_amd64", "caddy_linux_amd64", "release.json"} {
		if b, ok := all[n]; ok {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, checksumsName), checksumsFor(all), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, all
}

func (h *harness) cleanTranscript(code int, repl ...string) string {
	return strings.NewReplacer(repl...).Replace(h.transcript(code))
}

// The CLI reads cluster mode from /health and takes the matching routes.
func TestUpgradeTellsClusterFromSingleNode(t *testing.T) {
	for _, tc := range []struct {
		cluster bool
		want    string
	}{
		{true, "No rollout has run on this cluster.\n"},
		{false, "No upgrade has run on this node. It runs v0.6.12.\n"},
	} {
		f := newFakeUpgrade(t, tc.cluster, "v0.6.12")
		h := upgradeHarness(t, f)
		if code := h.run("upgrade", "status"); code != exitOK || h.stdout.String() != tc.want {
			t.Fatalf("cluster=%v: %d %q %q", tc.cluster, code, h.stdout.String(), h.stderr.String())
		}
		if code := h.run("upgrade", "status", "-o", "json"); code != exitOK || h.stdout.String() != "null\n" {
			t.Fatalf("cluster=%v json: %q", tc.cluster, h.stdout.String())
		}
		single, cluster := f.sawCall("GET "+upgradewire.NodeUpgradePath), f.sawCall("GET "+upgradewire.ClusterUpgradePath)
		if tc.cluster && (single != 0 || cluster != 2) || !tc.cluster && (single != 2 || cluster != 0) {
			t.Fatalf("cluster=%v: node route %d, cluster route %d", tc.cluster, single, cluster)
		}
	}
}

func TestUpgradeSingleNodeFromDirWaitRepeatRollback(t *testing.T) {
	f := newFakeUpgrade(t, false, "v0.6.12")
	f.dropOnStep = "swapping"
	h := upgradeHarness(t, f)
	dir, all := distDir(t, "v0.6.13", true)
	repl := []string{dir, "<dist>"}

	code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait")
	if code != exitOK {
		t.Fatalf("apply = %d %s", code, h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-single-wait.golden", h.cleanTranscript(code, repl...))
	if f.running != "v0.6.13" || len(f.files) != 4 || f.sawCall("PUT "+upgradewire.NodeUpgradeFilesPath+"/"+sha(all["sandboxd_linux_amd64"])) != 1 {
		t.Fatalf("node runs %s with %d files", f.running, len(f.files))
	}
	req := f.nodeReqs[0]
	if req.Source != upgradewire.SourceUpload || req.Version != "v0.6.13" || len(req.Files) != 4 || req.Files["release.json"] != sha(all["release.json"]) || req.HealthTimeout != "" {
		t.Fatalf("request = %+v", req)
	}

	// A repeat: the files are there (HEAD), nothing is uploaded, the node
	// says it already runs the version.
	puts := len(f.files)
	code = h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait")
	if code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-single-again.golden", h.cleanTranscript(code, repl...))
	if len(f.files) != puts || len(f.ops) != 1 {
		t.Fatal("a repeat uploaded or started something")
	}

	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"upgrade", "status"}, "status-single.golden"},
		{[]string{"upgrade", "status", "-o", "json"}, "status-single-json.golden"},
		{[]string{"upgrade", "status", "--output", "yaml"}, "status-single-yaml.golden"},
	} {
		if code := h.run(tc.args...); code != exitOK {
			t.Fatal(h.stderr.String())
		}
		checkGoldenIn(t, "upgrade", tc.golden, h.transcript(exitOK))
	}

	// Roll back, then again: the second one sees its own rollback.
	code = h.run("upgrade", "rollback", "--wait")
	if code != exitOK || f.running != "v0.6.12" {
		t.Fatalf("rollback = %d %s", code, h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "rollback-single-wait.golden", h.transcript(code))
	if rb := f.nodeReqs[len(f.nodeReqs)-1]; !rb.Rollback || rb.Version != "v0.6.12" || len(rb.Files) != 0 {
		t.Fatalf("rollback request = %+v", rb)
	}
	if code := h.run("upgrade", "rollback"); code != exitOK || !strings.Contains(h.stdout.String(), "already rolled back to v0.6.12 (upgrade op-2)") || len(f.ops) != 2 {
		t.Fatalf("second rollback = %d %q", code, h.stdout.String())
	}
	if code := h.run("upgrade", "rollback", "-o", "json"); code != exitOK || !strings.Contains(h.stdout.String(), `"rollback": true`) {
		t.Fatalf("rollback json = %q", h.stdout.String())
	}
}

func TestUpgradeSingleNodeFromRelease(t *testing.T) {
	r := newFakeReleases(t)
	publishStd(r)
	f := newFakeUpgrade(t, false, "v0.6.12")
	h := upgradeHarness(t, f)
	h.env["AEROLVM_RELEASE_URL"] = r.base()
	code := h.run("upgrade", "apply", "v0.6.13", "--node-timeout", "3m")
	if code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-single.golden", h.transcript(code))
	req := f.nodeReqs[0]
	// Every CPU type goes; the node keeps its own. No upload.
	if req.Source != upgradewire.SourceRelease || len(req.Files) != 7 || req.HealthTimeout != "3m0s" || len(f.files) != 0 {
		t.Fatalf("request = %+v", req)
	}
	// While it runs, the same apply returns the same op; JSON prints it.
	if code := h.run("upgrade", "apply", "v0.6.13", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var op upgradewire.NodeUpgradeResponse
	h.jsonOut(&op)
	if op.Op != "op-1" || len(f.ops) != 1 {
		t.Fatalf("retry = %+v", op)
	}
	// Another version while it runs is refused.
	if code := h.run("upgrade", "apply", "v0.6.12", "--arch", "amd64"); code != exitError || !strings.Contains(h.stderr.String(), "upgrade op-1 is running") ||
		!strings.Contains(h.stderr.String(), "hint: aerolvm upgrade status") {
		t.Fatalf("busy = %d %q", code, h.stderr.String())
	}
	// A node below upgrade_from_min is refused before anything is sent.
	f2 := newFakeUpgrade(t, false, "v0.6.10")
	h2 := upgradeHarness(t, f2)
	h2.env["AEROLVM_RELEASE_URL"] = r.base()
	if code := h2.run("upgrade", "apply", "v0.6.13"); code != exitError || !strings.Contains(h2.stderr.String(), "can't be reached straight from v0.6.10") ||
		f2.sawCall("POST "+upgradewire.NodeUpgradePath) != 0 {
		t.Fatalf("skew = %d %q", code, h2.stderr.String())
	}
}

func TestUpgradeSingleNodeRefusals(t *testing.T) {
	dir, _ := distDir(t, "v0.6.13", true)
	f := newFakeUpgrade(t, false, "v0.6.12")
	h := upgradeHarness(t, f)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"upgrade", "apply", "v0.6.13", "--from", dir, "--hold"}, exitUsage, "--hold is for a cluster"},
		{[]string{"upgrade", "apply", "v0.6.13", "--from", dir, "--batch", "3"}, exitUsage, "--batch and --pause-after are for a cluster"},
		{[]string{"upgrade", "apply", "v0.6.13", "--from", dir, "--pause-after", "1"}, exitUsage, "--batch and --pause-after are for a cluster"},
		{[]string{"upgrade", "stop"}, exitError, "single node: there is no rollout to stop"},
		{[]string{"upgrade", "resume"}, exitError, "no rollout to resume"},
		{[]string{"upgrade", "finalize", "--json"}, exitError, upgradewire.ErrCodeNotClusterMode},
		{[]string{"upgrade", "rollback"}, exitError, "nothing to roll back"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q, want %q", tc.args, code, h.stderr.String(), tc.want)
		}
	}
	// SB_REMOTE_UPGRADE=false on the node: the refusal and its hint.
	f.remoteOff = true
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir); code != exitError ||
		!strings.Contains(h.stderr.String(), "SB_REMOTE_UPGRADE is off") || !strings.Contains(h.stderr.String(), "hint: on the node: sudo sandboxd upgrade node") {
		t.Fatalf("remote off = %d %q", code, h.stderr.String())
	}
	f.remoteOff = false
	// The upgrade fails on the node: exit 1, the node's reason, the journal.
	f.failWith = "the new sandboxd did not report v0.6.13 within 2m0s"
	code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait")
	if code != exitError {
		t.Fatalf("failed = %d", code)
	}
	checkGoldenIn(t, "upgrade", "apply-single-failed.golden", h.cleanTranscript(code, dir, "<dist>"))
	// A failed upgrade put the old files back: rollback has nothing to do.
	if code := h.run("upgrade", "rollback"); code != exitOK || !strings.Contains(h.stdout.String(), "already runs v0.6.12, the version before upgrade op-1") {
		t.Fatalf("rollback after failure = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	// An older sandboxd without the routes.
	f.noRoutes = true
	if code := h.run("upgrade", "status"); code != exitError || !strings.Contains(h.stderr.String(), "has no upgrade API") ||
		!strings.Contains(h.stderr.String(), "install.sh") {
		t.Fatalf("old sandboxd = %d %q", code, h.stderr.String())
	}
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir); code != exitError || !strings.Contains(h.stderr.String(), "has no upgrade API") {
		t.Fatalf("old sandboxd apply = %d %q", code, h.stderr.String())
	}
}

func TestUpgradeSingleRollbackCases(t *testing.T) {
	f := newFakeUpgrade(t, false, "v0.6.13")
	h := upgradeHarness(t, f)
	// An op still running, an op with no previous version.
	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-9", State: "swapping", Version: "v0.6.14", From: "v0.6.13"}}
	f.opSteps = []string{"swapping", "swapping"}
	f.opStep = 0
	f.failWith = ""
	if code := h.run("upgrade", "rollback"); code != exitError || !strings.Contains(h.stderr.String(), "upgrade op-9 is still") {
		t.Fatalf("running = %d %q", code, h.stderr.String())
	}
	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-8", State: "done", Version: "v0.6.13"}}
	if code := h.run("upgrade", "rollback"); code != exitError || !strings.Contains(h.stderr.String(), "recorded no previous version") {
		t.Fatalf("no from = %d %q", code, h.stderr.String())
	}
	// A rollback without --wait prints the op and the way to follow it.
	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-7", State: "done", Version: "v0.6.13", From: "v0.6.12"}}
	if code := h.run("upgrade", "rollback"); code != exitOK || h.stdout.String() != "rollback op-2 started: v0.6.13 -> v0.6.12\n" {
		t.Fatalf("rollback = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("upgrade", "rollback", "extra"); code != exitUsage {
		t.Fatal("rollback took an argument")
	}
	if code := h.run("upgrade", "rollback", "--node-timeout", "0s"); code != exitUsage {
		t.Fatal("zero timeout")
	}
	if code := h.run("upgrade", "rollback", "-o", "csv"); code != exitUsage {
		t.Fatal("bad -o")
	}
}

func TestUpgradeUsage(t *testing.T) {
	f := newFakeUpgrade(t, true, "v0.6.12")
	h := upgradeHarness(t, f)
	dir, _ := distDir(t, "v0.6.13", true)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"upgrade"}, "expected a subcommand"},
		{[]string{"upgrade", "go"}, `unknown subcommand "go"`},
		{[]string{"upgrade", "apply"}, "apply needs one version"},
		{[]string{"upgrade", "apply", "../x"}, "is not a version"},
		{[]string{"upgrade", "apply", "main"}, "pass --allow-unversioned"},
		{[]string{"upgrade", "apply", "v0.6.13", "-o", "wide"}, "-o must be json or yaml"},
		{[]string{"upgrade", "apply", "v0.6.13", "--batch", "0"}, "would never upgrade a worker"},
		{[]string{"upgrade", "apply", "v0.6.13", "--batch", "0%"}, "would never upgrade a worker"},
		{[]string{"upgrade", "apply", "v0.6.13", "--batch", "150%"}, "give at most 100%"},
		{[]string{"upgrade", "apply", "v0.6.13", "--batch", "ten"}, "is not a number of workers"},
		{[]string{"upgrade", "apply", "v0.6.13", "--batch", "-1"}, "is not a number of workers"},
		{[]string{"upgrade", "apply", "v0.6.13", "--pause-after", "-1"}, "must not be negative"},
		{[]string{"upgrade", "apply", "v0.6.13", "--node-timeout", "0s"}, "--node-timeout must be a positive"},
		{[]string{"upgrade", "apply", "v0.6.13", "--arch", "x86/64"}, "not a CPU type"},
		{[]string{"upgrade", "apply", "v0.6.13", "--nope"}, "nope"},
		{[]string{"upgrade", "status", "x"}, "status takes no argument"},
		{[]string{"upgrade", "status", "-o", "wide"}, "-o must be json or yaml"},
		{[]string{"upgrade", "status", "--nope"}, "nope"},
		{[]string{"upgrade", "stop", "x"}, "stop takes no argument"},
		{[]string{"upgrade", "stop", "-o", "wide"}, "-o must be json or yaml"},
		{[]string{"upgrade", "stop", "--nope"}, "nope"},
		{[]string{"upgrade", "rollback", "--nope"}, "nope"},
	} {
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q, want usage with %q", tc.args, code, h.stderr.String(), tc.want)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a usage error reached sandboxd: %v", f.calls)
	}
	// Accepted batch forms reach the server unchanged.
	for _, b := range []string{"10%", "3", "100%"} {
		f.rollout = nil
		if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--batch", b); code != exitOK {
			t.Fatalf("--batch %s = %d %s", b, code, h.stderr.String())
		}
		if got := f.applyReqs[len(f.applyReqs)-1].Batch; got != b {
			t.Fatalf("--batch %s sent %q", b, got)
		}
	}
	if got := h.run("help", "upgrade"); got != exitOK || !strings.Contains(h.stdout.String(), "aerolvm upgrade rollback [--wait]") {
		t.Fatal("help upgrade")
	}
	if got := h.run("upgrade", "--help"); got != exitOK || !strings.Contains(h.stdout.String(), "--pause-after N") {
		t.Fatal("upgrade --help")
	}
	if got := h.run("release", "-h"); got != exitOK || !strings.Contains(h.stdout.String(), "release pull <version>") {
		t.Fatal("release -h")
	}
}

func TestBatchSize(t *testing.T) {
	for _, tc := range []struct {
		spec    string
		workers int
		want    int
	}{
		{"10%", 25, 3}, {"10%", 5, 1}, {"", 30, 3}, {"3", 100, 3}, {"100%", 7, 7}, {"1%", 0, 1}, {"bad", 9, 1},
	} {
		if got := batchSize(tc.spec, tc.workers); got != tc.want {
			t.Errorf("batchSize(%q, %d) = %d, want %d", tc.spec, tc.workers, got, tc.want)
		}
	}
}

func TestUpgradeClusterApplyWaitPauseResumeFinalize(t *testing.T) {
	r := newFakeReleases(t)
	publishStd(r)
	f := newFakeUpgrade(t, true, "v0.6.12")
	stdFleet(f, "v0.6.12")
	f.advance = true
	h := upgradeHarness(t, f)
	h.env["AEROLVM_RELEASE_URL"] = r.base()

	// No --wait: it hands the rollout over and returns.
	f.advance = false
	code := h.run("upgrade", "apply", "v0.6.13", "--pause-after", "1", "--allow-downtime")
	if code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-cluster.golden", h.transcript(code))
	req := f.applyReqs[0]
	if req.Source != upgradewire.SourceRelease || req.PauseAfter != 1 || !req.AllowDowntime || req.NodeTimeout != "10m0s" || len(req.Files) != 7 || req.Hold {
		t.Fatalf("apply request = %+v", req)
	}
	// --wait on the same target follows the same rollout to the canary pause.
	f.advance = true
	code = h.run("upgrade", "apply", "v0.6.13", "--pause-after", "1", "--wait")
	if code != exitOK || f.rollout.State != upgradewire.StatePaused {
		t.Fatalf("wait = %d %s %s", code, f.rollout.State, h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-cluster-wait-paused.golden", h.transcript(code))
	if len(f.applyReqs) != 2 || f.nextID != 1 {
		t.Fatal("the same apply made a second rollout")
	}
	if code := h.run("upgrade", "resume"); code != exitOK || h.stdout.String() != "rollout r-1: running\n" {
		t.Fatalf("resume = %d %q", code, h.stdout.String())
	}
	if code := h.run("upgrade", "resume"); code != exitOK || h.stdout.String() != "rollout r-1: running\n" {
		t.Fatalf("resume again = %d %q", code, h.stdout.String())
	}
	code = h.run("upgrade", "apply", "v0.6.13", "--wait")
	if code != exitOK || f.rollout.State != upgradewire.StateFinalized {
		t.Fatalf("to the end = %d %s %s", code, f.rollout.State, h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "apply-cluster-wait-finalized.golden", h.transcript(code))
	// finalize after finalized, and apply of the same target: success, no change.
	if code := h.run("upgrade", "finalize"); code != exitOK || h.stdout.String() != "rollout r-1: finalized\n" {
		t.Fatalf("finalize again = %d %q", code, h.stdout.String())
	}
	// After finalize there is no rollback.
	if code := h.run("upgrade", "rollback"); code != exitError || !strings.Contains(h.stderr.String(), "after finalize there is no rollback") {
		t.Fatalf("rollback after finalize = %d %q", code, h.stderr.String())
	}
	// A new target is a new rollout.
	r.publish("v0.6.14", releaseFiles("v0.6.14", releaseMeta("v0.6.14", "v0.6.12", "install-14", []int{2}), "amd64"), true)
	f.advance = false
	if code := h.run("upgrade", "apply", "v0.6.14", "-o", "json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var ro upgradewire.Rollout
	h.jsonOut(&ro)
	if ro.ID != "r-2" || ro.State != upgradewire.StateStaging {
		t.Fatalf("new rollout = %+v", ro)
	}
	// Another target while that one runs is refused, with the way out.
	if code := h.run("upgrade", "apply", "v0.6.13"); code != exitError || !strings.Contains(h.stderr.String(), "rollout r-2 to v0.6.14 is staging") ||
		!strings.Contains(h.stderr.String(), "hint: finalize or roll back first") {
		t.Fatalf("other target = %d %q", code, h.stderr.String())
	}
}

func TestUpgradeClusterStatusStopRollbackTable(t *testing.T) {
	f := newFakeUpgrade(t, true, "v0.6.12")
	stdFleet(f, "v0.6.12")
	f.members[5]["alive"] = false // wkr-2 is down
	f.manual["wkr-3"] = true
	h := upgradeHarness(t, f)
	dir, all := distDir(t, "v0.6.13", true)
	// The leader already has sandboxd: only the other three are sent.
	f.files[sha(all["sandboxd_linux_amd64"])] = all["sandboxd_linux_amd64"]
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--hold"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if heads, puts := countPrefix(f.calls, "HEAD "+upgradewire.ClusterUpgradeFilesPath), countPrefix(f.calls, "PUT "+upgradewire.ClusterUpgradeFilesPath); heads != 4 || puts != 3 {
		t.Fatalf("HEAD %d, PUT %d", heads, puts)
	}
	if req := f.applyReqs[0]; req.Source != upgradewire.SourceUpload || !req.Hold || len(req.Files) != 4 {
		t.Fatalf("apply = %+v", req)
	}
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"upgrade", "status"}, "status-cluster.golden"},
		{[]string{"upgrade", "status", "-o", "json"}, "status-cluster-json.golden"},
		{[]string{"upgrade", "status", "-o", "yaml"}, "status-cluster-yaml.golden"},
	} {
		if code := h.run(tc.args...); code != exitOK {
			t.Fatal(h.stderr.String())
		}
		checkGoldenIn(t, "upgrade", tc.golden, h.transcript(exitOK))
	}
	steps := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"upgrade", "finalize"}, exitError, "finalize needs it done"},
		{[]string{"upgrade", "stop"}, exitOK, "rollout r-1: stopped\n"},
		{[]string{"upgrade", "stop"}, exitOK, "rollout r-1: stopped\n"},
		{[]string{"upgrade", "resume"}, exitError, "hint: run the same apply again: aerolvm upgrade apply v0.6.13"},
		{[]string{"upgrade", "apply", "v0.6.13", "--from", dir}, exitOK, "rollout r-1 to v0.6.13 is already staging\n"},
	}
	for _, s := range steps {
		code := h.run(s.args...)
		out := h.stdout.String() + h.stderr.String()
		if code != s.code || !strings.Contains(out, s.want) {
			t.Fatalf("%v = %d %q, want %q", s.args, code, out, s.want)
		}
	}
	// Done, held, with a skipped node: finalize names it.
	f.rollout.State = upgradewire.StateDone
	if code := h.run("upgrade", "finalize"); code != exitError || !strings.Contains(h.stderr.String(), "(nodes: wkr-2)") ||
		!strings.Contains(h.stderr.String(), "hint: aerolvm delete node <name>") {
		t.Fatalf("finalize with skipped = %d %q", code, h.stderr.String())
	}
	if code := h.run("upgrade", "stop", "--json"); code != exitError {
		t.Fatal("stop on done")
	}
	// Roll it back and follow it; again is a no-op.
	f.advance = true
	code := h.run("upgrade", "rollback", "--wait")
	if code != exitOK || f.rollout.State != upgradewire.StateRolledBack {
		t.Fatalf("rollback = %d %s", code, h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "rollback-cluster-wait.golden", h.transcript(code))
	if code := h.run("upgrade", "rollback", "-o", "yaml"); code != exitOK || !strings.Contains(h.stdout.String(), "state: rolled-back") {
		t.Fatalf("rollback again = %d %q", code, h.stdout.String())
	}
	if code := h.run("upgrade", "rollback"); code != exitOK || h.stdout.String() != "rollout r-1: rolled-back, back to v0.6.12\n" {
		t.Fatalf("rollback text = %q", h.stdout.String())
	}
	// Apply while a rollback runs is refused; after rolled-back it is new.
	f.rollout.State = upgradewire.StateRollingBack
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir); code != exitError || !strings.Contains(h.stderr.String(), "a rollback is running") {
		t.Fatalf("apply during rollback = %d %q", code, h.stderr.String())
	}
}

func countPrefix(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// --wait's endings: each state that ends it, and its exit code.
func TestRolloutEnd(t *testing.T) {
	for _, tc := range []struct {
		ro            upgradewire.Rollout
		rollback      bool
		ended, ok     bool
		wantInMessage string
	}{
		{upgradewire.Rollout{State: upgradewire.StateRunning}, false, false, false, ""},
		{upgradewire.Rollout{State: upgradewire.StateDone}, false, false, false, ""},
		{upgradewire.Rollout{State: upgradewire.StateDone, Hold: true}, false, true, true, "done and held"},
		{upgradewire.Rollout{State: upgradewire.StateFinalized, TargetVersion: "v2"}, false, true, true, "every node runs v2"},
		{upgradewire.Rollout{State: upgradewire.StatePaused}, false, true, true, "paused"},
		{upgradewire.Rollout{State: upgradewire.StateFailed, Error: "boom"}, false, true, false, "failed: boom"},
		{upgradewire.Rollout{State: upgradewire.StateStopped}, false, true, false, "was stopped"},
		{upgradewire.Rollout{State: upgradewire.StateRolledBack}, false, true, false, "rolled back"},
		{upgradewire.Rollout{State: upgradewire.StateRolledBack}, true, true, true, "rolled back"},
		{upgradewire.Rollout{State: upgradewire.StateFailed, Direction: upgradewire.DirectionRollback}, true, true, false, "failed"},
		{upgradewire.Rollout{State: upgradewire.StateFinalizing}, false, false, false, ""},
		{upgradewire.Rollout{State: upgradewire.StateFinalizing, Nodes: []upgradewire.RolloutNode{{NodeID: "w1", State: upgradewire.NodeFailed, Error: "migration 7"}}},
			false, true, false, "node w1 failed its one-way migrations: migration 7"},
	} {
		ended, ok, msg, _ := rolloutEnd(tc.ro, tc.rollback)
		if ended != tc.ended || ok != tc.ok || !strings.Contains(msg, tc.wantInMessage) {
			t.Errorf("%s rollback=%v = %v %v %q", tc.ro.State, tc.rollback, ended, ok, msg)
		}
	}
}

func TestUpgradeClusterWaitFailureAndErrors(t *testing.T) {
	f := newFakeUpgrade(t, true, "v0.6.12")
	stdFleet(f, "v0.6.12")
	h := upgradeHarness(t, f)
	dir, _ := distDir(t, "v0.6.13", true)
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	f.rollout.State, f.rollout.Error = upgradewire.StateFailed, "node wkr-1 did not pass its health check within 10m0s"
	f.rollout.Nodes[4].State, f.rollout.Nodes[4].Error = upgradewire.NodeFailed, "health check timed out"
	code := h.run("upgrade", "status")
	if code != exitOK || !strings.Contains(h.stdout.String(), "Error:           node wkr-1 did not pass") {
		t.Fatalf("status = %q", h.stdout.String())
	}
	// A rollback that fails on a node: --wait ends with exit 1.
	f.onGet = func(ro *upgradewire.Rollout) {
		if ro.State == upgradewire.StateRollingBack {
			ro.State, ro.Error = upgradewire.StateFailed, "node srv-a did not come back on v0.6.12"
		}
	}
	code = h.run("upgrade", "rollback", "--wait", "--json")
	if code != exitError || h.errorEnvelope().Code != "rollout_failed" || !strings.Contains(h.errorEnvelope().Message, "did not come back") {
		t.Fatalf("failed rollback = %d %s", code, h.stderr.String())
	}
	f.onGet = nil
	// A server error during --wait that is not a restart ends it.
	f.rollout.State = upgradewire.StateRunning
	f.rollout.Direction = upgradewire.DirectionUpgrade
	f.rollout.TargetVersion = "v0.6.13"
	f.noRoutes = false
	h.app.pollEvery = 1
	f.advance = false
	go func() {
		f.mu.Lock()
		f.noRoutes = true
		f.mu.Unlock()
	}()
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait"); code != exitError {
		t.Fatalf("apply with routes gone = %d", code)
	}
}

func TestUpgradeRefusalShapes(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
		msg    string
	}{
		{http.StatusConflict, `{"error":"cluster_mode","reason":"in a cluster","hint":"aerolvm upgrade apply <version>"}`, "cluster_mode", "in a cluster"},
		{http.StatusNotFound, `404 page not found`, "server_unsupported", "no upgrade API"},
		{http.StatusMethodNotAllowed, ``, "server_unsupported", "no upgrade API"},
		{http.StatusNotFound, `{"error":"not_found","reason":"no rollout"}`, "not_found", "no rollout"},
		{http.StatusForbidden, `{"error":"operator authorization required"}`, "forbidden", "operator authorization required"},
		{http.StatusUnauthorized, `{"error":"unauthorized"}`, "unauthorized", "unauthorized"},
		{http.StatusServiceUnavailable, `{}`, "unavailable", "Service Unavailable"},
		{http.StatusConflict, `{"error":"skipped_nodes","reason":"skipped","nodes":["a","b"]}`, "skipped_nodes", "skipped (nodes: a, b)"},
		{http.StatusBadRequest, `{"error":"Bad Thing"}`, "invalid_argument", "Bad Thing"},
		{http.StatusRequestEntityTooLarge, `{"reason":"big"}`, "too_large", "big"},
		{http.StatusInternalServerError, `oops`, "internal", "Internal Server Error"},
		{http.StatusTooManyRequests, `{}`, "unavailable", "Too Many Requests"},
		{http.StatusGatewayTimeout, `{}`, "unavailable", "Gateway Timeout"},
		{http.StatusBadGateway, `{}`, "unavailable", "Bad Gateway"},
	} {
		err := upgradeRefusal(tc.status, []byte(tc.body))
		var e struct{ Code, Message string }
		raw, _ := json.Marshal(err)
		_ = json.Unmarshal(raw, &e)
		if e.Code != tc.code || !strings.Contains(e.Message, tc.msg) {
			t.Errorf("%d %s = %+v", tc.status, tc.body, e)
		}
	}
	if !transient(upgradeRefusal(http.StatusBadGateway, nil)) || transient(upgradeRefusal(http.StatusConflict, []byte(`{"error":"x"}`))) {
		t.Fatal("transient")
	}
}
