//go:build integration

package suite

// Cluster rollouts, Phase 3b live gate (plans/kubectl-style-cluster-ops.md
// §9 Phase 3b row, §10; UC-641..657). The cluster runs build A (this tree,
// the harness's stamp); build B is the same tree with another version
// stamp, built here. The cases drive the public upgrade API with the
// upgradewire types and run in source order, each on the state the one
// before left:
//
//	01 leader transfer              UC-641
//	02 upload routes (build B)      UC-656
//	03 a node that can't stage      UC-650, UC-645
//	04 --pause-after 1, mixed       UC-651, UC-643
//	05 a forced failure on a node   UC-644
//	06 finish, leader upgraded,     UC-652, UC-653, UC-657
//	   no restarts, no failover
//	07 rollback to A                UC-654
//	08 source release + finalize    UC-655, UC-642
//
// Every node restarts several times: run it alone,
// AEROL_TEST_RUN='TestRolloutLive' on cluster-rollout (a copy of cluster-hetero-lite
// under its own name: the harness keys Terraform state by scenario name). The file sorts
// last so a full pass runs it after everything else.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// rolloutLiveState is what one case leaves for the next.
type rolloutLiveState struct {
	versionA, versionB string
	filesB             map[string]string // asset -> sha256
	buildDir           string
	rolloutID          string
	firstLeader        string
	// sandboxes made before the first restart: id -> (owner, pid 1 start)
	sandboxes map[string]liveSandbox
	stageFail harness.IntegrationNode
	failNode  harness.IntegrationNode
	ready     bool
}

type liveSandbox struct {
	sb    *microvm.Sandbox
	owner string
	start string
}

var rl rolloutLiveState

func requireRolloutLive(t *testing.T) (*harness.Client, *harness.IntegrationTargets) {
	t.Helper()
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: a rollout restarts every node")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	return client(t), targets
}

// requirePrevious skips a case whose setup an earlier case did not finish.
func requirePrevious(t *testing.T) {
	t.Helper()
	if !rl.ready {
		t.Fatal("an earlier rollout case did not finish; this case needs its state")
	}
}

// upgradeCall sends one upgrade API call with the scenario's token and
// returns the status and body.
func upgradeCall(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, sc.BaseURL+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+sc.PAT)
		req.Header.Set("Content-Type", "application/json")
		resp, err := harness.HTTPClient(time.Minute).Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			// The leader may be restarting: the API answers 502/503 for a
			// moment. A command is idempotent (§6.6), so a retry is safe.
			if (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout) && attempt < 20 {
				time.Sleep(3 * time.Second)
				if body != nil {
					b2, _ := json.Marshal(body)
					rd = bytes.NewReader(b2)
				}
				continue
			}
			return resp.StatusCode, b
		}
		if attempt >= 20 {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		time.Sleep(3 * time.Second)
		if body != nil {
			b2, _ := json.Marshal(body)
			rd = bytes.NewReader(b2)
		}
	}
}

func getRollout(t *testing.T) (*upgradewire.Rollout, int) {
	t.Helper()
	code, b := upgradeCall(t, http.MethodGet, upgradewire.ClusterUpgradePath, nil)
	if code != http.StatusOK {
		return nil, code
	}
	var r upgradewire.Rollout
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decode rollout: %v: %s", err, b)
	}
	return &r, code
}

func rolloutNodes(r *upgradewire.Rollout) string {
	var parts []string
	for _, n := range r.Nodes {
		s := n.NodeID + "=" + n.State
		if n.Error != "" {
			s += "(" + n.Error + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// waitRollout polls the rollout until done says so, logging each change.
func waitRollout(t *testing.T, timeout time.Duration, what string, done func(*upgradewire.Rollout) bool) *upgradewire.Rollout {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		r, code := getRollout(t)
		if r != nil {
			now := r.State + " | " + rolloutNodes(r)
			if now != last {
				t.Logf("rollout %s: %s", r.ID, now)
				last = now
			}
			if done(r) {
				return r
			}
		} else {
			t.Logf("GET rollout = %d", code)
		}
		if time.Now().After(deadline) {
			t.Fatalf("rollout did not reach %s within %s (last: %s)", what, timeout, last)
		}
		time.Sleep(5 * time.Second)
	}
}

func inState(states ...string) func(*upgradewire.Rollout) bool {
	return func(r *upgradewire.Rollout) bool {
		for _, s := range states {
			if r.State == s {
				return true
			}
		}
		return false
	}
}

// memberVersions maps every alive member to the build it gossips.
func memberVersions(t *testing.T, c *harness.Client) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range listNodeViews(t, c) {
		if m.Alive {
			out[m.NodeID] = m.Version
		}
	}
	return out
}

func currentLeader(t *testing.T, c *harness.Client) string {
	t.Helper()
	for _, m := range listNodeViews(t, c) {
		if m.Leader {
			return m.NodeID
		}
	}
	return ""
}

// waitAllOn waits until every alive member gossips version.
func waitAllOn(t *testing.T, c *harness.Client, version string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		vs := memberVersions(t, c)
		all := len(vs) > 0
		for _, v := range vs {
			if v != version {
				all = false
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("members never all reported %s: %v", version, vs)
		}
		time.Sleep(5 * time.Second)
	}
}

// buildB builds this tree's sandboxd and toolboxd for linux/amd64 with
// version stamped in, the way integration-tests/lib/build.sh does (zig as
// the C cross compiler, since sandboxd needs CGO for sqlite), stripped so
// the upload is smaller.
func buildB(t *testing.T, version string) (string, map[string]string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	dir := filepath.Join(root, "integration-tests", ".build", "rollout-"+version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ldflags := "-s -w -X github.com/aerol-ai/microvm/internal/version.Version=" + version
	builds := []struct {
		out, pkg string
		cgo      bool
	}{{"sandboxd_linux_amd64", "./cmd/sandboxd", true}, {"toolboxd_linux_amd64", "./cmd/toolboxd", false}}
	files := map[string]string{}
	for _, b := range builds {
		out := filepath.Join(dir, b.out)
		if _, err := os.Stat(out); err != nil {
			cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", out, b.pkg)
			cmd.Dir = root
			env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
			if b.cgo {
				env = append(env, "CGO_ENABLED=1", "CC=zig cc -target x86_64-linux-gnu.2.31", "CXX=zig c++ -target x86_64-linux-gnu.2.31")
			} else {
				env = append(env, "CGO_ENABLED=0")
			}
			cmd.Env = env
			if outb, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build %s: %v\n%s", b.out, err, outb)
			}
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		files[b.out] = hex.EncodeToString(sum[:])
	}
	return dir, files
}

// putFile uploads one file to the leader (PUT …/files/{sha256}).
func putFile(t *testing.T, sum string, body io.Reader, size int64) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sc.BaseURL+upgradewire.ClusterUpgradeFilesPath+"/"+sum, body)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = size
	req.Header.Set("Authorization", "Bearer "+sc.PAT)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := harness.HTTPClient(20 * time.Minute).Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", sum, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

func headFile(t *testing.T, sum string) int {
	t.Helper()
	code, _ := upgradeCall(t, http.MethodHead, upgradewire.ClusterUpgradeFilesPath+"/"+sum, nil)
	return code
}

// sshRoot runs script as root on node and fails the case on error.
func sshRoot(t *testing.T, node harness.IntegrationNode, script string) string {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Fatalf("no SSH address for %s", node.Name)
	}
	out, err := harness.SSHRun(t, target, "sudo bash -c "+shellQuote(script))
	if err != nil {
		t.Fatalf("ssh %s: %v\n%s", node.Name, err, out)
	}
	return out
}

// rolloutNodesOfRole returns the SSH-reachable targets of role, in name order.
func rolloutNodesOfRole(t *testing.T, targets *harness.IntegrationTargets, role string) []harness.IntegrationNode {
	t.Helper()
	var out []harness.IntegrationNode
	for _, n := range targets.Nodes {
		if strings.EqualFold(n.Role, role) {
			if _, ok := harness.SSHTarget(n); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

func applyB(source string) upgradewire.ApplyRequest {
	return upgradewire.ApplyRequest{
		Version: rl.versionB, Files: rl.filesB, Source: source, Hold: true, Batch: "1", PauseAfter: 1,
		NodeTimeout: "10m", AllowUnversioned: true,
	}
}

// keptSandbox creates a sandbox that outlives the case that made it: the
// later cases check it kept its PID 1 through every restart. The last case
// destroys it (destroyKeptSandboxes).
func keptSandbox(t *testing.T, c *harness.Client, name string) *microvm.Sandbox {
	t.Helper()
	public := true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: name, Image: harness.DefaultImage, AllowPublicTraffic: &public})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	return sb
}

func destroyKeptSandboxes(t *testing.T, c *harness.Client) {
	for id := range rl.sandboxes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if err := c.SDK().Destroy(ctx, id); err != nil {
			t.Logf("cleanup: destroy sandbox %s: %v", id, err)
		}
		cancel()
	}
}

// pid1Start is the start time of the sandbox's PID 1, in clock ticks since
// boot: it changes only if the container restarts.
func pid1Start(t *testing.T, sb *microvm.Sandbox) string {
	t.Helper()
	return strings.TrimSpace(execOK(t, sb, "cut -d' ' -f22 /proc/1/stat"))
}

// UC-641 — POST /v1/cluster/leader/transfer moves Raft leadership to
// another voter.
func TestRolloutLive01LeaderTransfer(t *testing.T) {
	harness.Require(t, sc, "UC-641")
	c, _ := requireRolloutLive(t)
	before := currentLeader(t, c)
	if before == "" {
		t.Fatal("no leader in the member list")
	}
	code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterLeaderTransferPath, upgradewire.LeaderTransferRequest{})
	if code != http.StatusOK {
		t.Fatalf("transfer = %d %s", code, b)
	}
	var out upgradewire.LeaderTransferResponse
	if err := json.Unmarshal(b, &out); err != nil || out.Leader == "" || out.Leader == before || out.Term == 0 {
		t.Fatalf("transfer answer %s (was %s)", b, before)
	}
	deadline := time.Now().Add(time.Minute)
	for currentLeader(t, c) != out.Leader {
		if time.Now().After(deadline) {
			t.Fatalf("members never showed %s as leader", out.Leader)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("leadership moved %s -> %s (term %d)", before, out.Leader, out.Term)
}

// UC-656 — the upload routes: PUT stores a file under its SHA-256 (201,
// then 200 for a repeat), HEAD answers 200 for a stored file and 404 for a
// missing one, a body that does not hash to its path is refused with 400
// hash_mismatch, and a path that is not 64 hex digits is a 400.
func TestRolloutLive02UploadRoutes(t *testing.T) {
	harness.Require(t, sc, "UC-656")
	c, _ := requireRolloutLive(t)
	vs := memberVersions(t, c)
	for _, v := range vs {
		rl.versionA = v
		break
	}
	for id, v := range vs {
		if v != rl.versionA {
			t.Fatalf("the cluster does not run one build: %s runs %s, others %s", id, v, rl.versionA)
		}
	}
	rl.versionB = rl.versionA + "-b"
	rl.buildDir, rl.filesB = buildB(t, rl.versionB)
	t.Logf("build A %s, build B %s: %v", rl.versionA, rl.versionB, rl.filesB)
	for name, sum := range rl.filesB {
		if headFile(t, sum) == http.StatusOK {
			continue
		}
		f, err := os.Open(filepath.Join(rl.buildDir, name))
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := f.Stat()
		start := time.Now()
		code, body := putFile(t, sum, f, fi.Size())
		f.Close()
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("PUT %s = %d %s", name, code, body)
		}
		t.Logf("uploaded %s (%d MiB) in %s: %d", name, fi.Size()>>20, time.Since(start).Round(time.Second), code)
	}
	for name, sum := range rl.filesB {
		if code := headFile(t, sum); code != http.StatusOK {
			t.Fatalf("HEAD %s = %d after upload", name, code)
		}
		raw, _ := os.ReadFile(filepath.Join(rl.buildDir, name))
		if code, body := putFile(t, sum, bytes.NewReader(raw), int64(len(raw))); code != http.StatusOK {
			t.Fatalf("repeat PUT %s = %d %s, want 200", name, code, body)
		}
	}
	missing := strings.Repeat("0", 64)
	if code := headFile(t, missing); code != http.StatusNotFound {
		t.Fatalf("HEAD of a missing file = %d", code)
	}
	if code, body := putFile(t, missing, strings.NewReader("not that file"), 13); code != http.StatusBadRequest || !strings.Contains(body, upgradewire.ErrCodeHashMismatch) {
		t.Fatalf("PUT with the wrong hash = %d %s", code, body)
	}
	if code, _ := upgradeCall(t, http.MethodHead, upgradewire.ClusterUpgradeFilesPath+"/NOT-HEX", nil); code != http.StatusBadRequest {
		t.Fatalf("HEAD with a bad path = %d", code)
	}
	rl.ready = true
}

// UC-650 — a node that can't stage fails the rollout before any node
// restarts: the rollout ends failed naming that node, and every member
// still runs build A. Applying the same version again after the fix sends
// the rollout back to staging. UC-645 — the rollout shows the active
// cluster version: written once every server ran this build, at A.
func TestRolloutLive03StageFailureStopsEarly(t *testing.T) {
	harness.Require(t, sc, "UC-650", "UC-645")
	c, targets := requireRolloutLive(t)
	requirePrevious(t)
	rl.ready = false
	workers := rolloutNodesOfRole(t, targets, "worker")
	if len(workers) < 3 {
		t.Skipf("needs 3 SSH-reachable workers, have %d", len(workers))
	}
	// Sandboxes made now must outlive every restart (UC-653).
	rl.sandboxes = map[string]liveSandbox{}
	for i := 0; i < 2; i++ {
		sb := keptSandbox(t, c, fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		owner, err := c.OwnerNodeID(ctx, sb.ID)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		execOK(t, sb, "echo kept > /tmp/uc653")
		rl.sandboxes[sb.ID] = liveSandbox{sb: sb, owner: owner, start: pid1Start(t, sb)}
	}
	rl.stageFail = workers[len(workers)-1]
	sshRoot(t, rl.stageFail, "mkdir -p /var/lib/sandboxd/upgrade/files && rm -f /var/lib/sandboxd/upgrade/files/* && chattr +i /var/lib/sandboxd/upgrade/files")
	defer sshRoot(t, rl.stageFail, "chattr -i /var/lib/sandboxd/upgrade/files")
	rl.firstLeader = currentLeader(t, c)

	code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, applyB(upgradewire.SourceUpload))
	if code != http.StatusCreated {
		t.Fatalf("apply = %d %s", code, b)
	}
	var created upgradewire.Rollout
	_ = json.Unmarshal(b, &created)
	rl.rolloutID = created.ID
	if created.Caller == "" || created.Batch != "1" || created.PauseAfter != 1 || !created.Hold {
		t.Fatalf("created rollout = %+v", created)
	}
	if created.ActiveFSMOpsVersion < 13 || created.ActiveVersion != rl.versionA {
		t.Fatalf("active version on the rollout = %q fv %d, want %s and >= 13", created.ActiveVersion, created.ActiveFSMOpsVersion, rl.versionA)
	}
	r := waitRollout(t, 10*time.Minute, "failed", inState(upgradewire.StateFailed, upgradewire.StateRunning))
	if r.State != upgradewire.StateFailed {
		t.Fatalf("rollout = %s, want failed at staging: %s", r.State, rolloutNodes(r))
	}
	failed := ""
	for _, n := range r.Nodes {
		switch n.State {
		case upgradewire.NodeUpgrading, upgradewire.NodeDone:
			if n.Version != rl.versionA {
				t.Fatalf("node %s moved to %s after a stage failure", n.NodeID, n.State)
			}
		case upgradewire.NodeFailed:
			failed = n.NodeID + ": " + n.Error
		}
	}
	if failed == "" || !strings.Contains(r.Error, "stage") {
		t.Fatalf("no node failed to stage: %s (%s)", rolloutNodes(r), r.Error)
	}
	t.Logf("stage failure: %s", failed)
	for id, v := range memberVersions(t, c) {
		if v != rl.versionA {
			t.Fatalf("%s runs %s after a stage failure", id, v)
		}
	}
	rl.ready = true
}

// UC-651 — --pause-after 1: the first worker batch is one worker, and the
// rollout pauses once it is done, after the servers (the leader last, after
// a hand-off) and the ingress node. UC-643 — the mixed-version window
// works: while A and B run side by side, a new sandbox starts and the old
// ones answer exec.
func TestRolloutLive04PauseAfterCanary(t *testing.T) {
	harness.Require(t, sc, "UC-651", "UC-643")
	c, targets := requireRolloutLive(t)
	requirePrevious(t)
	rl.ready = false
	code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, applyB(upgradewire.SourceUpload))
	if code != http.StatusOK {
		t.Fatalf("apply again = %d %s, want 200 (the failed rollout restages)", code, b)
	}
	r := waitRollout(t, 30*time.Minute, "paused", inState(upgradewire.StatePaused, upgradewire.StateFailed))
	if r.State != upgradewire.StatePaused || r.ID != rl.rolloutID {
		t.Fatalf("rollout = %s (%s): %s", r.State, r.ID, rolloutNodes(r))
	}
	workersDone := 0
	for _, n := range r.Nodes {
		if n.Role == "worker" && n.State == upgradewire.NodeDone {
			workersDone++
		}
		if n.Role != "worker" && n.State != upgradewire.NodeDone {
			t.Fatalf("paused before %s (%s) was done", n.NodeID, n.Role)
		}
	}
	if workersDone != 1 {
		t.Fatalf("paused after %d workers, want exactly 1: %s", workersDone, rolloutNodes(r))
	}
	// Still paused a little later: nothing moves without resume.
	time.Sleep(20 * time.Second)
	if r2, _ := getRollout(t); r2.State != upgradewire.StatePaused {
		t.Fatalf("a paused rollout moved on: %s", r2.State)
	}
	vs := memberVersions(t, c)
	onA, onB := 0, 0
	for _, v := range vs {
		switch v {
		case rl.versionA:
			onA++
		case rl.versionB:
			onB++
		}
	}
	if onA == 0 || onB == 0 {
		t.Fatalf("not a mixed-version window: %v", vs)
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	execOK(t, sb, "true")
	for id, s := range rl.sandboxes {
		if out := execOK(t, s.sb, "cat /tmp/uc653"); !strings.Contains(out, "kept") {
			t.Fatalf("sandbox %s lost its file: %q", id, out)
		}
	}
	// Keep a copy of build B on every server for UC-655 while their
	// stores hold it (the store prunes unused files after an hour).
	for _, s := range rolloutNodesOfRole(t, targets, "server") {
		var script strings.Builder
		fmt.Fprintf(&script, "set -e; mkdir -p /var/tmp/aerolvm-rel/%s; ", rl.versionB)
		for name, sum := range rl.filesB {
			fmt.Fprintf(&script, "cp /var/lib/sandboxd/upgrade/files/%s /var/tmp/aerolvm-rel/%s/%s; ", sum, rl.versionB, name)
		}
		sshRoot(t, s, script.String())
	}
	rl.ready = true
}

// UC-644 — a node whose upgrade fails during apply is rolled back by its
// own upgrader: the new toolboxd swapped in first is put back, the old
// sandboxd starts again, the node stays a live member on build A, and the
// rollout ends failed naming it.
func TestRolloutLive05ForcedFailureRollsNodeBack(t *testing.T) {
	harness.Require(t, sc, "UC-644")
	c, targets := requireRolloutLive(t)
	requirePrevious(t)
	rl.ready = false
	r, _ := getRollout(t)
	byID := map[string]upgradewire.RolloutNode{}
	for _, n := range r.Nodes {
		byID[n.NodeID] = n
	}
	// The next worker in line: the lowest batch still pending.
	var next harness.IntegrationNode
	nextBatch := 1 << 30
	for _, w := range rolloutNodesOfRole(t, targets, "worker") {
		id := heteroNodeID(t, c, targets, w.Name)
		n, ok := byID[id]
		if ok && n.State != upgradewire.NodeDone && n.Batch < nextBatch {
			next, nextBatch = w, n.Batch
		}
	}
	if next.Name == "" {
		t.Fatal("no worker left to upgrade")
	}
	rl.failNode = next
	nextID := heteroNodeID(t, c, targets, next.Name)
	sshRoot(t, next, "chattr +i /usr/local/bin/sandboxd")
	restored := false
	defer func() {
		if !restored {
			sshRoot(t, next, "chattr -i /usr/local/bin/sandboxd")
		}
	}()
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeResumePath, nil); code != http.StatusOK {
		t.Fatalf("resume = %d %s", code, b)
	}
	// A repeat of a command that took effect succeeds (§6.6).
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeResumePath, nil); code != http.StatusOK {
		t.Fatalf("second resume = %d %s", code, b)
	}
	r = waitRollout(t, 20*time.Minute, "failed", inState(upgradewire.StateFailed, upgradewire.StateDone))
	if r.State != upgradewire.StateFailed {
		t.Fatalf("rollout = %s, want failed on %s", r.State, nextID)
	}
	var fn upgradewire.RolloutNode
	for _, n := range r.Nodes {
		if n.NodeID == nextID {
			fn = n
		}
	}
	if fn.State != upgradewire.NodeFailed || !strings.Contains(fn.Error, "put the previous files back") {
		t.Fatalf("forced-failure node = %+v", fn)
	}
	out := sshRoot(t, next, "sha256sum /usr/local/bin/toolboxd | cut -d' ' -f1; curl -fsS http://127.0.0.1:21212/health")
	if strings.Contains(out, rl.filesB["toolboxd_linux_amd64"]) || !strings.Contains(out, rl.versionA) {
		t.Fatalf("%s did not go back to build A: %s", next.Name, out)
	}
	if v := memberVersions(t, c)[nextID]; v != rl.versionA {
		t.Fatalf("%s gossips %q, want %s", nextID, v, rl.versionA)
	}
	sshRoot(t, next, "chattr -i /usr/local/bin/sandboxd")
	restored = true
	rl.ready = true
}

// UC-652 — the rollout runs in the cluster: applied again, it finishes
// with no client attached (this case only polls), every member runs B, and
// the leader that started it was upgraded too, after handing leadership
// off. UC-653 — zero container restarts and no failover: every sandbox made
// before the first restart keeps its owner, its PID 1 and its files.
// UC-657 — commands answer per §6.6: another target is refused with
// rollout_conflict while a held rollout is done, stop and resume refuse a
// done rollout, and GET shows every node done.
func TestRolloutLive06FinishesAndKeepsSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-652", "UC-653", "UC-657")
	c, _ := requireRolloutLive(t)
	requirePrevious(t)
	rl.ready = false
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, applyB(upgradewire.SourceUpload)); code != http.StatusOK {
		t.Fatalf("apply again = %d %s", code, b)
	}
	r := waitRollout(t, 40*time.Minute, "done", inState(upgradewire.StateDone, upgradewire.StateFailed))
	if r.State != upgradewire.StateDone {
		t.Fatalf("rollout = %s: %s (%s)", r.State, rolloutNodes(r), r.Error)
	}
	for _, n := range r.Nodes {
		if n.State != upgradewire.NodeDone {
			t.Fatalf("node %s is %s in a done rollout", n.NodeID, n.State)
		}
	}
	waitAllOn(t, c, rl.versionB, 5*time.Minute)
	if leader := currentLeader(t, c); leader == "" {
		t.Fatal("no leader after the rollout")
	}
	found := false
	for _, n := range r.Nodes {
		if n.NodeID == rl.firstLeader && n.State == upgradewire.NodeDone {
			found = true
		}
	}
	if !found {
		t.Fatalf("the first leader %s was not upgraded", rl.firstLeader)
	}
	for id, s := range rl.sandboxes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		owner, err := c.OwnerNodeID(ctx, id)
		cancel()
		if err != nil || owner != s.owner {
			t.Fatalf("sandbox %s moved from %s to %q (%v): a failover during the rollout", id, s.owner, owner, err)
		}
		if got := pid1Start(t, s.sb); got != s.start {
			t.Fatalf("sandbox %s restarted: PID 1 started at %s, was %s", id, got, s.start)
		}
		if out := execOK(t, s.sb, "cat /tmp/uc653"); !strings.Contains(out, "kept") {
			t.Fatalf("sandbox %s lost its file", id)
		}
	}
	other := applyB(upgradewire.SourceUpload)
	other.Version = rl.versionB + "-other"
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, other); code != http.StatusConflict || !strings.Contains(string(b), upgradewire.ErrCodeRolloutConflict) {
		t.Fatalf("apply another target while done = %d %s", code, b)
	}
	for _, p := range []string{upgradewire.ClusterUpgradeStopPath, upgradewire.ClusterUpgradeResumePath} {
		if code, b := upgradeCall(t, http.MethodPost, p, nil); code != http.StatusConflict {
			t.Fatalf("%s on a done rollout = %d %s", p, code, b)
		}
	}
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, applyB(upgradewire.SourceUpload)); code != http.StatusOK || !strings.Contains(string(b), rl.rolloutID) {
		t.Fatalf("apply the same target while done = %d %s", code, b)
	}
	rl.ready = true
}

// UC-654 — rollback puts every node back on build A: workers first, the
// servers last, and the rollout ends rolled-back with the sandboxes kept.
func TestRolloutLive07Rollback(t *testing.T) {
	harness.Require(t, sc, "UC-654")
	c, _ := requireRolloutLive(t)
	requirePrevious(t)
	rl.ready = false
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeRollbackPath, nil); code != http.StatusOK || !strings.Contains(string(b), upgradewire.StateRollingBack) {
		t.Fatalf("rollback = %d %s", code, b)
	}
	r := waitRollout(t, 40*time.Minute, "rolled-back", inState(upgradewire.StateRolledBack, upgradewire.StateFailed))
	if r.State != upgradewire.StateRolledBack || r.Direction != upgradewire.DirectionRollback {
		t.Fatalf("rollback = %s: %s (%s)", r.State, rolloutNodes(r), r.Error)
	}
	waitAllOn(t, c, rl.versionA, 5*time.Minute)
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeRollbackPath, nil); code != http.StatusOK {
		t.Fatalf("second rollback = %d %s", code, b)
	}
	for id, s := range rl.sandboxes {
		if got := pid1Start(t, s.sb); got != s.start {
			t.Fatalf("sandbox %s restarted during the rollback", id)
		}
	}
	rl.ready = true
}

// UC-655 — source release: servers download from SB_RELEASE_URL and
// workers and the ingress node copy from servers only; without --hold the
// rollout finalizes by itself: every node runs its one-way migrations and
// the rollout ends finalized. UC-642 — the active cluster version moves to
// B at finalize.
func TestRolloutLive08ReleaseSourceAndFinalize(t *testing.T) {
	harness.Require(t, sc, "UC-655", "UC-642")
	c, targets := requireRolloutLive(t)
	requirePrevious(t)
	t.Cleanup(func() { destroyKeptSandboxes(t, c) })
	servers := rolloutNodesOfRole(t, targets, "server")
	for _, s := range servers {
		sshRoot(t, s, "pkill -f 'http.server 18099' || true; "+
			"nohup setsid python3 -m http.server 18099 --bind 127.0.0.1 --directory /var/tmp/aerolvm-rel > /var/tmp/aerolvm-rel.log 2>&1 < /dev/null & "+
			"sed -i '/^SB_RELEASE_URL=/d' /etc/sandboxd/sandboxd.env; echo SB_RELEASE_URL=http://127.0.0.1:18099 >> /etc/sandboxd/sandboxd.env")
	}
	defer func() {
		for _, s := range servers {
			sshRoot(t, s, "pkill -f 'http.server 18099' || true; sed -i '/^SB_RELEASE_URL=/d' /etc/sandboxd/sandboxd.env")
		}
	}()
	// No node holds build B now, so staging must fetch it again.
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); ok {
			sshRoot(t, n, "rm -f /var/lib/sandboxd/upgrade/files/*")
		}
	}
	req := applyB(upgradewire.SourceRelease)
	req.Hold, req.PauseAfter, req.Batch = false, 0, "50%"
	code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradePath, req)
	if code != http.StatusCreated {
		t.Fatalf("apply after a rollback = %d %s, want a new rollout", code, b)
	}
	r := waitRollout(t, 45*time.Minute, "finalized", inState(upgradewire.StateFinalized, upgradewire.StateFailed))
	if r.State != upgradewire.StateFinalized {
		t.Fatalf("rollout = %s: %s (%s)", r.State, rolloutNodes(r), r.Error)
	}
	for _, n := range r.Nodes {
		if !n.Migrated {
			t.Fatalf("finalized with %s not migrated", n.NodeID)
		}
	}
	if r.ActiveVersion != rl.versionB || r.ActiveFSMOpsVersion < 13 {
		t.Fatalf("active version after finalize = %q fv %d, want %s", r.ActiveVersion, r.ActiveFSMOpsVersion, rl.versionB)
	}
	waitAllOn(t, c, rl.versionB, 5*time.Minute)
	// Each server fetched both files from its own release URL; nothing
	// else ever did.
	for _, s := range servers {
		log := sshRoot(t, s, "cat /var/tmp/aerolvm-rel.log")
		for name := range rl.filesB {
			if !strings.Contains(log, "GET /"+rl.versionB+"/"+name) {
				t.Fatalf("%s never fetched %s from SB_RELEASE_URL:\n%s", s.Name, name, log)
			}
		}
	}
	for _, n := range targets.Nodes {
		if strings.EqualFold(n.Role, "server") {
			continue
		}
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		out := sshRoot(t, n, "ls /var/lib/sandboxd/upgrade/files 2>/dev/null | wc -l; ls -d /var/tmp/aerolvm-rel 2>/dev/null || true")
		if strings.Contains(out, "aerolvm-rel") {
			t.Fatalf("%s has a release directory: only servers fetch", n.Name)
		}
	}
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeFinalizePath, nil); code != http.StatusOK {
		t.Fatalf("finalize after finalized = %d %s", code, b)
	}
	if code, b := upgradeCall(t, http.MethodPost, upgradewire.ClusterUpgradeRollbackPath, nil); code != http.StatusConflict {
		t.Fatalf("rollback after finalize = %d %s", code, b)
	}
}
