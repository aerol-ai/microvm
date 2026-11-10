//go:build integration

package suite

// UC-660..666: `aerolvm upgrade` and `aerolvm release pull` on a single node
// (plans/kubectl-style-cluster-ops.md §6.1, §7.1, Phase 3b). The node runs
// this tree's build (A, itest-<id>); build.sh variant builds the same tree
// as itest-<id>-b (B). aerolvm uploads B with --from, the node upgrades
// itself through POST /v1/node/upgrade, then rolls back to A. These restart
// sandboxd, so the file sorts after the rest of the suite. The cases share
// one state and run in order; each skips when the one before left nothing
// to build on.
//
// Terraform runs cluster-init.sh even on a one-node scenario, so the
// harness's "single node" is a cluster of one server, where the single-node
// routes answer 409 cluster_mode. A node installed with install.sh alone
// runs with cluster mode off. UC-660 turns the scenario's node into that
// (a systemd drop-in that sets SB_ENABLE_CLUSTER=false after cluster.env),
// and UC-666's cleanup turns cluster mode back on.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

var upgradeLive struct {
	versionA, versionB, dirB string
	keep                     *microvm.Sandbox
	op                       nodeOpView
	// standaloneTarget is the node UC-660 took out of cluster mode, for
	// UC-666's cleanup to put back.
	standaloneTarget string
}

// standaloneDropIn is read after cluster-init.sh's cluster.conf (drop-ins
// apply in name order, and a later EnvironmentFile wins).
const standaloneDropIn = `set -e
printf 'SB_ENABLE_CLUSTER=false\n' | sudo tee /etc/sandboxd/standalone.env >/dev/null
sudo mkdir -p /etc/systemd/system/sandboxd.service.d
printf '[Service]\nEnvironmentFile=/etc/sandboxd/standalone.env\n' | sudo tee /etc/systemd/system/sandboxd.service.d/zz-standalone.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart sandboxd`

const clusterAgain = `set -e
sudo rm -f /etc/systemd/system/sandboxd.service.d/zz-standalone.conf /etc/sandboxd/standalone.env
sudo systemctl daemon-reload
sudo systemctl restart sandboxd`

// healthMode waits until /health answers, and says whether the node runs
// in cluster mode.
func healthMode(t *testing.T, c *harness.Client) (cluster bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var h struct {
			Version         string `json:"version"`
			ClusterTopology string `json:"cluster_topology"`
		}
		err := c.GetJSON(ctx, "/health", &h)
		cancel()
		if err == nil && h.Version != "" {
			return h.ClusterTopology != ""
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health did not answer: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
}

// makeStandalone turns the scenario's one node into a node with cluster
// mode off, as install.sh alone leaves it.
func makeStandalone(t *testing.T, c *harness.Client) {
	t.Helper()
	if !healthMode(t, c) {
		return
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) != 1 {
		t.Skip("the single-node routes need a one-node deployment to take out of cluster mode")
	}
	target, ok := harness.SSHTarget(targets.Nodes[0])
	if !ok {
		t.Skipf("no SSH address for %s", targets.Nodes[0].Name)
	}
	if out, err := harness.SSHRun(t, target, standaloneDropIn); err != nil {
		t.Fatalf("turn cluster mode off on %s: %v\n%s", targets.Nodes[0].Name, err, out)
	}
	upgradeLive.standaloneTarget = target
	if healthMode(t, c) {
		t.Fatal("the node still reports cluster mode after the standalone drop-in")
	}
}

type nodeOpView struct {
	Op       string `json:"op"`
	State    string `json:"state"`
	Version  string `json:"version"`
	From     string `json:"from"`
	Rollback bool   `json:"rollback"`
}

// aerolvmLong runs the CLI with the scenario's token and a long deadline:
// apply uploads a 100 MiB sandboxd from this machine and waits out the
// node's restart.
func aerolvmLong(t *testing.T, args ...string) cliResult {
	t.Helper()
	// A slow uplink moves the 113 MiB sandboxd at well under 1 Mbit/s (the
	// first live run took 39 minutes to upload it).
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, aerolvmBinary(t), args...)
	cmd.Env = tokenEnv(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("aerolvm %v: %v", args, err)
	}
	t.Logf("aerolvm %s = %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), res.code, res.stdout, res.stderr)
	return res
}

func runningVersion(t *testing.T, c *harness.Client) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var h struct {
		Version string `json:"version"`
	}
	if err := c.GetJSON(ctx, "/health", &h); err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	return h.Version
}

func latestNodeOp(t *testing.T) nodeOpView {
	t.Helper()
	r := aerolvmLong(t, "upgrade", "status", "-o", "json")
	if r.code != 0 {
		t.Fatalf("upgrade status = %d", r.code)
	}
	var op nodeOpView
	if err := json.Unmarshal([]byte(r.stdout), &op); err != nil {
		t.Fatalf("upgrade status -o json: %v\n%s", err, r.stdout)
	}
	return op
}

func requireUpgradeDisruptive(t *testing.T) {
	t.Helper()
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this restarts sandboxd")
	}
}

// keepAnswers checks the sandbox from before the upgrade still runs under
// the same ID and answers exec.
func keepAnswers(t *testing.T, sb *microvm.Sandbox, word string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := sb.Refresh(ctx)
		cancel()
		if err == nil && string(sb.Status) == "started" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s is not running after the upgrade (status %q, err %v)", sb.ID, sb.Status, err)
		}
		time.Sleep(3 * time.Second)
	}
	if out := execOK(t, sb, "echo "+word); !strings.Contains(out, word) {
		t.Fatalf("exec in %s = %q", sb.ID, out)
	}
}

// UC-660: plan reads build B from a directory and prints a single-node plan.
func TestUpgradeCLIPlanSingleNode(t *testing.T) {
	harness.Require(t, sc, "UC-660")
	requireUpgradeDisruptive(t)
	buildID := os.Getenv("AEROL_BUILD_ID")
	if os.Getenv("AEROL_BUILD_MODE") != "local" || buildID == "" {
		t.Skip("needs the node to run this tree's local build (run.sh without --released/--version)")
	}
	c := client(t)
	makeStandalone(t, c)
	upgradeLive.versionA = runningVersion(t, c)
	if upgradeLive.versionA != "itest-"+buildID {
		t.Fatalf("the node runs %q, not this tree's build itest-%s", upgradeLive.versionA, buildID)
	}
	cmd := exec.Command("bash", "../lib/build.sh", "variant", "b")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("build.sh variant b: %v\n%s", err, stderr.String())
	}
	dir := strings.TrimSpace(string(out))
	if filepath.Base(filepath.Dir(dir)) != buildID {
		t.Fatalf("variant built from tree %s, but the node runs %s: the tree changed since build A", filepath.Base(filepath.Dir(dir)), buildID)
	}
	upgradeLive.dirB, upgradeLive.versionB = dir, "itest-"+buildID+"-b"

	r := aerolvmLong(t, "upgrade", "plan", upgradeLive.versionB, "--from", dir, "--allow-unversioned")
	if r.code != 0 || !strings.Contains(r.stdout, "single-node") || !strings.Contains(r.stdout, "this node") ||
		!strings.Contains(r.stdout, upgradeLive.versionA) || !strings.Contains(r.stdout, "To go ahead: aerolvm upgrade apply "+upgradeLive.versionB) {
		t.Fatalf("plan = %d %s", r.code, r.stdout)
	}
	r = aerolvmLong(t, "upgrade", "plan", upgradeLive.versionB, "--from", dir, "--allow-unversioned", "-o", "json")
	var p struct {
		Mode  string `json:"mode"`
		Nodes []struct {
			Version string `json:"version"`
			Action  string `json:"action"`
		} `json:"nodes"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &p) != nil || p.Mode != "single-node" || len(p.Nodes) != 1 ||
		p.Nodes[0].Version != upgradeLive.versionA || p.Nodes[0].Action != "upgrade" {
		t.Fatalf("plan -o json = %d %s", r.code, r.stdout)
	}
}

// UC-661: apply --from --wait upgrades the node to B; a sandbox from before
// keeps running under the same ID and answers exec.
func TestUpgradeCLIApplySingleNode(t *testing.T) {
	harness.Require(t, sc, "UC-661")
	requireUpgradeDisruptive(t)
	if upgradeLive.dirB == "" {
		t.Skip("UC-660 did not build B")
	}
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: harness.DefaultImage})
	cancel()
	if err != nil {
		t.Fatalf("create the sandbox to keep: %v", err)
	}
	upgradeLive.keep = sb
	waitRunning(t, sb)
	execOK(t, sb, "echo before > /tmp/uc661")

	start := time.Now()
	r := aerolvmOnNode(t, "upgrade", "apply", upgradeLive.versionB, "--from", upgradeLive.dirB, "--allow-unversioned", "--wait")
	if r.code != 0 {
		t.Fatalf("apply = %d", r.code)
	}
	t.Logf("apply --wait took %s", time.Since(start).Round(time.Second))
	if !strings.Contains(r.stderr, "uploading sandboxd_linux_amd64") || !strings.Contains(r.stdout, "node now runs "+upgradeLive.versionB) {
		t.Fatalf("apply output: %s %s", r.stdout, r.stderr)
	}
	if got := runningVersion(t, c); got != upgradeLive.versionB {
		t.Fatalf("/health reports %q after the upgrade, want %s", got, upgradeLive.versionB)
	}
	keepAnswers(t, sb, "after-upgrade")
	if out := execOK(t, sb, "cat /tmp/uc661"); !strings.Contains(out, "before") {
		t.Fatalf("the sandbox lost its file: %q", out)
	}
}

// UC-662: the same apply again is a no-op: nothing is uploaded, no new
// operation, sandboxd keeps running.
func TestUpgradeCLIApplyAgainIsNoop(t *testing.T) {
	harness.Require(t, sc, "UC-662")
	requireUpgradeDisruptive(t)
	if upgradeLive.dirB == "" || upgradeLive.keep == nil {
		t.Skip("UC-661 did not upgrade")
	}
	before := latestNodeOp(t)
	r := aerolvmOnNode(t, "upgrade", "apply", upgradeLive.versionB, "--from", upgradeLive.dirB, "--allow-unversioned", "--wait")
	if r.code != 0 || !strings.Contains(r.stdout, "node already runs "+upgradeLive.versionB+"; nothing to do") ||
		strings.Contains(r.stderr, "uploading") || !strings.Contains(r.stderr, "sandboxd_linux_amd64 is already there") {
		t.Fatalf("repeat = %d %s %s", r.code, r.stdout, r.stderr)
	}
	if after := latestNodeOp(t); after.Op != before.Op {
		t.Fatalf("a repeat started operation %s (the last was %s)", after.Op, before.Op)
	}
	if got := runningVersion(t, client(t)); got != upgradeLive.versionB {
		t.Fatalf("/health reports %q", got)
	}
}

// UC-663: status shows the operation (text and -o json).
func TestUpgradeCLIStatusSingleNode(t *testing.T) {
	harness.Require(t, sc, "UC-663")
	requireUpgradeDisruptive(t)
	if upgradeLive.versionB == "" || upgradeLive.keep == nil {
		t.Skip("UC-661 did not upgrade")
	}
	op := latestNodeOp(t)
	if op.State != "done" || op.Version != upgradeLive.versionB || op.From != upgradeLive.versionA || op.Rollback || op.Op == "" {
		t.Fatalf("status -o json = %+v", op)
	}
	upgradeLive.op = op
	r := aerolvmLong(t, "upgrade", "status")
	if r.code != 0 || !strings.Contains(r.stdout, "Node upgrade:  "+op.Op) || !strings.Contains(r.stdout, "State:         done") ||
		!strings.Contains(r.stdout, upgradeLive.versionB+", from "+upgradeLive.versionA) {
		t.Fatalf("status = %d %s", r.code, r.stdout)
	}
	// Cluster-only verbs say so on a single node.
	if r := aerolvmLong(t, "upgrade", "stop"); r.code != 1 || !strings.Contains(r.stderr, "single node: there is no rollout to stop") {
		t.Fatalf("stop = %d %s", r.code, r.stderr)
	}
}

// UC-664: rollback --wait puts A back; the sandbox still runs; a second
// rollback is a no-op.
func TestUpgradeCLIRollbackSingleNode(t *testing.T) {
	harness.Require(t, sc, "UC-664")
	requireUpgradeDisruptive(t)
	if upgradeLive.keep == nil || upgradeLive.versionB == "" {
		t.Skip("UC-661 did not upgrade")
	}
	c := client(t)
	t.Cleanup(func() { destroyBest(c, upgradeLive.keep.ID) })
	r := aerolvmLong(t, "upgrade", "rollback", "--wait")
	if r.code != 0 || !strings.Contains(r.stdout, "node now runs "+upgradeLive.versionA) {
		t.Fatalf("rollback = %d %s %s", r.code, r.stdout, r.stderr)
	}
	if got := runningVersion(t, c); got != upgradeLive.versionA {
		t.Fatalf("/health reports %q after the rollback, want %s", got, upgradeLive.versionA)
	}
	keepAnswers(t, upgradeLive.keep, "after-rollback")
	op := latestNodeOp(t)
	if !op.Rollback || op.Version != upgradeLive.versionA || op.State != "done" {
		t.Fatalf("rollback op = %+v", op)
	}
	if r := aerolvmLong(t, "upgrade", "rollback"); r.code != 0 || !strings.Contains(r.stdout, "already rolled back to "+upgradeLive.versionA) {
		t.Fatalf("second rollback = %d %s %s", r.code, r.stdout, r.stderr)
	}
	if again := latestNodeOp(t); again.Op != op.Op {
		t.Fatalf("a second rollback started %s", again.Op)
	}
}

// UC-665: release pull fetches a real GitHub release into a checked bundle;
// a tampered copy and an unknown bundle format are refused before anything
// reaches sandboxd.
func TestUpgradeCLIReleasePullAndTamperedBundle(t *testing.T) {
	harness.Require(t, sc, "UC-665")
	requireUpgradeDisruptive(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "aerolvm-v0.6.11.tgz")
	r := aerolvmLong(t, "release", "pull", "v0.6.11", "--arch", "amd64", "-o", good)
	if r.code != 0 || !strings.Contains(r.stdout, "wrote "+good+": v0.6.11") {
		t.Fatalf("release pull = %d %s %s", r.code, r.stdout, r.stderr)
	}
	entries := readTgz(t, good)
	var names []string
	for _, e := range entries {
		names = append(names, e.name)
	}
	if got := strings.Join(names, " "); got != "manifest.json checksums.txt caddy_linux_amd64 sandboxd_linux_amd64 toolboxd_linux_amd64 v0.6.11.intoto.jsonl" {
		t.Fatalf("bundle holds %s", got)
	}
	var before nodeOpView
	if r := aerolvmLong(t, "upgrade", "status", "-o", "json"); r.code == 0 {
		_ = json.Unmarshal([]byte(r.stdout), &before)
	}
	// One byte of sandboxd changed: refused, before any call.
	tampered := filepath.Join(dir, "tampered.tgz")
	for i := range entries {
		if entries[i].name == "sandboxd_linux_amd64" {
			entries[i].body[len(entries[i].body)/2] ^= 0xff
		}
	}
	writeTgz(t, tampered, entries)
	r = aerolvmLong(t, "upgrade", "apply", "v0.6.11", "--from", tampered)
	if r.code != 1 || !strings.Contains(r.stderr, "sandboxd_linux_amd64 has SHA-256") || !strings.Contains(r.stderr, "refusing it") {
		t.Fatalf("tampered bundle = %d %s", r.code, r.stderr)
	}
	// A bundle format this aerolvm does not know.
	future := filepath.Join(dir, "future.tgz")
	writeTgz(t, future, []tgzEntry{{name: "manifest.json", body: []byte(`{"bundle_format":2,"version":"v0.6.11"}`)}})
	r = aerolvmLong(t, "upgrade", "apply", "v0.6.11", "--from", future)
	if r.code != 1 || !strings.Contains(r.stderr, "bundle format 2, and this aerolvm reads format 1") {
		t.Fatalf("future bundle = %d %s", r.code, r.stderr)
	}
	var after nodeOpView
	if r := aerolvmLong(t, "upgrade", "status", "-o", "json"); r.code == 0 {
		_ = json.Unmarshal([]byte(r.stdout), &after)
	}
	if after.Op != before.Op {
		t.Fatalf("a refused bundle started operation %s", after.Op)
	}
}

// UC-666: the node's upload route checks every file against its name.
func TestUpgradeCLINodeFileRoutes(t *testing.T) {
	// The last case puts cluster mode back, whatever happened before.
	t.Cleanup(func() {
		if upgradeLive.standaloneTarget == "" {
			return
		}
		if out, err := harness.SSHRun(t, upgradeLive.standaloneTarget, clusterAgain); err != nil {
			t.Errorf("RESTORE: turn cluster mode back on: %v\n%s", err, out)
			return
		}
		if !healthMode(t, client(t)) {
			t.Error("RESTORE: the node did not come back in cluster mode")
		}
	})
	harness.Require(t, sc, "UC-666")
	requireUpgradeDisruptive(t)
	body := []byte("uc666 " + time.Now().String())
	wrong := strings.Repeat("0", 64)
	if code, out := sendRaw(t, http.MethodPut, "/v1/node/upgrade/files/"+wrong, body); code != http.StatusBadRequest || !strings.Contains(out, "hash_mismatch") {
		t.Fatalf("PUT with the wrong hash = %d %s", code, out)
	}
	if code, _ := sendRaw(t, http.MethodHead, "/v1/node/upgrade/files/"+wrong, nil); code != http.StatusNotFound {
		t.Fatalf("HEAD of a file nobody uploaded = %d", code)
	}
	if code, out := sendRaw(t, http.MethodPut, "/v1/node/upgrade/files/not-a-hash", body); code != http.StatusBadRequest || !strings.Contains(out, "invalid_request") {
		t.Fatalf("PUT with a bad name = %d %s", code, out)
	}
	if code, out := sendRaw(t, http.MethodPost, "/v1/node/upgrade", []byte(`{"version":"../../etc","source":"release"}`)); code != http.StatusBadRequest {
		t.Fatalf("POST with a bad version = %d %s", code, out)
	}
}

func sendRaw(t *testing.T, method, path string, body []byte) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, sc.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+sc.PAT)
	resp, err := harness.HTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

type tgzEntry struct {
	name string
	body []byte
}

func readTgz(t *testing.T, path string) []tgzEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var out []tgzEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tgzEntry{name: hdr.Name, body: b})
	}
}

func writeTgz(t *testing.T, path string, entries []tgzEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
