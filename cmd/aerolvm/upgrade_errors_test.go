package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// statusCode turns a bare HTTP status from the upgrade routes into the
// agenttools code a script branches on.
func TestStatusCodeMapsEveryStatus(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusBadRequest:            agenttools.CodeInvalidArgument,
		http.StatusUnauthorized:          agenttools.CodeUnauthorized,
		http.StatusForbidden:             agenttools.CodeForbidden,
		http.StatusNotFound:              agenttools.CodeNotFound,
		http.StatusConflict:              agenttools.CodeConflict,
		http.StatusRequestEntityTooLarge: agenttools.CodeTooLarge,
		http.StatusBadGateway:            agenttools.CodeUnavailable,
		http.StatusServiceUnavailable:    agenttools.CodeUnavailable,
		http.StatusGatewayTimeout:        agenttools.CodeUnavailable,
		http.StatusTooManyRequests:       agenttools.CodeUnavailable,
		http.StatusTeapot:                agenttools.CodeInternal,
	} {
		if got := statusCode(status); got != want {
			t.Errorf("statusCode(%d) = %q, want %q", status, got, want)
		}
	}
}

// A single node's rollback prints its op as JSON, and one the node refuses
// fails with the node's reason. stop, resume and finalize fail the same way
// when the cluster has no upgrade API.
func TestUpgradeRollbackAndRolloutCommandErrors(t *testing.T) {
	f := newFakeUpgrade(t, false, "v0.6.13")
	h := upgradeHarness(t, f)
	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-7", State: upgradewire.NodeOpDone, Version: "v0.6.13", From: "v0.6.12"}}
	if code := h.run("upgrade", "rollback", "-o", "json"); code != exitOK {
		t.Fatalf("rollback -o json = %d %s", code, h.stderr.String())
	}
	var op upgradewire.NodeUpgradeResponse
	h.jsonOut(&op)
	if !op.Rollback || op.Version != "v0.6.12" || op.From != "v0.6.13" {
		t.Fatalf("rollback op = %+v", op)
	}

	f.ops = []upgradewire.NodeUpgradeResponse{{Op: "op-7", State: upgradewire.NodeOpDone, Version: "v0.6.13", From: "v0.6.12"}}
	f.remoteOff = true
	if code := h.run("upgrade", "rollback"); code != exitError || !strings.Contains(h.stderr.String(), "SB_REMOTE_UPGRADE is off") {
		t.Fatalf("refused rollback = %d %q", code, h.stderr.String())
	}

	c := newFakeUpgrade(t, true, "v0.6.12")
	stdFleet(c, "v0.6.12")
	hc := upgradeHarness(t, c)
	c.noRoutes = true
	for _, verb := range []string{"stop", "resume", "finalize"} {
		if code := hc.run("upgrade", verb); code != exitError || !strings.Contains(hc.stderr.String(), "no upgrade API") {
			t.Errorf("%s with no upgrade API = %d %q", verb, code, hc.stderr.String())
		}
	}
}

// While --wait follows a rollout, reads that fail for longer than one
// read's retries (a server restarting) are waited out with one note, and
// the rollout is still followed to its end.
func TestUpgradeWaitRidesOutAnAPIOutage(t *testing.T) {
	old := clusterReadRetryDelays
	clusterReadRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { clusterReadRetryDelays = old })
	f := newFakeUpgrade(t, true, "v0.6.12")
	stdFleet(f, "v0.6.12")
	h := upgradeHarness(t, f)
	dir, _ := distDir(t, "v0.6.13", true)
	f.advance = true
	f.failRolloutGets = 2 * (len(clusterReadRetryDelays) + 1)
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait"); code != exitOK {
		t.Fatalf("apply --wait = %d %s", code, h.stderr.String())
	}
	if n := strings.Count(h.stderr.String(), "the API is not answering"); n != 1 {
		t.Fatalf("outage notes = %d, want 1:\n%s", n, h.stderr.String())
	}
	if f.failRolloutGets != 0 || f.rollout.State != upgradewire.StateFinalized {
		t.Fatalf("left %d failing reads, rollout %s", f.failRolloutGets, f.rollout.State)
	}
}

// belowFloor needs release.json to judge anything, counts each version once,
// and skips a version it can't order (a dev build).
func TestBelowFloorSkipsWhatItCannotJudge(t *testing.T) {
	if got := belowFloor(nil, []string{"v0.1.0"}); got != nil {
		t.Fatalf("no release.json = %v", got)
	}
	meta := releaseMeta("v0.6.13", "v0.6.12", "x", []int{1})
	got := belowFloor(meta, []string{"itest-abc", "v0.6.11", "v0.6.11", "v0.6.12", "v0.6.10"})
	if strings.Join(got, ",") != "v0.6.10,v0.6.11" {
		t.Fatalf("below the floor = %v", got)
	}
}

// printRollout lists every setting a rollout started with, orders its
// nodes by order then ID, and prints no node table before any node has a
// row; printNodeOp shows an op's error.
func TestUpgradePrintersShowEverySetting(t *testing.T) {
	h := newHarness(t)
	h.app.printRollout(upgradewire.Rollout{ID: "ro-1", State: upgradewire.StateRunning, TargetVersion: "v0.6.13",
		Batch: "10%", PauseAfter: 2, NodeTimeout: "10m0s", Hold: true, AllowDowntime: true, Error: "the leader changed"})
	out := h.stdout.String()
	for _, want := range []string{"batch 10%, pause after 2, node timeout 10m0s, hold, allow downtime", "Error:", "the leader changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("rollout summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ORDER") {
		t.Fatalf("a rollout with no nodes printed a node table:\n%s", out)
	}

	h = newHarness(t)
	h.app.printRollout(upgradewire.Rollout{ID: "ro-2", Nodes: []upgradewire.RolloutNode{
		{NodeID: "wkr-b", Order: 1}, {NodeID: "wkr-a", Order: 1}, {NodeID: "srv-a", Order: 0}}})
	out = h.stdout.String()
	if a, b, c := strings.Index(out, "srv-a"), strings.Index(out, "wkr-a"), strings.Index(out, "wkr-b"); !(a >= 0 && a < b && b < c) {
		t.Fatalf("nodes not in order then ID:\n%s", out)
	}

	h = newHarness(t)
	h.app.printNodeOp(upgradewire.NodeUpgradeResponse{Op: "op-1", State: upgradewire.NodeOpFailed, Version: "v0.6.13", Error: "boom"}, "v0.6.12")
	if out := h.stdout.String(); !strings.Contains(out, "Error:") || !strings.Contains(out, "boom") {
		t.Fatalf("node op lacks its error:\n%s", out)
	}
}

// A single node's apply prints JSON on every ending: a node that already
// runs the version, an upgrade that finishes, and one that fails (the op
// is printed, then the command fails).
func TestUpgradeSingleNodeJSONEndings(t *testing.T) {
	dir, _ := distDir(t, "v0.6.13", true)
	f := newFakeUpgrade(t, false, "v0.6.13")
	h := upgradeHarness(t, f)
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "-o", "json"); code != exitOK {
		t.Fatalf("same version = %d %s", code, h.stderr.String())
	}
	var op upgradewire.NodeUpgradeResponse
	h.jsonOut(&op)
	if op.State != upgradewire.NodeOpDone || op.Version != "v0.6.13" {
		t.Fatalf("same version op = %+v", op)
	}

	f = newFakeUpgrade(t, false, "v0.6.12")
	h = upgradeHarness(t, f)
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait", "-o", "json"); code != exitOK {
		t.Fatalf("apply --wait -o json = %d %s", code, h.stderr.String())
	}
	h.jsonOut(&op)
	if op.State != upgradewire.NodeOpDone || op.Version != "v0.6.13" {
		t.Fatalf("finished op = %+v", op)
	}

	f = newFakeUpgrade(t, false, "v0.6.12")
	f.failWith = "the new sandboxd did not report v0.6.13 within 2m0s"
	h = upgradeHarness(t, f)
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", dir, "--wait", "-o", "json"); code != exitError || !strings.Contains(h.stderr.String(), "did not report v0.6.13") {
		t.Fatalf("failed apply = %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), `"state": "failed"`) {
		t.Fatalf("a failed op was not printed:\n%s", h.stdout.String())
	}
}

// release pull fails, and leaves nothing behind, when the provenance
// download breaks (a 500, unlike a release that publishes none) or the
// bundle file can't be created.
func TestReleasePullIOFailures(t *testing.T) {
	h, r, dir := pullHarness(t)
	out := filepath.Join(dir, "x.tgz")
	r.mu.Lock()
	r.fail = map[string]bool{"v0.6.13/v0.6.13.intoto.jsonl": true}
	r.mu.Unlock()
	if code := h.run("release", "pull", "v0.6.13", "-o", out); code != exitError || !strings.Contains(h.stderr.String(), "500") {
		t.Fatalf("broken provenance = %d %q", code, h.stderr.String())
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("a failed pull left %d files", len(left))
	}
	r.mu.Lock()
	r.fail = nil
	r.mu.Unlock()
	if err := os.Mkdir(out+".part", 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("release", "pull", "v0.6.13", "-o", out); code != exitError || !strings.Contains(h.stderr.String(), "is a directory") {
		t.Fatalf("unwritable bundle = %d %q", code, h.stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a failed pull left %s: %v", out, err)
	}
}
