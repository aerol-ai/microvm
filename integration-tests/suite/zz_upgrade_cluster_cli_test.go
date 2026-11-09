//go:build integration

package suite

// The upgrade CLI on a real cluster, and `sandboxd upgrade node` run by
// hand on a server (plans/kubectl-style-cluster-ops.md §6.1, §6.3 last
// paragraph; UC-646, UC-667, UC-668). zz_rollout_test.go drives rollouts
// with Go and the upgradewire types; these cases drive the same cluster
// with the built aerolvm binary, the way an operator does.
//
//	01 aerolvm upgrade plan + apply --hold --wait to build C     UC-667
//	02 sandboxd upgrade node --rollback by hand on servers        UC-646
//	   (refused while another server is down; on the leader it
//	   hands off leadership first)
//	03 aerolvm upgrade rollback --wait                            UC-668
//
// Build C is this tree again as itest-<id>-c (build.sh variant). Every node
// restarts: run it on cluster-rollout with AEROL_ALLOW_DISRUPTIVE=1. The
// file sorts after zz_rollout_test.go, so a full pass starts from whatever
// that one left (B, finalized), and that is fine: C is another target.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

var clusterCLI struct {
	versionPrev, versionC, dirC string
	keep                        *microvm.Sandbox
	applied                     bool
}

// UC-667: aerolvm upgrade plan and apply --hold --wait take every node to C.
func TestUpgradeCLICluster01Apply(t *testing.T) {
	harness.Require(t, sc, "UC-667")
	c, _ := requireRolloutLive(t)
	buildID := os.Getenv("AEROL_BUILD_ID")
	if os.Getenv("AEROL_BUILD_MODE") != "local" || buildID == "" {
		t.Skip("needs this tree's local build (run.sh without --released/--version)")
	}
	if !healthMode(t, c) {
		t.Skip("needs a cluster")
	}
	// The harness's single-node scenarios are one-server clusters, where
	// apply needs --allow-downtime and UC-646 has no follower to stop.
	voters := 0
	for _, m := range listNodeViews(t, c) {
		if m.Voter {
			voters++
		}
	}
	if voters < 3 {
		t.Skipf("needs three voting servers, found %d", voters)
	}
	before := memberVersions(t, c)
	for _, v := range before {
		clusterCLI.versionPrev = v
	}
	for id, v := range before {
		if v != clusterCLI.versionPrev {
			t.Fatalf("members run more than one build before the apply (%s runs %s): %v", id, v, before)
		}
	}
	cmd := exec.Command("bash", "../lib/build.sh", "variant", "c")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("build.sh variant c: %v\n%s", err, stderr.String())
	}
	clusterCLI.dirC = strings.TrimSpace(string(out))
	if filepath.Base(filepath.Dir(clusterCLI.dirC)) != buildID {
		t.Fatalf("variant built from tree %s, but the cluster runs %s", filepath.Base(filepath.Dir(clusterCLI.dirC)), buildID)
	}
	clusterCLI.versionC = "itest-" + buildID + "-c"

	r := aerolvmLong(t, "upgrade", "plan", clusterCLI.versionC, "--from", clusterCLI.dirC, "--allow-unversioned", "-o", "json")
	var p struct {
		Mode    string `json:"mode"`
		Allowed bool   `json:"allowed"`
		Nodes   []struct {
			NodeID string `json:"node_id"`
			Action string `json:"action"`
		} `json:"nodes"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &p) != nil || p.Mode != "cluster" || !p.Allowed || len(p.Nodes) != len(before) {
		t.Fatalf("plan = %d %s %s", r.code, r.stdout, r.stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: harness.DefaultImage})
	cancel()
	if err != nil {
		t.Fatalf("create the sandbox to keep: %v", err)
	}
	clusterCLI.keep = sb
	waitRunning(t, sb)
	execOK(t, sb, "echo before > /tmp/uc667")

	start := time.Now()
	r = aerolvmLong(t, "upgrade", "apply", clusterCLI.versionC, "--from", clusterCLI.dirC, "--allow-unversioned",
		"--hold", "--batch", "50%", "--wait")
	t.Logf("apply --wait took %s\n%s\n%s", time.Since(start).Round(time.Second), r.stdout, r.stderr)
	if r.code != 0 {
		t.Fatalf("apply = %d", r.code)
	}
	clusterCLI.applied = true
	waitAllOn(t, c, clusterCLI.versionC, 5*time.Minute)

	r = aerolvmLong(t, "upgrade", "status", "-o", "json")
	var ro upgradewire.Rollout
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &ro) != nil || ro.State != upgradewire.StateDone || ro.TargetVersion != clusterCLI.versionC || !ro.Hold {
		t.Fatalf("status = %d %s", r.code, r.stdout)
	}
	keepAnswers(t, sb, "after-cli-apply")
	if out := execOK(t, sb, "cat /tmp/uc667"); !strings.Contains(out, "before") {
		t.Fatalf("the sandbox lost its file: %q", out)
	}
}

// UC-646: run by hand on a server, sandboxd upgrade node keeps quorum and
// moves leadership off the node before it stops sandboxd.
func TestUpgradeCLICluster02HandRunKeepsQuorum(t *testing.T) {
	harness.Require(t, sc, "UC-646")
	c, targets := requireRolloutLive(t)
	if !clusterCLI.applied {
		t.Skip("UC-667 did not apply C")
	}
	servers := rolloutNodesOfRole(t, targets, "server")
	if len(servers) != 3 {
		t.Skipf("needs three SSH-reachable servers, found %d", len(servers))
	}
	waitServersListed(t, c, servers)
	leaderID := currentLeader(t, c)
	// Every id is read now, while all three are listed: a server stopped
	// below leaves gossip and drops out of the list, so its id can no
	// longer be looked up there (2026-11-09: the lookup after the stop fell
	// back to a guessed id and the case waited on it for 5 minutes).
	ids := map[string]string{}
	var leader harness.IntegrationNode
	var followers []harness.IntegrationNode
	for _, s := range servers {
		ids[s.Name] = heteroNodeID(t, c, targets, s.Name)
		if ids[s.Name] == leaderID {
			leader = s
		} else {
			followers = append(followers, s)
		}
	}
	if leader.Name == "" || len(followers) != 2 {
		t.Fatalf("leader %q not among the servers %v", leaderID, servers)
	}
	handRun := "sandboxd upgrade node " + clusterCLI.versionPrev + " --rollback --allow-unversioned 2>&1; echo exit=$?"

	// One follower down: stopping the other would leave 1 of 3 voters. Not
	// the seed, whose restart costs the rendezvous every joiner needs; of
	// two followers at least one is not the seed.
	down, other := followers[0], followers[1]
	if down.Seed {
		down, other = other, down
	}
	downTarget, _ := harness.SSHTarget(down)
	harness.MarkNodeDown(down.PublicIP)
	sshRoot(t, down, "systemctl stop sandboxd")
	restarted := false
	defer func() {
		if !restarted {
			restoreNodeDaemon(t, down, downTarget)
		}
	}()
	// The guard counts what gossip says, so wait until the cluster sees
	// the stopped server as down.
	downID := ids[down.Name]
	waitVoter(t, c, downID, false)
	out := sshRoot(t, other, handRun)
	if !strings.Contains(out, "exit=1") || !strings.Contains(out, "refusing to stop sandboxd") || !strings.Contains(out, "1 of 3 voting servers") {
		t.Fatalf("hand run with a server down was not refused:\n%s", out)
	}
	if v := strings.TrimSpace(sshRoot(t, other, "systemctl is-active sandboxd")); v != "active" {
		t.Fatalf("a refused upgrade stopped sandboxd on %s: %s", other.Name, v)
	}
	restarted = true
	restoreNodeDaemon(t, down, downTarget)
	if t.Failed() {
		t.FailNow() // the restore said why; the leader's hand run needs all three servers
	}
	waitVoter(t, c, downID, true)

	// On the leader: leadership moves first, then the node rolls back.
	out = sshRoot(t, leader, handRun)
	if !strings.Contains(out, "exit=0") || !strings.Contains(out, "handed leadership to") {
		t.Fatalf("hand run on the leader:\n%s", out)
	}
	waitLeader(t, c, leaderID, time.Minute)
	deadline := time.Now().Add(5 * time.Minute)
	for memberVersions(t, c)[leaderID] != clusterCLI.versionPrev {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reported %s: %v", leaderID, clusterCLI.versionPrev, memberVersions(t, c))
		}
		time.Sleep(5 * time.Second)
	}
}

// UC-668: aerolvm upgrade rollback --wait puts every node back; the node
// rolled back by hand is skipped, and the kept sandbox still answers.
func TestUpgradeCLICluster03Rollback(t *testing.T) {
	harness.Require(t, sc, "UC-668")
	c, _ := requireRolloutLive(t)
	if !clusterCLI.applied {
		t.Skip("UC-667 did not apply C")
	}
	r := aerolvmLong(t, "upgrade", "rollback", "--wait")
	t.Logf("rollback:\n%s\n%s", r.stdout, r.stderr)
	if r.code != 0 {
		t.Fatalf("rollback = %d", r.code)
	}
	waitAllOn(t, c, clusterCLI.versionPrev, 5*time.Minute)
	r = aerolvmLong(t, "upgrade", "status", "-o", "json")
	var ro upgradewire.Rollout
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &ro) != nil || ro.State != upgradewire.StateRolledBack {
		t.Fatalf("status = %d %s", r.code, r.stdout)
	}
	if clusterCLI.keep != nil {
		keepAnswers(t, clusterCLI.keep, "after-cli-rollback")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_ = c.SDK().Destroy(ctx, clusterCLI.keep.ID)
		cancel()
	}
}

// waitVoter waits until the voter nodeID is alive (or down) in gossip.
// waitServersListed waits until /v1/cluster/members lists every server
// alive. UC-667's rollout upgrades the old leader last, and a restart leaves
// gossip cleanly, so for a few seconds after the rollout ends the member list
// does not show that server at all. Resolving node ids then fell back to a
// guessed id (heteroNodeID), and UC-646 waited 5 minutes for a node that does
// not exist to go down (2026-11-09: it started 25 s after server-1's restart).
func waitServersListed(t *testing.T, c *harness.Client, servers []harness.IntegrationNode) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		views := listNodeViews(t, c)
		var missing []string
		for _, s := range servers {
			if !slices.ContainsFunc(views, func(m nodeView) bool {
				return m.Alive && (m.NodeID == s.Name || strings.HasSuffix(m.NodeID, "-"+s.Name))
			}) {
				missing = append(missing, s.Name)
			}
		}
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("servers %v are not listed alive in /v1/cluster/members", missing)
		}
		time.Sleep(3 * time.Second)
	}
}

func waitVoter(t *testing.T, c *harness.Client, nodeID string, alive bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		listed := false
		for _, m := range listNodeViews(t, c) {
			if m.NodeID == nodeID {
				listed = true
				if m.Alive == alive {
					return
				}
			}
		}
		// A stopped server leaves gossip cleanly and drops out of the list
		// rather than showing alive=false; the stop guard reads it as down
		// the same way.
		if !alive && !listed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never became alive=%v", nodeID, alive)
		}
		time.Sleep(3 * time.Second)
	}
}
