//go:build integration

package suite

// The node's day-2 tools in Go (plans/kubectl-style-cluster-ops.md Phase 5,
// UC-680..682): `sandboxd backup`, `sandboxd restore` and `sandboxd
// recover-quorum`, which replace the repo-only scripts. Each case stops
// sandboxd on the nodes it works on, so the file sorts after the rest.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// opsSSH runs script on node and fails the case on a non-zero exit.
func opsSSH(t *testing.T, node harness.IntegrationNode, script string) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, script)
	if err != nil {
		t.Fatalf("%s: %v\n%s", node.Name, err, out)
	}
	return out
}

// opsExit runs script on node and returns its output and exit status, for
// the refusals a case expects.
func opsExit(t *testing.T, node harness.IntegrationNode, script string) (string, string) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, _ := harness.SSHRun(t, target, script+"; echo \"exit=$?\"")
	m := regexp.MustCompile(`exit=(\d+)\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%s: no exit status in:\n%s", node.Name, out)
	}
	return out, m[1]
}

// opsSingleNode is the one node of a single-node scenario.
func opsSingleNode(t *testing.T) harness.IntegrationNode {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	if len(targets.Nodes) != 1 {
		t.Skipf("a single-node case; this scenario has %d nodes", len(targets.Nodes))
	}
	node := targets.Nodes[0]
	harness.RequireNodeSSH(t, node)
	return node
}

var vacuumLine = regexp.MustCompile(`backed up \S+ \(([^)]*)\) with VACUUM INTO in (\S+)`)

// UC-680 — `sandboxd backup`, then `sandboxd restore` brings the node back
// to the backup: what was made after the backup is gone, what was there
// before still works, and sandboxd is healthy. Restore refuses while
// sandboxd runs.
func TestOpsBackupRestoreRoundTrip(t *testing.T) {
	harness.Require(t, sc, "UC-680")
	node := opsSingleNode(t)
	c := client(t)

	before := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-a"})
	waitRunning(t, before)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	snap := "uc680-snap-" + harness.UniqueName(sc, t)
	if _, err := c.SDK().CreateSnapshot(ctx, before.ID, snap); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteSnapshot(cctx, snap)
	})

	t.Cleanup(func() { opsSSH(t, node, "sudo rm -f /var/tmp/itest-680.tgz") })
	out := opsSSH(t, node, "sudo sandboxd backup --output /var/tmp/itest-680.tgz")
	m := vacuumLine.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "wrote /var/tmp/itest-680.tgz") {
		t.Fatalf("sandboxd backup output:\n%s", out)
	}
	t.Logf("UC-680: state.db (%s) backed up with VACUUM INTO in %s", m[1], m[2])
	manifest := opsSSH(t, node, "sudo tar -xOzf /var/tmp/itest-680.tgz ./MANIFEST.txt; stat -c '%a' /var/tmp/itest-680.tgz")
	for _, want := range []string{"state_db_copy=vacuum_into", "included=/var/lib/sandboxd/state.db", "included=/etc/sandboxd", "\n600"} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("the archive's manifest or mode lacks %q:\n%s", want, manifest)
		}
	}

	// After the backup: a sandbox and a snapshot the backup does not have.
	after := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-c"})
	waitRunning(t, after)
	snapAfter := "uc680-after-" + harness.UniqueName(sc, t)
	if _, err := c.SDK().CreateSnapshot(ctx, before.ID, snapAfter); err != nil {
		t.Fatalf("CreateSnapshot after the backup: %v", err)
	}

	// A restore under a running sandboxd is refused, and nothing moves.
	got, code := opsExit(t, node, "sudo sandboxd restore --input /var/tmp/itest-680.tgz --force 2>&1")
	if code != "1" || !strings.Contains(got, "sandboxd is running") {
		t.Fatalf("restore with sandboxd running: exit %s\n%s", code, got)
	}

	restoredAt := strings.TrimSpace(opsSSH(t, node, "date -u '+%Y-%m-%d %H:%M:%S'"))
	t.Cleanup(func() {
		// A failed restore must not leave the node down for later cases.
		target, _ := harness.SSHTarget(node)
		_, _ = harness.SSHRun(t, target, "sudo systemctl is-active --quiet sandboxd || sudo systemctl start sandboxd")
		harness.MarkNodeUp(node.PublicIP)
	})
	harness.MarkNodeDown(node.PublicIP)
	out = opsSSH(t, node, "sudo systemctl stop sandboxd && sudo sandboxd restore --input /var/tmp/itest-680.tgz --force --start")
	harness.MarkNodeUp(node.PublicIP)
	for _, want := range []string{"moved aside: /var/lib/sandboxd/state.db -> ", "restored /var/tmp/itest-680.tgz into /", "sandboxd is up"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sandboxd restore output lacks %q:\n%s", want, out)
		}
	}
	if err := waitNodeRejoined(t, node); err != nil {
		t.Fatalf("the API did not come back after the restore: %v", err)
	}

	// The backup's state: the snapshot and the sandbox from before it.
	if got, err := c.SDK().GetSnapshot(ctx, snap); err != nil || got.Name != snap {
		t.Fatalf("snapshot %s from before the backup: %+v %v", snap, got, err)
	}
	if err := before.Refresh(ctx); err != nil {
		t.Fatalf("sandbox %s from before the backup: %v", before.ID, err)
	}
	if out := execOK(t, before, "echo still-here"); !strings.Contains(out, "still-here") {
		t.Fatalf("exec in %s after the restore: %q", before.ID, out)
	}
	// Made after the backup: gone from the restored database.
	if _, err := c.SDK().GetSnapshot(ctx, snapAfter); !errors.Is(err, microvm.ErrNotFound) {
		t.Fatalf("snapshot %s made after the backup: %v, want not found", snapAfter, err)
	}
	if _, err := c.SDK().Get(ctx, after.ID); !errors.Is(err, microvm.ErrNotFound) {
		t.Fatalf("sandbox %s made after the backup: %v, want not found", after.ID, err)
	}
	// The restored database still serves writes: a sandbox from the
	// restored snapshot.
	fromSnap := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-s", Image: snap})
	waitRunning(t, fromSnap)
	if errs := opsSSH(t, node, "sudo journalctl -u sandboxd --no-pager --since '"+restoredAt+"' | grep -ciE 'database disk image is malformed|no such table' || true"); strings.TrimSpace(errs) != "0" {
		t.Fatalf("sandboxd logged database errors after the restore (%s)", strings.TrimSpace(errs))
	}
	t.Logf("UC-680 PASS: restore brought back %s and %s, dropped %s and %s, and sandboxd is healthy", before.ID, snap, after.ID, snapAfter)
}

// UC-681 — `sandboxd backup` of a state.db near 1 GiB on the node's own
// disk, built from the node's real schema: the VACUUM INTO time an upgrade
// adds to the node's downtime (eng review T15). It reads a copy, so the
// live database is untouched.
func TestOpsBackupTimeOnALargeStateDB(t *testing.T) {
	harness.Require(t, sc, "UC-681")
	node := opsSingleNode(t)
	const dir = "/var/tmp/itest-681"
	t.Cleanup(func() { opsSSH(t, node, "sudo rm -rf "+dir) })
	build := opsSSH(t, node, `set -e
command -v sqlite3 >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q sqlite3 >/dev/null 2>&1
sudo rm -rf `+dir+` && sudo mkdir -p `+dir+`
sudo sqlite3 /var/lib/sandboxd/state.db "VACUUM INTO '`+dir+`/state.db'"
start=$(date +%s)
sudo sqlite3 `+dir+`/state.db "PRAGMA journal_mode=DELETE;
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 100000)
  INSERT INTO sandbox_snapshots (owner_ref, name, image, source_sandbox_id, created_at, image_digest)
  SELECT 'itest', printf('snap-%010d', x), printf('aerolvm/snapshot:%010d', x), printf('sb-%012d', x), datetime('now'), printf('sha256:%064d', x) FROM c;
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 850000)
  INSERT INTO secret_audit_index (sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries)
  SELECT printf('sb-%012d', x % 100000), 'inc-1', x, x * 4096, x * 4096 + 4095, x, x, x, 64, randomblob(1024) FROM c;" >/dev/null
echo "built_seconds=$(( $(date +%s) - start ))"
echo "db_bytes=$(sudo stat -c %s `+dir+`/state.db)"
df -h `+dir+` | tail -1`)
	t.Logf("UC-681: test database:\n%s", build)
	out := opsSSH(t, node, "sudo sandboxd backup --state-db "+dir+"/state.db --raft-dir "+dir+"/none --config-dir "+dir+"/none "+
		"--key-file "+dir+"/none --key-ring "+dir+"/none --output "+dir+"/out/b.tgz")
	m := vacuumLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("sandboxd backup output:\n%s", out)
	}
	took, err := time.ParseDuration(m[2])
	if err != nil {
		t.Fatalf("VACUUM INTO time %q: %v", m[2], err)
	}
	total := regexp.MustCompile(`wrote \S+ \(([^)]*)\) in (\S+)`).FindStringSubmatch(out)
	if total == nil {
		t.Fatalf("sandboxd backup output:\n%s", out)
	}
	t.Logf("UC-681 MEASURED: state.db %s copied with VACUUM INTO in %s; the whole backup (gzip) %s in %s", m[1], took, total[1], total[2])
	// A sanity bound, not a target: a node upgrade waits on this copy with
	// sandboxd stopped.
	if took > 5*time.Minute {
		t.Fatalf("VACUUM INTO of %s took %s", m[1], took)
	}
}

// UC-682 — lost quorum: with two of three servers stopped the cluster has
// no leader and refuses writes. `sandboxd recover-quorum --start` on the
// survivor makes it the only voter: the cluster leads and serves writes
// again, a sandbox from before is still there, and `recover-quorum --rejoin
// --start` on each lost server brings it back as a voter. Refusals on the
// way: recover-quorum while sandboxd runs, --rejoin on the seed.
func TestOpsLostQuorumRecovery(t *testing.T) {
	harness.Require(t, sc, "UC-682")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	var survivor harness.IntegrationNode
	var lost []harness.IntegrationNode
	for _, n := range targets.Nodes {
		if !strings.EqualFold(n.Role, "server") {
			continue
		}
		if n.Seed {
			survivor = n
		} else {
			lost = append(lost, n)
		}
	}
	if survivor.Name == "" || len(lost) != 2 {
		t.Skipf("needs three server-only nodes with the seed among them (seed %q, others %d)", survivor.Name, len(lost))
	}
	for _, n := range append([]harness.IntegrationNode{survivor}, lost...) {
		harness.RequireNodeSSH(t, n)
	}
	survivorTarget, _ := harness.SSHTarget(survivor)
	nodeID := func(n harness.IntegrationNode) string {
		return strings.TrimSpace(opsSSH(t, n, `sudo bash -c '`+sqliteSourceEnv+`echo "$SB_NODE_ID"'`))
	}
	survivorID := nodeID(survivor)
	c := client(t)
	keep := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-keep"})
	waitRunning(t, keep)

	// Refused with no side effect: the survivor still runs, and the seed
	// would bootstrap a cluster of its own with an empty Raft log.
	if out, code := opsExit(t, survivor, "sudo sandboxd recover-quorum 2>&1"); code != "1" || !strings.Contains(out, "sandboxd is running here") {
		t.Fatalf("recover-quorum with sandboxd running: exit %s\n%s", code, out)
	}
	if out, code := opsExit(t, survivor, "sudo sandboxd recover-quorum --rejoin 2>&1"); code != "1" || !strings.Contains(out, "SB_CLUSTER_BOOTSTRAP=true") {
		t.Fatalf("--rejoin on the seed: exit %s\n%s", code, out)
	}

	// Lose two of three servers.
	recovered, rejoined := false, map[string]bool{}
	t.Cleanup(func() {
		for _, n := range lost {
			if rejoined[n.Name] {
				continue
			}
			script := "sudo systemctl start sandboxd"
			if recovered {
				script = "sudo sandboxd recover-quorum --rejoin --start"
			}
			target, _ := harness.SSHTarget(n)
			if out, err := harness.SSHRun(t, target, script); err != nil {
				t.Errorf("RESTORE FAILED on %s (%s): %v\n%s", n.Name, script, err, out)
			}
			harness.MarkNodeUp(n.PublicIP)
		}
	})
	for _, n := range lost {
		harness.MarkNodeDown(n.PublicIP)
		opsSSH(t, n, "sudo systemctl stop sandboxd")
	}
	deadline := time.Now().Add(2 * time.Minute)
	for nodeLocalLeader(t, survivorTarget) != "" {
		if time.Now().After(deadline) {
			t.Fatalf("with two of three servers stopped, %s still reports a leader after 2m", survivor.Name)
		}
		time.Sleep(3 * time.Second)
	}
	wctx, wcancel := context.WithTimeout(context.Background(), 45*time.Second)
	if sb, err := c.SDK().Create(wctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-noquorum", Image: harness.DefaultImage}); err == nil {
		wcancel()
		_ = c.SDK().Destroy(context.Background(), sb.ID)
		t.Fatal("a create succeeded with no quorum")
	}
	wcancel()
	t.Logf("UC-682: quorum lost: no leader on %s and a create is refused", survivor.Name)

	// Recover on the survivor.
	harness.MarkNodeDown(survivor.PublicIP)
	out := opsSSH(t, survivor, "sudo systemctl stop sandboxd && sudo sandboxd recover-quorum --start --timeout 4m")
	harness.MarkNodeUp(survivor.PublicIP)
	recovered = true
	for _, want := range []string{"backed up /var/lib/sandboxd/state.db", "is the only voter", "recovery applied"} {
		if !strings.Contains(out, want) {
			t.Fatalf("recover-quorum output lacks %q:\n%s", want, out)
		}
	}
	deadline = time.Now().Add(2 * time.Minute)
	for nodeLocalLeader(t, survivorTarget) != survivorID {
		if time.Now().After(deadline) {
			t.Fatalf("%s does not lead after recover-quorum (its leader: %q)", survivor.Name, nodeLocalLeader(t, survivorTarget))
		}
		time.Sleep(3 * time.Second)
	}
	writes := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-after"})
	waitRunning(t, writes)
	if err := keep.Refresh(context.Background()); err != nil {
		t.Fatalf("the sandbox from before the loss: %v", err)
	}
	execOK(t, keep, "true")
	t.Logf("UC-682: %s leads alone and serves writes (%s created)", survivor.Name, writes.ID)

	// Bring the lost servers back, one at a time.
	for _, n := range lost {
		target, _ := harness.SSHTarget(n)
		out := opsSSH(t, n, "sudo sandboxd recover-quorum --rejoin --start --timeout 3m")
		rejoined[n.Name] = true
		harness.MarkNodeUp(n.PublicIP)
		if !strings.Contains(out, "moved aside: /var/lib/sandboxd/raft -> /var/lib/sandboxd/raft.pre-rejoin.") {
			t.Fatalf("%s: --rejoin output:\n%s", n.Name, out)
		}
		id := nodeID(n)
		deadline := time.Now().Add(4 * time.Minute)
		for {
			voter := false
			for _, m := range listNodeViews(t, c) {
				if m.NodeID == id && m.Alive && m.Voter {
					voter = true
				}
			}
			if voter && nodeLocalLeader(t, target) == survivorID {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not rejoin as a voter following %s within 4m", n.Name, survivorID)
			}
			time.Sleep(5 * time.Second)
		}
		t.Logf("UC-682: %s rejoined as a voter", n.Name)
	}
	voters, leaders := 0, 0
	for _, m := range listNodeViews(t, c) {
		if m.Voter {
			voters++
		}
		if m.Leader {
			leaders++
		}
	}
	if voters != 3 || leaders != 1 {
		t.Fatalf("after the rejoins: %d voters and %d leaders, want 3 and 1", voters, leaders)
	}
	last := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-last"})
	waitRunning(t, last)
	t.Logf("UC-682 PASS: quorum recovered on %s, both lost servers rejoined, 3 voters and 1 leader, writes work", survivor.Name)
}
