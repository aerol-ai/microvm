//go:build integration

package suite

// UC-469. Restarts sandboxd on one node, so it sorts after the rest of the
// suite.

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-469 — an external-storage mount keeps serving across a sandboxd restart
// (plans/kubectl-style-cluster-ops.md §6.3 step 4 and §6.4, Codex eng
// finding 3; the Phase 3a live gate for mounts).
//
// The mount helper (mount-s3 for an S3-backed platform volume) used to run
// in sandboxd's cgroup, and the unit's KillMode=control-group killed it with
// every restart: the running container's /vol turned into a dead FUSE mount
// ("Transport endpoint is not connected") until the sandbox was re-created.
// Now the helper runs in the aerolvm-mounts cgroup and the restarted
// sandboxd adopts it. So, on the node that runs the sandbox: write through
// the mount, restart sandboxd, then read the old file and write a new one
// through the same mount of the same sandbox, never re-created. The helper
// must be the same process before and after (adopted, not mounted again)
// and, on a cgroup v2 host, sit in aerolvm-mounts. A second sandbox on the
// same volume reads the new file, so the write reached the backing store.
//
// With an NFS-backed volume there is no helper (a kernel mount survives a
// restart on its own); the read and write halves still run.
func TestMountHelpersServeAcrossSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-469")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this restarts sandboxd on the sandbox's node")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	vol := volumeName(t)

	sb, node := mountRestartSandbox(t, c, targets, vol)
	if sc.Has(harness.CapCluster) {
		// mountRestartSandbox already placed it off the seed; this is the
		// guard restart_node_test.go looks for.
		requireNonSeedVictim(t, node)
	}
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Skipf("no SSH address for %s", node.Name)
	}

	execOK(t, sb, "echo uc469-before > /vol/uc469-before.txt")
	if out := execOK(t, sb, "cat /vol/uc469-before.txt"); !strings.Contains(out, "uc469-before") {
		t.Fatalf("read-back before the restart = %q", out)
	}
	before := mountHelperOn(t, target, sb.ID)
	t.Logf("before the restart on %s: helper pid %q, cgroup %q, cgroup v2 %q", node.Name, before["pid"], before["cgroup"], before["v2"])
	if before["pid"] != "" && before["v2"] == "yes" && !strings.Contains(before["cgroup"], "0::/aerolvm-mounts") {
		t.Fatalf("the mount helper (pid %s) runs in %q, not the aerolvm-mounts cgroup: KillMode=control-group will kill it with sandboxd", before["pid"], before["cgroup"])
	}

	if out, err := harness.SSHRun(t, target, "sudo systemctl restart sandboxd"); err != nil {
		t.Fatalf("restart sandboxd on %s: %v\n%s", node.Name, err, out)
	}
	// A restart that left the unit down is put back for the next case.
	t.Cleanup(func() { restoreNodeDaemon(t, node, target) })
	if err := waitNodeRejoined(t, node); err != nil {
		t.Fatalf("%s did not come back after the restart: %v", node.Name, err)
	}

	// The same sandbox, not re-created: the old file reads back and a new
	// write lands through the same mount.
	readBackWithRetry(t, sb, "/vol/uc469-before.txt", "uc469-before")
	execOK(t, sb, "echo uc469-after > /vol/uc469-after.txt")
	readBackWithRetry(t, sb, "/vol/uc469-after.txt", "uc469-after")

	after := mountHelperOn(t, target, sb.ID)
	t.Logf("after the restart on %s: helper pid %q, cgroup %q", node.Name, after["pid"], after["cgroup"])
	if before["pid"] != "" && after["pid"] != before["pid"] {
		t.Fatalf("the mount helper changed across the restart (pid %s -> %q): the mount was set up again instead of adopted, and the running container still holds the old one", before["pid"], after["pid"])
	}

	// The write reached the backing store, not only the helper's cache.
	second := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	})
	waitRunning(t, second)
	readBackWithRetry(t, second, "/vol/uc469-after.txt", "uc469-after")
}

// mountRestartSandbox creates a sandbox with platform volume vol at /vol on
// a node this case may restart. On a cluster that is any node but the seed
// (restarting the seed takes the cluster's rendezvous down, see
// restart_node_test.go), so a placement on the seed is destroyed and tried
// again. On a single node it is the only node.
func mountRestartSandbox(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, vol string) (*microvm.Sandbox, harness.IntegrationNode) {
	t.Helper()
	opts := sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
	}
	for range 6 {
		sb := c.NewSandbox(t, opts)
		waitRunning(t, sb)
		if !sc.Has(harness.CapCluster) || len(targets.Nodes) == 1 {
			return sb, targets.Nodes[0]
		}
		node := nodeForOwner(t, targets, resolveOwnerNode(t, c, sb.ID))
		if !node.Seed {
			return sb, node
		}
		destroyBest(c, sb.ID)
		opts.Name = harness.UniqueName(sc, t)
	}
	t.Skip("six placements in a row landed on the seed; this case does not restart the seed")
	return nil, harness.IntegrationNode{}
}

// mountHelperOn reads, on the node, the helper serving mount 0 of sandboxID:
// its pid (empty for a kernel mount), its cgroup line, and whether the host
// runs cgroup v2. Every helper's last argument is its mount path,
// <mounts root>/<sandbox id>/0; the oldest match is the helper itself and
// not a child it has just forked.
func mountHelperOn(t *testing.T, target, sandboxID string) map[string]string {
	t.Helper()
	script := `pid=$(pgrep -o -f -- '/` + sandboxID + `/0$' || true)
echo "pid=$pid"
if [ -n "$pid" ]; then echo "cgroup=$(tr '\n' ' ' < /proc/$pid/cgroup)"; fi
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then echo v2=yes; else echo v2=no; fi`
	// On stdin, so neither the quoting nor pgrep's own pattern lands in the
	// command line of the shell that runs it.
	out, err := harness.SSHRunStdin(t, target, "sudo sh -s", script)
	if err != nil {
		t.Fatalf("read the mount helper of %s: %v\n%s", sandboxID, err, out)
	}
	return parseKV(out)
}
