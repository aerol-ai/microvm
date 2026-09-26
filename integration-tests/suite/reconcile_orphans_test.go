//go:build integration

package suite

// Group M, UC-167 — the isolate orphan sweep.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-167 — reconcile reclaims a leaked workerd group.
//
// The product fix landed 2026-09-19: service.go aggregates isolate.ListManaged
// and calls removeOrphans for it. This is the live confirmation.
//
// KNOWN LIMIT, and why this case does NOT test restart survival: isolate's
// ListManaged reads the driver's IN-MEMORY map, so the sweep only reclaims
// groups leaked within one daemon lifetime. The crash/restart case needs a
// host-backed enumeration seam that has not landed (TODOS.md). Writing this
// UC to assert restart survival would make it a permanently red row for a
// gap that is tracked elsewhere.
func TestIsolateOrphanSweepReclaimsLeakedGroups(t *testing.T) {
	harness.Require(t, sc, "UC-167")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	ref := uploadBundle(t, c, "itest-uc167",
		`export default { async fetch() { return new Response("uc167"); } };`)
	sb := newIsolateSandbox(t, c, ref, "itest-uc167", sdktypes.CreateSandboxOptions{})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node")
		}
	}
	target, _ := harness.SSHTarget(node)

	before := countWorkerd(t, target)
	if before == 0 {
		t.Skipf("no workerd process on %s while an isolate sandbox is running; this node is not serving it", node.Name)
	}

	// Leak the group: remove the sandbox row out from under the driver, so
	// the daemon's in-memory group outlives anything that references it.
	// Deleting the row rather than the process is the point — a killed
	// process is not an orphan, it is a dead process.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := harness.SSHRun(t, target, deleteSandboxRowScript(sb.ID))
	if err != nil || strings.Contains(out, "NOROW") {
		t.Skipf("could not orphan the isolate group on %s (%v): %s", node.Name, err, strings.TrimSpace(out))
	}

	if err := c.PostJSON(ctx, "/v1/admin/reconcile", nil, nil); err != nil {
		t.Fatalf("POST /v1/admin/reconcile: %v", err)
	}

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if countWorkerd(t, target) < before {
			t.Logf("UC-167 PASS: reconcile reclaimed the orphaned workerd group (%d -> %d)", before, countWorkerd(t, target))
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("reconcile left %d workerd process(es) on %s after the sandbox row was removed: the group leaked, and every leaked group holds a tenant's memory and PIDs for the daemon's lifetime",
		countWorkerd(t, target), node.Name)
}

// countWorkerd counts workerd processes on a node.
func countWorkerd(t *testing.T, target string) int {
	t.Helper()
	// -C matches the executable name, so this cannot count the ssh command
	// line that is asking the question — a mistake that has produced a false
	// positive in this repo before.
	out, _ := harness.SSHRun(t, target, `ps -o pid= -C workerd 2>/dev/null | wc -l`)
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0
	}
	return n
}
