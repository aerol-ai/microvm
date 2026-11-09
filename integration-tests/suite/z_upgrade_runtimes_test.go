//go:build integration

package suite

// UC-703: a node upgrade through `aerolvm upgrade apply --from` keeps WASM
// and V8-isolate sandboxes running, with their state, the way UC-661 keeps
// a container running. It reuses UC-660's single-node setup (cluster mode
// off, build B from build.sh variant) and sorts after z_upgrade_cli_test.go
// so it can reuse a B that UC-660 built in the same run.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-703 — aerolvm upgrade plan says WASM and isolate sandboxes keep
// running, and aerolvm upgrade apply <B> --from --wait keeps them running:
// after the upgrade each answers exec with its state moved on by one (a
// WASM counter file, an isolate's in-memory counter), and the node runs B.
func TestUpgradeKeepsWasmAndIsolateRunning(t *testing.T) {
	harness.Require(t, sc, "UC-703")
	requireUpgradeDisruptive(t)
	target := t14Node(t)
	buildID := os.Getenv("AEROL_BUILD_ID")
	if os.Getenv("AEROL_BUILD_MODE") != "local" || buildID == "" {
		t.Skip("needs the node to run this tree's local build (run.sh without --released/--version)")
	}
	c := client(t)
	madeStandalone := upgradeLive.standaloneTarget == ""
	makeStandalone(t, c)
	if madeStandalone && upgradeLive.standaloneTarget != "" {
		t.Cleanup(func() {
			if out, err := harness.SSHRun(t, upgradeLive.standaloneTarget, clusterAgain); err != nil {
				t.Errorf("RESTORE: turn cluster mode back on: %v\n%s", err, out)
			}
			upgradeLive.standaloneTarget = ""
		})
	}
	versionA := runningVersion(t, c)
	if versionA != "itest-"+buildID {
		t.Skipf("the node runs %q, not this tree's build A itest-%s (an earlier case left it on another build)", versionA, buildID)
	}
	dirB, versionB := upgradeLive.dirB, "itest-"+buildID+"-b"
	// AEROL_UPGRADE_B_DIR reuses a B already built from the node's tree
	// (.build/<id>/variant-b), for a rerun on a kept stack whose own tree
	// has moved on by test-only commits. It must still name the node's
	// build id, so B is always the node's code under another version.
	if reuse := os.Getenv("AEROL_UPGRADE_B_DIR"); dirB == "" && reuse != "" {
		if filepath.Base(filepath.Dir(reuse)) != buildID {
			t.Fatalf("AEROL_UPGRADE_B_DIR %s is not a variant of the node's build %s", reuse, buildID)
		}
		dirB = reuse
	}
	if dirB == "" {
		cmd := exec.Command("bash", "../lib/build.sh", "variant", "b")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("build.sh variant b: %v\n%s", err, stderr.String())
		}
		dirB = strings.TrimSpace(string(out))
		if filepath.Base(filepath.Dir(dirB)) != buildID {
			t.Fatalf("variant built from tree %s, but the node runs %s", filepath.Base(filepath.Dir(dirB)), buildID)
		}
	}

	wasmDefault := newWasmCounterSubject(t, c, "ephemeral (default)", sdktypes.CreateSandboxOptions{})
	wasmPassive := newWasmCounterSubject(t, c, "passivatable", sdktypes.CreateSandboxOptions{Durability: sdktypes.DurabilityPassivatable})
	ref := uploadBundle(t, c, "itest-uc703-counter", isolateCounter)
	isolate := newIsolateCounterSubject(t, c, ref, "jail on (default)", "itest-uc703")
	subjects := []*t14Subject{wasmDefault, wasmPassive, isolate}

	plan := aerolvmLong(t, "upgrade", "plan", versionB, "--from", dirB, "--allow-unversioned")
	if plan.code != 0 || !strings.Contains(plan.stdout, "WASM sandboxes") || !strings.Contains(plan.stdout, "keep running with their /work files") ||
		!strings.Contains(plan.stdout, "keep running with their in-memory state") || strings.Contains(plan.stdout, "are LOST") {
		t.Fatalf("plan = %d\n%s", plan.code, plan.stdout)
	}

	// The upload alone can take longer than the isolate idle TTL (5m; 628 s
	// on one run), and the old sandboxd runs all through it: left alone, its
	// idle reaper stops the isolate's group before the upgrade even starts,
	// and the isolate comes back fresh. That is scale-to-zero working, not
	// a takeover failure, so the isolate is kept in use with pings that do
	// not count.
	began := time.Now()
	t14MeasureWith(t, target, subjects, func() {
		stop := keepIsolateInUse(t, isolate.sb, time.Minute)
		// The upload runs from a node inside AWS (client_in_vpc_test.go).
		r := aerolvmOnNode(t, "upgrade", "apply", versionB, "--from", dirB, "--allow-unversioned", "--wait")
		stop()
		if r.code != 0 {
			t.Fatalf("apply = %d", r.code)
		}
	})
	if got := runningVersion(t, c); got != versionB {
		t.Fatalf("/health reports %q after the upgrade, want %s", got, versionB)
	}
	t14AssertKept(t, wasmDefault, "4", "marker: marker-"+wasmDefault.sb.ID)
	t14AssertKept(t, wasmPassive, "4", "marker: marker-"+wasmPassive.sb.ID)
	if reaped := isolateReapedSince(t, target, "itest-uc703", began); reaped != "" {
		t.Errorf("the idle reaper stopped the isolate's group during the upgrade, so it came back fresh: the keep-alive did not keep it in use\n%s", reaped)
	}
	t14AssertKept(t, isolate, "4", "in-memory counter 4")

	// Back to A, as UC-664 does, so later cases find the build they expect.
	if r := aerolvmLong(t, "upgrade", "rollback", "--wait"); r.code != 0 {
		t.Errorf("rollback to A = %d", r.code)
	}
}
