//go:build integration

package suite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// splitGoFuncs returns each top-level func body in a source file, keyed by
// its signature line.
//
// File granularity is not enough here. z_audit_tamper_test.go holds both
// UC-134 (which stops a node) and UC-135 (which uses KillNodeDaemon), so a
// whole-file scan reports the file as safe while UC-134's own cleanup waits
// for nothing — which is exactly the regression that produced the cascade
// this guard exists to prevent.
func splitGoFuncs(src string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(src, "\nfunc ")
	for _, p := range parts[1:] {
		nl := strings.Index(p, "\n")
		if nl < 0 {
			continue
		}
		out["func "+p[:nl]] = p
	}
	return out
}

// Any case that takes sandboxd down must bring it back AND wait for the node
// to rejoin before it returns.
//
// A bare `systemctl start` in a t.Cleanup returns in milliseconds while the
// node takes tens of seconds to rejoin gossip and Raft, so the next case runs
// against a fleet one member short without knowing it. That is not
// hypothetical: UC-134 stopped a node, failed, and "restored" it; UC-135 then
// killed the owner, waited out its full 8-minute deadline for a reassignment
// the shrunken cluster could not make, and reported it as a failover bug.
// Blaming the product for the previous case's debris is the worst kind of
// red, because it is the kind someone acts on.
//
// The guard keys on TAKING THE DAEMON DOWN rather than on starting it, so a
// case that stops a node and never restores it at all is caught too.
func TestEveryCaseThatStopsSandboxdWaitsForTheRejoin(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		switch f {
		case "restart_node_test.go", "secrets_support_test.go":
			continue // the guard and the helper it enforces
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for sig, body := range splitGoFuncs(string(raw)) {
			stops := strings.Contains(body, "systemctl stop sandboxd") ||
				strings.Contains(body, "systemctl restart sandboxd") ||
				strings.Contains(body, "KillNodeDaemon")
			if !stops {
				continue
			}
			checked++
			// KillNodeDaemon restores and waits by contract;
			// TestTheRejoinWaitIsWiredEndToEnd holds it to that.
			if !strings.Contains(body, "restoreNodeDaemon") &&
				!strings.Contains(body, "waitNodeRejoined") &&
				!strings.Contains(body, "KillNodeDaemon") {
				t.Errorf("%s: %s takes sandboxd down but never waits for the node to rejoin; use restoreNodeDaemon so the next case is not handed a smaller fleet",
					f, strings.TrimSuffix(sig, " {"))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no function was inspected; this guard would have passed having checked nothing")
	}
	t.Logf("checked %d functions that take a daemon down", checked)
}

// The wait the guard above accepts on faith: KillNodeDaemon's restore must
// actually reach NodeRejoinCheck, and the suite must install it.
//
// A nil hook is the dangerous shape, because it fails silently — the restore
// returns immediately and looks exactly like a restore that waited. A live
// run once lost 79 cases to that gap.
func TestTheRejoinWaitIsWiredEndToEnd(t *testing.T) {
	harnessSrc, err := os.ReadFile(filepath.Join("harness", "secrets.go"))
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for sig, b := range splitGoFuncs(string(harnessSrc)) {
		if strings.HasPrefix(sig, "func KillNodeDaemon(") {
			body = b
			break
		}
	}
	if body == "" {
		t.Fatal("KillNodeDaemon is gone; this guard no longer checks anything")
	}
	// Both halves: the guard clause AND the call. Checking only that the
	// identifier appears somewhere let `if NodeRejoinCheck != nil` become
	// `if false` with the call still sitting there, unreachable.
	if !strings.Contains(body, "if NodeRejoinCheck != nil {") {
		t.Error("KillNodeDaemon no longer guards on NodeRejoinCheck being installed; if the wait has become unconditional that is fine, but it must not have become unreachable")
	}
	if !strings.Contains(body, "NodeRejoinCheck(t, node)") {
		t.Error("KillNodeDaemon never calls NodeRejoinCheck; every case that kills a node now hands the next one a smaller fleet")
	}

	mainSrc, err := os.ReadFile("main_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mainSrc), "harness.NodeRejoinCheck = ") {
		t.Error("the suite never installs harness.NodeRejoinCheck, so KillNodeDaemon's wait is a nil hook that returns instantly")
	}
}
