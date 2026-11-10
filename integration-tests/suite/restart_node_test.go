//go:build integration

package suite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// splitGoFuncs returns each top-level func body in a source file, keyed by
// its signature line, with comment lines dropped.
//
// A body runs to the next "\nfunc ", so it also holds the doc comment of the
// function after it. Keeping comments let prose about a helper count as code:
// chaosStopVoters was reported as taking sandboxd down because the comment
// above chaosKillVoters names KillSandboxdScript.
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
		var code []string
		for _, line := range strings.Split(p, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				code = append(code, line)
			}
		}
		out["func "+p[:nl]] = strings.Join(code, "\n")
	}
	return out
}

// takesSandboxdDown reports whether a function body stops, restarts or
// SIGKILLs sandboxd. KillSandboxdScript is listed because the two guards
// below once keyed only on the stop and restart strings, so the SIGKILL
// paths (UC-480, UC-481) were never inspected at all.
func takesSandboxdDown(body string) bool {
	return strings.Contains(body, "systemctl stop sandboxd") ||
		strings.Contains(body, "systemctl restart sandboxd") ||
		strings.Contains(body, "KillSandboxdScript") ||
		strings.Contains(body, "KillNodeDaemon")
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
	seen := map[string]bool{}
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
			stops := takesSandboxdDown(body)
			if !stops {
				continue
			}
			checked++
			if name := funcName(sig); neverRestoredCases[name] {
				seen[name] = true
				continue
			}
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
	// A stale name would let a new function of that name through unread.
	for name := range neverRestoredCases {
		if !seen[name] {
			t.Errorf("neverRestoredCases names %s, which no longer takes a daemon down; drop it", name)
		}
	}
	t.Logf("checked %d functions that take a daemon down", checked)
}

// Cases whose subject is a node that must never come back. They take it
// out for the rest of the run on purpose, so there is no rejoin to wait for:
// waiting for one would fail the case for passing. Each one marks the node
// down in the harness (MarkNodeDown) and logs that the run goes on a node
// short. Named here rather than slipping through on a substring, like
// seedVictimCases below.
var neverRestoredCases = map[string]bool{
	"TestNodeDeleteWorkerAndItCannotRejoin": true, // UC-614, UC-615: a deleted worker is denied for good
}

// funcName is the name in a splitGoFuncs signature: "func Foo(t ...) {" is Foo.
func funcName(sig string) string {
	return strings.TrimSpace(strings.SplitN(strings.TrimPrefix(sig, "func "), "(", 2)[0])
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

// A disruptive case must choose its victim deliberately, never the seed.
//
// On a live 3-node run, stopping the seed broke far more than one member:
// the read under test answered 502 for its entire poll, the seed could not
// rejoin within four minutes ("no raft leader yet"), and the next case could
// not even create a sandbox. The cause, found later in the journals, was not
// the survivors — they elected a leader within 3s — but the restarted seed:
// it has no SB_CLUSTER_PEERS, came back as a gossip island, and after its
// eviction from Raft could never be re-admitted. That is fixed in the product
// (internal/cluster/gossip_peer_cache.go) and proven by UC-170.
//
// The guard stays. A case about secrets or audit that also happens to evict
// the seed is paying for a control-plane event it is not testing, and any
// red it produces reads as a bug in the wrong subsystem. UC-170 is the one
// cluster case whose subject IS the seed, so it is named here rather than
// slipping through on a substring. The single-node cases after it stop the
// only node there is: on a single-node scenario that node is the seed, and
// there is no cluster and no rendezvous to lose.
var seedVictimCases = map[string]bool{
	"TestSeedLossSurvivorsKeepALeaderAndTheSeedRejoins": true, // UC-170
	"TestOpsBackupRestoreRoundTrip":                     true, // UC-680, single-node only (opsSingleNode)
	"t14Disrupt":                                        true, // T14, UC-677/678/702/703, single-node only (t14Node)
}

func TestDisruptiveCasesChooseANonSeedVictim(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		switch f {
		case "restart_node_test.go", "secrets_support_test.go":
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for sig, body := range splitGoFuncs(string(raw)) {
			stops := takesSandboxdDown(body)
			if !stops {
				continue
			}
			checked++
			if seedVictimCases[funcName(sig)] {
				continue
			}
			// Any of these is a deliberate choice: the pickers exclude the
			// seed themselves, and an explicit .Seed test is the hand-rolled
			// equivalent. pickTamperVictim falls back to the seed only on a
			// scenario without the cluster capability, where the seed is the
			// only node and there is no rendezvous to lose; the witness and
			// tamper gates exist to be proven on exactly that box.
			if !strings.Contains(body, "PickRestartableNode") &&
				!strings.Contains(body, "pickNonSeedNode") &&
				!strings.Contains(body, "pickTamperVictim") &&
				!strings.Contains(body, "requireNonSeedVictim") &&
				!strings.Contains(body, ".Seed") {
				t.Errorf("%s: %s takes a daemon down without excluding the seed; stopping the seed takes the whole cluster down, and every later case then fails for a reason that has nothing to do with what it tests",
					f, strings.TrimSuffix(sig, " {"))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no function was inspected; this guard would have passed having checked nothing")
	}
}
