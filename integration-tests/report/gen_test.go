package main

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Offline golden test of the classification brain. The report is the whole
// product of the harness, so its pass/fail/skip/pending/inconclusive logic must
// be verified without AWS.

func reg() []harness.UseCase {
	return []harness.UseCase{
		{ID: "UC-10", Title: "auth", Implemented: true},
		{ID: "UC-11", Title: "create", Implemented: true},
		{ID: "UC-30", Title: "reach", Implemented: true},
		{ID: "UC-24", Title: "firecracker", Implemented: false}, // pending
	}
}

func TestClassifyMixed(t *testing.T) {
	events := []testEvent{
		{Action: "run", Test: "TestAuth/UC-10"},
		{Action: "pass", Test: "TestAuth/UC-10"},
		{Action: "fail", Test: "TestCreate/UC-11"},
		{Action: "skip", Test: "TestReach/UC-30"},
		// UC-24 not implemented -> pending; no event for it.
	}
	got := classify(events, reg(), false)
	want := map[string]Status{
		"UC-10": StatusPass,
		"UC-11": StatusFail,
		"UC-30": StatusSkip,
		"UC-24": StatusPending,
	}
	for _, r := range got {
		if want[r.ID] != r.Status {
			t.Errorf("%s = %s, want %s", r.ID, r.Status, want[r.ID])
		}
	}
}

func TestClassifyFlatNamedViaMarker(t *testing.T) {
	// The real suite uses flat test names (TestSnapshotCreate), not TestX/UC-NN
	// subtests, and surfaces the UC id only through the `ucid=UC-NN` marker that
	// harness.Require logs. The join must work off that marker; without it every
	// implemented UC would (wrongly) read as missing.
	events := []testEvent{
		{Action: "run", Test: "TestAuth"},
		{Action: "output", Test: "TestAuth", Output: "    client.go:54: ucid=UC-10\n"},
		{Action: "pass", Test: "TestAuth"},
		{Action: "output", Test: "TestCreate", Output: "    client.go:54: ucid=UC-11\n"},
		{Action: "fail", Test: "TestCreate"},
		{Action: "output", Test: "TestReach", Output: "    client.go:54: ucid=UC-30\n"},
		{Action: "skip", Test: "TestReach"},
	}
	got := classify(events, reg(), false)
	want := map[string]Status{
		"UC-10": StatusPass,
		"UC-11": StatusFail,
		"UC-30": StatusSkip,
		"UC-24": StatusPending,
	}
	for _, r := range got {
		if want[r.ID] != r.Status {
			t.Errorf("%s = %s, want %s", r.ID, r.Status, want[r.ID])
		}
	}
}

func TestClassifyParentSkipCoversSubUCs(t *testing.T) {
	// A parent test gates on UC-11 and also covers UC-30 (a subtest's UC); when
	// the parent is capability-skipped, the subtest never runs. Because the
	// parent's Require logged a marker for BOTH, UC-30 must read as skip — not
	// missing — and inherit the skip reason.
	events := []testEvent{
		{Action: "output", Test: "TestFanout", Output: "    client.go:54: ucid=UC-11\n"},
		{Action: "output", Test: "TestFanout", Output: "    client.go:54: ucid=UC-30\n"},
		{Action: "output", Test: "TestFanout", Output: `    skip.go:53: scenario "local-mode" lacks capabilities [domain] for UC-11` + "\n"},
		{Action: "skip", Test: "TestFanout"},
	}
	got := classify(events, []harness.UseCase{
		{ID: "UC-11", Implemented: true},
		{ID: "UC-30", Implemented: true},
	}, false)
	for _, r := range got {
		if r.Status != StatusSkip {
			t.Errorf("%s = %s, want skip", r.ID, r.Status)
		}
		if !strings.Contains(r.Reason, "lacks capabilities [domain]") {
			t.Errorf("%s reason = %q, want capability-skip message", r.ID, r.Reason)
		}
	}
}

func TestClassifyFailReasonCaptured(t *testing.T) {
	events := []testEvent{
		{Action: "output", Test: "TestSnap", Output: "    client.go:54: ucid=UC-20\n"},
		{Action: "output", Test: "TestSnap", Output: "    lifecycle_more_test.go:185: create snapshot: 400 must be lowercase\n"},
		{Action: "fail", Test: "TestSnap"},
	}
	got := classify(events, []harness.UseCase{{ID: "UC-20", Implemented: true}}, false)
	if got[0].Status != StatusFail {
		t.Fatalf("UC-20 = %s, want fail", got[0].Status)
	}
	if !strings.Contains(got[0].Reason, "must be lowercase") {
		t.Fatalf("UC-20 reason = %q, want the assertion text", got[0].Reason)
	}
}

func TestClassifyMissingImplementedIsNotSilentGreen(t *testing.T) {
	// UC-10 is implemented but produced NO event (e.g. the test binary crashed
	// before reaching it). It must surface as missing, never as a silent pass.
	got := classify(nil, reg(), false)
	for _, r := range got {
		if r.ID == "UC-10" && r.Status != StatusMissing {
			t.Fatalf("UC-10 with no event = %s, want missing", r.Status)
		}
		if r.ID == "UC-24" && r.Status != StatusPending {
			t.Fatalf("UC-24 (unimplemented) = %s, want pending", r.Status)
		}
	}
}

func TestClassifyForceInconclusive(t *testing.T) {
	events := []testEvent{{Action: "pass", Test: "TestAuth/UC-10"}}
	got := classify(events, reg(), true)
	for _, r := range got {
		switch r.ID {
		case "UC-24":
			if r.Status != StatusPending { // unimplemented stays pending even when inconclusive
				t.Errorf("UC-24 = %s, want pending", r.Status)
			}
		default:
			if r.Status != StatusInconclusive {
				t.Errorf("%s = %s, want inconclusive", r.ID, r.Status)
			}
		}
	}
}

func TestFailWinsOverPass(t *testing.T) {
	// A parent test passes but a subtest fails for the same UC id; fail must win.
	events := []testEvent{
		{Action: "fail", Test: "TestX/UC-11/case-b"},
		{Action: "pass", Test: "TestX/UC-11"},
	}
	got := classify(events, []harness.UseCase{{ID: "UC-11", Implemented: true}}, false)
	if got[0].Status != StatusFail {
		t.Fatalf("UC-11 = %s, want fail (fail must win)", got[0].Status)
	}
}

func TestSummarize(t *testing.T) {
	rs := []Result{
		{Status: StatusPass}, {Status: StatusPass}, {Status: StatusFail},
		{Status: StatusSkip}, {Status: StatusPending}, {Status: StatusInconclusive},
	}
	s := summarize(rs)
	if s.Pass != 2 || s.Fail != 1 || s.Skip != 1 || s.Pending != 1 || s.Inconclusive != 1 || s.Total != 6 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestClassifyAttachesInvariantVerdicts(t *testing.T) {
	// The chaos cases log one invariant marker per invariant from a cleanup,
	// before their terminal event. The verdicts must land on the row (pass
	// rows included: "held over 61 samples" is the evidence the fault was
	// injected) and must not be mistaken for a fail reason.
	events := []testEvent{
		{Action: "output", Test: "TestClusterChaosPartition", Output: "    client.go:54: ucid=UC-11\n"},
		{Action: "output", Test: "TestClusterChaosPartition", Output: "    z_cluster_chaos_test.go:99: I7 violated: cut-off ingress served the old copy\n"},
		{Action: "output", Test: "TestClusterChaosPartition", Output: "    invariants.go:171: invariant=I1 held: max 1 running copy over 61 samples\n"},
		{Action: "output", Test: "TestClusterChaosPartition", Output: "    invariants.go:171: invariant=I7 violated: cut-off ingress served the old copy\n"},
		{Action: "fail", Test: "TestClusterChaosPartition"},
		{Action: "output", Test: "TestClusterChaosRestart", Output: "    client.go:54: ucid=UC-10\n"},
		{Action: "output", Test: "TestClusterChaosRestart", Output: "    invariants.go:171: invariant=I6 held: converged in 41s\n"},
		{Action: "pass", Test: "TestClusterChaosRestart"},
	}
	got := classify(events, reg(), false)
	by := map[string]Result{}
	for _, r := range got {
		by[r.ID] = r
	}
	fail := by["UC-11"]
	if fail.Status != StatusFail || len(fail.Invariants) != 2 {
		t.Fatalf("UC-11 = %+v, want fail with two invariant verdicts", fail)
	}
	if fail.Invariants[0] != (harness.InvariantResult{ID: "I1", Result: "held", Detail: "max 1 running copy over 61 samples"}) {
		t.Errorf("UC-11 I1 = %+v", fail.Invariants[0])
	}
	if strings.Contains(fail.Reason, "invariant=") {
		t.Errorf("an invariant marker leaked into the fail reason: %q", fail.Reason)
	}
	if !strings.Contains(fail.Reason, "served the old copy") {
		t.Errorf("the t.Errorf line must still be the reason: %q", fail.Reason)
	}
	pass := by["UC-10"]
	if pass.Status != StatusPass || len(pass.Invariants) != 1 || pass.Invariants[0].ID != "I6" {
		t.Fatalf("UC-10 = %+v, want pass carrying I6", pass)
	}
	if cell := detailCell(pass); cell != "I6 held" {
		t.Errorf("pass detail = %q, want the verdict summary", cell)
	}
	if cell := detailCell(fail); !strings.HasPrefix(cell, "I1 held · I7 violated — ") {
		t.Errorf("fail detail = %q, want the verdicts before the reason", cell)
	}
	if md := renderMarkdown(Report{Scenario: "cluster-chaos", Results: got}); !strings.Contains(md, "| ✅ pass | I6 held |") {
		t.Errorf("markdown does not show the pass row's verdict:\n%s", md)
	}
}

func TestApplyFocusDowngradesOnlyUnfocusedMissingRows(t *testing.T) {
	focusReg := []harness.UseCase{
		{ID: "UC-10", Implemented: true},
		{ID: "UC-470", Requires: []harness.Capability{harness.CapCluster, harness.CapClusterChaos}, Implemented: true},
		{ID: "UC-471", Requires: []harness.Capability{harness.CapCluster, harness.CapClusterChaos}, Implemented: true},
		{ID: "UC-24", Implemented: false},
	}
	events := []testEvent{
		{Action: "output", Test: "TestClusterChaosA", Output: "    client.go:54: ucid=UC-470\n"},
		{Action: "pass", Test: "TestClusterChaosA"},
		// UC-471's test crashed before reporting: it must stay missing.
	}
	got := applyFocus(classify(events, focusReg, false), focusReg, harness.CapClusterChaos)
	want := map[string]Status{"UC-10": StatusSkip, "UC-470": StatusPass, "UC-471": StatusMissing, "UC-24": StatusPending}
	for _, r := range got {
		if r.Status != want[r.ID] {
			t.Errorf("%s = %s, want %s", r.ID, r.Status, want[r.ID])
		}
		if r.ID == "UC-10" && !strings.Contains(r.Reason, "focused scenario") {
			t.Errorf("UC-10 reason = %q, want the focus explanation", r.Reason)
		}
	}
	if s := summarize(got); s.Missing != 1 || s.Fail != 0 {
		t.Errorf("summary = %+v: the gate must stay red for the focused case that never reported", s)
	}
}

func TestValidateFocusRefusesACapabilityThatWouldSkipEverything(t *testing.T) {
	if err := validateFocus(harness.CapClusterChaos, harness.Registry); err != nil {
		t.Fatalf("cluster-chaos is a real focus: %v", err)
	}
	if err := validateFocus("clutser-chaos", harness.Registry); err == nil {
		t.Error("a typo'd focus capability must be refused: it would turn every missing row, the focused ones included, into a skip")
	}
	unused := []harness.UseCase{{ID: "UC-10", Requires: []harness.Capability{harness.CapDocker}, Implemented: true}}
	if err := validateFocus(harness.CapClusterChaos, unused); err == nil {
		t.Error("a focus no use case requires must be refused")
	}
}
