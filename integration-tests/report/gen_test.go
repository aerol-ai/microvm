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
