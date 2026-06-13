package main

import (
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
