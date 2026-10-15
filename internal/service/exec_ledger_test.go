package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestExecOutcomeEncodeDecode(t *testing.T) {
	o := ExecOutcome{Exit: 7, StdoutLen: 12, StderrLen: 3}
	got, ok := DecodeExecOutcome(o.Encode())
	if !ok || got != o {
		t.Fatalf("round trip = %+v ok=%v, want %+v", got, ok, o)
	}
	if lost, ok := DecodeExecOutcome(ExecOutcome{Lost: true}.Encode()); !ok || !lost.Lost {
		t.Fatalf("lost round trip = %+v ok=%v", lost, ok)
	}
	// An empty or corrupt target is not an outcome.
	if _, ok := DecodeExecOutcome(""); ok {
		t.Fatal("empty target decoded as an outcome")
	}
	if _, ok := DecodeExecOutcome("not json"); ok {
		t.Fatal("corrupt target decoded as an outcome")
	}
}

func TestExecLedgerClaimSettleAndRelease(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	ctx := context.Background()
	fp := "sb-exec/rlx-abc"

	// First claim acquires; a second claim of the still-pending obligation
	// does not (the row never lapses on a timer).
	if _, acquired, err := svc.ClaimExecLedger(ctx, fp, false); err != nil || !acquired {
		t.Fatalf("first claim acquired=%v err=%v, want true/nil", acquired, err)
	}
	if _, acquired, err := svc.ClaimExecLedger(ctx, fp, false); err != nil || acquired {
		t.Fatalf("second claim acquired=%v err=%v, want false/nil", acquired, err)
	}

	// Writing the outcome before settling leaves the row pending → owed.
	if err := svc.SetExecLedgerTarget(ctx, fp, ExecOutcome{Exit: 2, StdoutLen: 5}.Encode()); err != nil {
		t.Fatalf("SetExecLedgerTarget: %v", err)
	}
	outcome, owed, ok := svc.ExecLedgerOutcome(ctx, fp)
	if !ok || !owed || outcome.Exit != 2 || outcome.StdoutLen != 5 {
		t.Fatalf("pre-complete outcome=%+v owed=%v ok=%v, want exit2/len5/owed", outcome, owed, ok)
	}

	// Completing opens the replay window and clears the owed flag.
	if err := svc.CompleteExecLedger(ctx, fp, outcome.Encode()); err != nil {
		t.Fatalf("CompleteExecLedger: %v", err)
	}
	outcome, owed, ok = svc.ExecLedgerOutcome(ctx, fp)
	if !ok || owed || outcome.Exit != 2 {
		t.Fatalf("post-complete outcome=%+v owed=%v ok=%v, want exit2/not-owed", outcome, owed, ok)
	}

	// A named claim uses the lapsing lock; the row reads back as a plain
	// idempotency row (no outcome yet), and ExecLedgerOutcome on an unknown
	// fingerprint reports not-ok rather than erroring.
	if _, acquired, err := svc.ClaimExecLedger(ctx, "sb-exec/rln-xyz", true); err != nil || !acquired {
		t.Fatalf("named claim acquired=%v err=%v, want true/nil", acquired, err)
	}
	if _, _, ok := svc.ExecLedgerOutcome(ctx, "sb-exec/rlx-missing"); ok {
		t.Fatal("ExecLedgerOutcome on a missing row reported ok")
	}

	// Release deletes the row entirely.
	released := "sb-exec/rlx-def"
	if _, _, err := svc.ClaimExecLedger(ctx, released, false); err != nil {
		t.Fatalf("claim released row: %v", err)
	}
	if err := svc.ReleaseExecLedger(ctx, released); err != nil {
		t.Fatalf("ReleaseExecLedger: %v", err)
	}
	if _, err := svc.GetExecLedger(ctx, released); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetExecLedger after release err=%v, want ErrNotFound", err)
	}
}

func TestExecLedgerListPending(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	ctx := context.Background()

	for _, fp := range []string{"sb-x/rlx-1", "sb-x/rlx-2", "sb-x/rlx-3"} {
		if _, _, err := svc.ClaimExecLedger(ctx, fp, false); err != nil {
			t.Fatalf("claim %s: %v", fp, err)
		}
	}
	// Settle one; it must drop out of the pending page.
	if err := svc.CompleteExecLedger(ctx, "sb-x/rlx-2", ExecOutcome{}.Encode()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	rows, err := svc.ListPendingExecLedger(ctx, "", 100)
	if err != nil {
		t.Fatalf("ListPendingExecLedger: %v", err)
	}
	pending := map[string]bool{}
	for _, r := range rows {
		if r.State == models.RequestStatePending {
			pending[r.Fingerprint] = true
		}
	}
	if !pending["sb-x/rlx-1"] || !pending["sb-x/rlx-3"] || pending["sb-x/rlx-2"] {
		t.Fatalf("pending set = %v, want rlx-1 and rlx-3 only", pending)
	}
}
