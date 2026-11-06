package store

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestRecordProgramExit: the first report on a started sandbox stores the
// exit with status_reason program_exited and its code; a second report, or
// one for a sandbox that is not started, changes nothing. A stop keeps the
// exit (its destroy timer still counts); a start clears it.
func TestRecordProgramExit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-exit")
	sb.Status = models.SandboxStatusStarted
	sb.Lifecycle.DestroyAfterExitFor = 90 * time.Second
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(ctx, sb.ID)
	if got.Lifecycle.DestroyAfterExitFor != 90*time.Second || got.ProgramExitedAt != nil {
		t.Fatalf("fresh row: after=%s exited=%v", got.Lifecycle.DestroyAfterExitFor, got.ProgramExitedAt)
	}
	stale := *got

	first := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	if ok, err := st.RecordProgramExit(ctx, sb.ID, got.RunGeneration, first, 3); err != nil || !ok {
		t.Fatalf("first report: %v %v", ok, err)
	}
	if ok, err := st.RecordProgramExit(ctx, sb.ID, got.RunGeneration, first.Add(time.Minute), 9); err != nil || ok {
		t.Fatalf("second report recorded: %v %v", ok, err)
	}
	got, _ = st.Get(ctx, sb.ID)
	assertReason(t, got, models.StatusReasonProgramExited, exitPtr(3))
	if got.ProgramExitedAt == nil || !got.ProgramExitedAt.Equal(first) {
		t.Fatalf("program_exited_at = %v", got.ProgramExitedAt)
	}

	// A whole-row write from a read taken before the exit keeps it.
	if err := st.Upsert(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.ProgramExitedAt == nil {
		t.Fatal("a same-status Upsert dropped the exit")
	}
	stopped := *got
	stopped.Status = models.SandboxStatusStopped
	stopped.StatusReason, stopped.ExitCode, stopped.ProgramExitedAt = models.StatusReasonUserStop, nil, nil
	if err := st.Upsert(ctx, &stopped); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.ProgramExitedAt == nil || got.StatusReason != models.StatusReasonUserStop {
		t.Fatalf("after stop: exited=%v reason=%q", got.ProgramExitedAt, got.StatusReason)
	}
	if ok, _ := st.RecordProgramExit(ctx, sb.ID, got.RunGeneration, first, 1); ok {
		t.Fatal("recorded an exit on a stopped sandbox")
	}
	started := *got
	started.Status = models.SandboxStatusStarted
	started.StatusReason, started.ExitCode = "", nil
	if err := st.Upsert(ctx, &started); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.ProgramExitedAt != nil {
		t.Fatalf("a start kept the old exit: %v", got.ProgramExitedAt)
	}

	l := got.Lifecycle
	l.DestroyAfterExitFor = time.Hour
	if err := st.UpdateLifecycle(ctx, sb.ID, l); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.Lifecycle.DestroyAfterExitFor != time.Hour {
		t.Fatalf("UpdateLifecycle: %s", got.Lifecycle.DestroyAfterExitFor)
	}
	if ok, err := st.RecordProgramExit(ctx, "missing", 0, first, 0); err != nil || ok {
		t.Fatalf("missing row: %v %v", ok, err)
	}
}
