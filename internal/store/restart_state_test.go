package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestRestartOnFailureColumns: the lifecycle flag round-trips through Create,
// Upsert and UpdateLifecycle, and the backoff state is written only by its
// own methods, so a whole-row write from an older read cannot drop a
// restart a crash scheduled.
func TestRestartOnFailureColumns(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-restart")
	sb.Status = models.SandboxStatusStarted
	sb.Lifecycle.RestartOnFailure = true
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Lifecycle.RestartOnFailure || got.RestartFailures != 0 || got.RestartAt != nil || got.LastRestartedAt != nil {
		t.Fatalf("fresh row: flag=%v failures=%d at=%v last=%v", got.Lifecycle.RestartOnFailure, got.RestartFailures, got.RestartAt, got.LastRestartedAt)
	}
	stale := *got

	at := time.Date(2026, 11, 6, 10, 0, 5, 0, time.UTC)
	if err := st.ScheduleRestart(ctx, sb.ID, 3, at); err != nil {
		t.Fatalf("ScheduleRestart: %v", err)
	}
	// A whole-row write from the read taken before the crash.
	stale.Status = models.SandboxStatusStopped
	if err := st.Upsert(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	got, _ = st.Get(ctx, sb.ID)
	if got.RestartFailures != 3 || got.RestartAt == nil || !got.RestartAt.Equal(at) {
		t.Fatalf("Upsert touched the backoff: failures=%d at=%v", got.RestartFailures, got.RestartAt)
	}

	ran := at.Add(time.Second)
	if err := st.MarkRestarted(ctx, sb.ID, ran); err != nil {
		t.Fatalf("MarkRestarted: %v", err)
	}
	got, _ = st.Get(ctx, sb.ID)
	if got.RestartAt != nil || got.LastRestartedAt == nil || !got.LastRestartedAt.Equal(ran) || got.RestartFailures != 3 {
		t.Fatalf("after MarkRestarted: at=%v last=%v failures=%d", got.RestartAt, got.LastRestartedAt, got.RestartFailures)
	}

	off := got.Lifecycle
	off.RestartOnFailure = false
	if err := st.UpdateLifecycle(ctx, sb.ID, off); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); got.Lifecycle.RestartOnFailure {
		t.Fatal("UpdateLifecycle did not clear restart_on_failure")
	}
	got.Lifecycle.RestartOnFailure = true
	if err := st.Upsert(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Get(ctx, sb.ID); !got.Lifecycle.RestartOnFailure {
		t.Fatal("Upsert did not write restart_on_failure")
	}
}

// TestCancelRestartReplacesTheCrashReasonOnlyWhenOnePending: a stop of a
// sandbox waiting to restart reads as that stop; with nothing pending, or
// with no reason given, the reason is left alone.
func TestCancelRestartReplacesTheCrashReasonOnlyWhenOnePending(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-cancel")
	sb.Status = models.SandboxStatusStopped
	sb.StatusReason = models.StatusReasonCrashed
	sb.ExitCode = exitPtr(1)
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name     string
		schedule bool
		reason   string
		want     string
		wantExit *int
	}{
		{"nothing pending keeps the reason", false, models.StatusReasonUserStop, models.StatusReasonCrashed, exitPtr(1)},
		{"pending with no reason keeps it", true, "", models.StatusReasonCrashed, exitPtr(1)},
		{"pending with a reason replaces it", true, models.StatusReasonUserStop, models.StatusReasonUserStop, nil},
	}
	for _, step := range steps {
		if step.schedule {
			if err := st.ScheduleRestart(ctx, sb.ID, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.CancelRestart(ctx, sb.ID, step.reason); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		got, _ := st.Get(ctx, sb.ID)
		if got.RestartAt != nil {
			t.Fatalf("%s: restart still pending", step.name)
		}
		assertReason(t, got, step.want, step.wantExit)
	}
	for name, err := range map[string]error{
		"ScheduleRestart": st.ScheduleRestart(ctx, "missing", 1, time.Now()),
		"MarkRestarted":   st.MarkRestarted(ctx, "missing", time.Now()),
		"CancelRestart":   st.CancelRestart(ctx, "missing", ""),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s(missing) = %v, want ErrNotFound", name, err)
		}
	}
}
