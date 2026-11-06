package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// seedSleepingServerless writes a stopped serverless sandbox armed to wake.
func seedSleepingServerless(t *testing.T, h *restartHarness, id string) {
	t.Helper()
	h.svc.cfg.EnableServerless = true
	h.seedStarted(t, id, models.Lifecycle{Serverless: true}, 0, 0)
	sb := h.row(t, id)
	sb.Status = models.SandboxStatusStopped
	if err := h.st.Upsert(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	if err := h.st.SetWakeArmed(context.Background(), id, true); err != nil {
		t.Fatal(err)
	}
}

// TestWakeDoesNotUndoAStopThatWonTheBoundary: a request finds a sleeping
// serverless sandbox armed to wake, and a manual stop gets the lifecycle
// boundary before the wake does. The stop disarms the wake, so the wake
// starts nothing and says so (409), without counting it against the wake
// breaker. Before, the wake started the sandbox the operator had just
// stopped.
func TestWakeDoesNotUndoAStopThatWonTheBoundary(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	id := "sb-sleepy"
	seedSleepingServerless(t, h, id)

	unlock, err := h.svc.lifecycleLocks.lock(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	woke := make(chan error, 1)
	go func() {
		_, err := h.svc.EnsureSandboxAwakeForHTTP(ctx, id)
		woke <- err
	}()
	select {
	case err := <-woke:
		unlock()
		t.Fatalf("the wake did not wait for the boundary (err=%v)", err)
	case <-time.After(50 * time.Millisecond):
	}
	// The manual stop that holds the boundary.
	if _, err := h.svc.stopSandboxLocked(ctx, id, stopModeManual, models.StatusReasonUserStop); err != nil {
		unlock()
		t.Fatal(err)
	}
	unlock()
	if err := <-woke; !errors.Is(err, ErrSandboxManuallyStopped) {
		t.Fatalf("wake after a manual stop = %v, want ErrSandboxManuallyStopped", err)
	}
	if len(h.rt.startRefs) != 0 {
		t.Fatal("the wake started the sandbox the operator stopped")
	}
	if row := h.row(t, id); row.Status != models.SandboxStatusStopped || row.WakeArmed {
		t.Fatalf("status %q wake_armed %v, want stopped and disarmed", row.Status, row.WakeArmed)
	}
	if f := h.svc.wakeFlightFor(id); f.failures != 0 {
		t.Fatalf("the refused wake counted as %d breaker failures", f.failures)
	}
}

// TestWakeSandboxDecidesFromTheRowItHolds covers the rest of the re-check.
func TestWakeSandboxDecidesFromTheRowItHolds(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)

	seedSleepingServerless(t, h, "sb-armed")
	got, err := h.svc.wakeSandbox(ctx, "sb-armed")
	if err != nil || got.Status != models.SandboxStatusStarted {
		t.Fatalf("armed: %v %v", got, err)
	}
	// Already started (another call woke it): returned as it is.
	if got, err := h.svc.wakeSandbox(ctx, "sb-armed"); err != nil || got.Status != models.SandboxStatusStarted {
		t.Fatalf("started: %v %v", got, err)
	}
	starts := len(h.rt.startRefs)

	// No longer serverless: returned as it is, not started.
	seedSleepingServerless(t, h, "sb-plain")
	if _, err := h.svc.UpdateLifecycle(ctx, "sb-plain", models.Lifecycle{}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.svc.wakeSandbox(ctx, "sb-plain"); err != nil || got.Status != models.SandboxStatusStopped {
		t.Fatalf("not serverless: %v %v", got, err)
	}
	if len(h.rt.startRefs) != starts {
		t.Fatal("started a sandbox that no longer wakes")
	}

	if _, err := h.svc.wakeSandbox(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
