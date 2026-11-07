package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSandboxLocks: one sandbox's steps wait for each other, other
// sandboxes' never do, a wait ends with ctx, and nothing is left behind
// (lifecycleLocks, a keyedLocks[string] taken with lockCtx).
func TestSandboxLocks(t *testing.T) {
	ctx := context.Background()
	var l keyedLocks[string]
	unlockA, err := l.lockCtx(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}

	// Another sandbox is not held up.
	unlockB, err := l.lockCtx(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	unlockB()

	// The same sandbox waits.
	got := make(chan func(), 1)
	go func() {
		unlock, err := l.lockCtx(ctx, "a")
		if err != nil {
			t.Error(err)
		}
		got <- unlock
	}()
	select {
	case <-got:
		t.Fatal("a second step on the same sandbox did not wait")
	case <-time.After(50 * time.Millisecond):
	}

	// A wait that outlasts its ctx gives up, and holds nothing.
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := l.lockCtx(short, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a wait past its deadline = %v", err)
	}

	unlockA()
	select {
	case unlock := <-got:
		unlock()
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting step never got the lock")
	}
	if n := l.keys(); n != 0 {
		t.Fatalf("%d locks left after every step finished", n)
	}

	// A free lock is taken even with a done ctx, as before.
	done, cancelDone := context.WithCancel(ctx)
	cancelDone()
	unlock, err := l.lockCtx(done, "a")
	if err != nil {
		t.Fatalf("free lock with a done ctx: %v", err)
	}
	unlock()
}

// TestEveryLifecycleEntryPointTakesTheBoundary is review 2 finding 9's
// inventory: every call that changes whether a sandbox runs waits while
// another step holds that sandbox's lifecycle boundary, then runs. The
// facades (Daytona start and stop, E2B pause and connect, Runloop suspend
// and resume) and the fleet controls reach the boundary through these.
func TestEveryLifecycleEntryPointTakesTheBoundary(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		seed func(t *testing.T, h *restartHarness, id string)
		call func(h *restartHarness, id string) error
	}{
		{"StartSandbox", seedStoppedRow, func(h *restartHarness, id string) error {
			_, err := h.svc.StartSandbox(ctx, id)
			return err
		}},
		{"StopSandbox", nil, func(h *restartHarness, id string) error {
			_, err := h.svc.StopSandbox(ctx, id)
			return err
		}},
		{"PauseSandbox", nil, func(h *restartHarness, id string) error {
			_, err := h.svc.PauseSandbox(ctx, id)
			return err
		}},
		{"ResumeSandbox", seedStoppedRow, func(h *restartHarness, id string) error {
			_, err := h.svc.ResumeSandbox(ctx, id)
			return err
		}},
		{"DestroySandbox", nil, func(h *restartHarness, id string) error {
			return h.svc.DestroySandbox(ctx, id)
		}},
		{"UpdateLifecycle", nil, func(h *restartHarness, id string) error {
			_, err := h.svc.UpdateLifecycle(ctx, id, models.Lifecycle{StopIfIdleFor: time.Hour})
			return err
		}},
		{"ApplyLifecyclePatch", nil, func(h *restartHarness, id string) error {
			_, _, err := h.svc.ApplyLifecyclePatch(ctx, id, func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
				return models.Lifecycle{StopIfIdleFor: time.Hour}, true, nil
			})
			return err
		}},
		{"disk watchdog stop", nil, func(h *restartHarness, id string) error {
			_, err := h.svc.stopSandboxForReason(ctx, id, stopModeManual, models.StatusReasonDiskLimit)
			return err
		}},
		{"lifecycle sweep stop", func(t *testing.T, h *restartHarness, id string) {
			h.seedStarted(t, id, models.Lifecycle{StopIfIdleFor: time.Minute}, 0, time.Hour)
		}, func(h *restartHarness, id string) error {
			h.svc.runLifecycleSweep(ctx)
			return wantStatus(h, id, models.SandboxStatusStopped)
		}},
		{"wake", func(t *testing.T, h *restartHarness, id string) {
			h.svc.cfg.EnableServerless = true
			seedStoppedRow(t, h, id)
			sb := h.row(t, id)
			sb.Lifecycle.Serverless, sb.WakeArmed = true, true
			if err := h.st.Upsert(ctx, sb); err != nil {
				t.Fatal(err)
			}
			if err := h.st.SetWakeArmed(ctx, id, true); err != nil {
				t.Fatal(err)
			}
		}, func(h *restartHarness, id string) error {
			_, err := h.svc.EnsureSandboxAwakeForHTTP(ctx, id)
			return err
		}},
		{"restart on failure", func(t *testing.T, h *restartHarness, id string) {
			h.seedRestarting(t, id, models.Lifecycle{})
			h.event(t, id, "die", 1)
			h.clock.advance(time.Minute)
		}, func(h *restartHarness, id string) error {
			h.svc.restartIfDue(ctx, id)
			return wantStatus(h, id, models.SandboxStatusStarted)
		}},
		{"die event", nil, func(h *restartHarness, id string) error {
			return h.svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 1, Time: time.Now().UTC()})
		}},
		{"destroy event", nil, func(h *restartHarness, id string) error {
			return h.svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "destroy", Time: time.Now().UTC()})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-boundary"
			if tc.seed != nil {
				tc.seed(t, h, id)
			} else {
				h.seedStarted(t, id, models.Lifecycle{}, 0, 0)
			}
			unlock, err := h.svc.lifecycleLocks.lockCtx(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- tc.call(h, id) }()
			select {
			case err := <-done:
				unlock()
				t.Fatalf("ran while another step held the boundary (err=%v)", err)
			case <-time.After(50 * time.Millisecond):
			}
			unlock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("after the boundary was free: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("never ran after the boundary was free")
			}
		})
	}
}

// TestLifecycleEntryPointsGiveUpWithTheirContext: a call that waits for the
// boundary returns its ctx's error when the caller gives up, and changes
// nothing.
func TestLifecycleEntryPointsGiveUpWithTheirContext(t *testing.T) {
	h := newRestartHarness(t)
	id := "sb-busy"
	h.seedStarted(t, id, models.Lifecycle{}, 0, 0)
	unlock, err := h.svc.lifecycleLocks.lockCtx(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	calls := map[string]func(ctx context.Context) error{
		"StartSandbox": func(ctx context.Context) error { _, err := h.svc.StartSandbox(ctx, id); return err },
		"StopSandbox":  func(ctx context.Context) error { _, err := h.svc.StopSandbox(ctx, id); return err },
		"PauseSandbox": func(ctx context.Context) error { _, err := h.svc.PauseSandbox(ctx, id); return err },
		"ResumeSandbox": func(ctx context.Context) error {
			_, err := h.svc.ResumeSandbox(ctx, id)
			return err
		},
		"DestroySandbox": func(ctx context.Context) error { return h.svc.DestroySandbox(ctx, id) },
		"UpdateLifecycle": func(ctx context.Context) error {
			_, err := h.svc.UpdateLifecycle(ctx, id, models.Lifecycle{})
			return err
		},
		"ApplyLifecyclePatch": func(ctx context.Context) error {
			_, _, err := h.svc.ApplyLifecyclePatch(ctx, id, nil)
			return err
		},
		"wakeSandbox": func(ctx context.Context) error { _, err := h.svc.wakeSandbox(ctx, id); return err },
		"die event": func(ctx context.Context) error {
			return h.svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 1})
		},
		"lifecycle action": func(ctx context.Context) error {
			return h.svc.runLifecycleAction(ctx, id, time.Now(), 0, false)
		},
	}
	for name, call := range calls {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := call(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s while the boundary is held = %v, want the deadline", name, err)
		}
	}
	if row := h.row(t, id); row.Status != models.SandboxStatusStarted {
		t.Fatalf("a call that gave up changed the row: %s", row.Status)
	}
	if len(h.rt.startRefs)+len(h.rt.stopRefs)+len(h.rt.destroyIDs) != 0 {
		t.Fatalf("a call that gave up reached the runtime: start=%v stop=%v destroy=%v", h.rt.startRefs, h.rt.stopRefs, h.rt.destroyIDs)
	}
}

// wantStatus is an error unless id's row is in status (safe off the test
// goroutine).
func wantStatus(h *restartHarness, id string, status models.SandboxStatus) error {
	sb, err := h.st.Get(context.Background(), id)
	if err != nil {
		return err
	}
	if sb.Status != status {
		return errors.New("status " + string(sb.Status) + ", want " + string(status))
	}
	return nil
}

// TestLifecycleSweepDecidesAgainInsideTheBoundary is finding 10's other half:
// the sweep acts on a row it read before its probes and every action ahead
// of it. A sandbox whose main program ended, then was stopped and started
// again, no longer carries that exit, so the delete the old read called for
// is not done.
func TestLifecycleSweepDecidesAgainInsideTheBoundary(t *testing.T) {
	ctx := context.Background()
	h := newExitHarness(t)
	exited := time.Now().UTC().Add(-time.Hour)
	h.seed(t, "sb-rerun", models.SandboxStatusStarted, models.RuntimeDocker, time.Second, &exited)
	h.seed(t, "sb-done", models.SandboxStatusStarted, models.RuntimeDocker, time.Second, &exited)
	now := time.Now().UTC()
	// The sweep's earlier read of sb-rerun called for a delete.
	if action, _ := lifecycleDecision(h.mustGet(t, "sb-rerun"), now, 0, time.Time{}); action != lifecycleDestroy {
		t.Fatalf("setup: decision %v, want a delete", action)
	}
	if _, err := h.svc.StopSandbox(ctx, "sb-rerun"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.StartSandbox(ctx, "sb-rerun"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sb-rerun", "sb-done"} {
		if err := h.svc.runLifecycleAction(ctx, id, now, 0, false); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if sb, ok := h.get(t, "sb-rerun"); !ok || sb.Status != models.SandboxStatusStarted {
		t.Fatalf("the new run was deleted for the old run's exit (present=%v)", ok)
	}
	if _, ok := h.get(t, "sb-done"); ok {
		t.Fatal("a sandbox whose exit still stands was not deleted")
	}
	// A row that is already gone is nothing to do.
	if err := h.svc.runLifecycleAction(ctx, "sb-done", now, 0, false); err != nil {
		t.Fatalf("gone row: %v", err)
	}
}

// seedStoppedRow writes a stopped Docker sandbox.
func seedStoppedRow(t *testing.T, h *restartHarness, id string) {
	t.Helper()
	h.seedStarted(t, id, models.Lifecycle{}, 0, 0)
	sb := h.row(t, id)
	sb.Status = models.SandboxStatusStopped
	if err := h.st.Upsert(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
}
