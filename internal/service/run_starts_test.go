package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// exitEvent is a die or stop event of sandbox id stamped at.
func exitEvent(id, action string, exitCode int, at time.Time) docker.DockerEvent {
	return docker.DockerEvent{SandboxID: id, ContainerID: id, Action: action, ExitCode: exitCode, Time: at}
}

// handleDuringStart runs ev the way the event queue does when it comes in
// while a start holds the sandbox's lifecycle boundary: the event waits for
// the boundary, the start runs, and the event is handled after it, reading
// the row the start wrote.
func handleDuringStart(t *testing.T, h *restartHarness, id string, ev docker.DockerEvent) {
	t.Helper()
	ctx := context.Background()
	unlock, err := h.svc.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan error, 1)
	go func() { handled <- h.svc.handleDockerEvent(ctx, ev) }()
	deadline := time.Now().Add(5 * time.Second)
	for h.svc.lifecycleLocks.refs(id) < 2 {
		if time.Now().After(deadline) {
			unlock()
			t.Fatal("the event never waited for the boundary")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := h.svc.startSandboxLocked(ctx, id, startRequested); err != nil {
		unlock()
		t.Fatal(err)
	}
	unlock()
	if err := <-handled; err != nil {
		t.Fatal(err)
	}
}

// TestExitEventOfAnEarlierRun: a die or stop event is handled only for the
// run it came from. The program crashes, its die waits behind a start the
// user asked for right away, and is handled once the new run is up. Before,
// it was never checked against the run: it marked the new run stopped and,
// with restart_on_failure, scheduled a restart that killed the user's new
// program. An exit stamped before the current run's start (the engine's own
// clock, SandboxRuntimeState.StartedAt) now changes nothing, and an exit of
// the current run is handled as always.
func TestExitEventOfAnEarlierRun(t *testing.T) {
	ctx := context.Background()
	runStart := time.Now().UTC()
	before, after := runStart.Add(-time.Second), runStart.Add(time.Second)

	cases := []struct {
		name string
		// noStartTime is a runtime that does not say when a run started.
		noStartTime bool
		steps       func(t *testing.T, h *restartHarness, id string)
		wantStatus  models.SandboxStatus
		wantReason  string
		wantExit    *int
		wantTimers  int
	}{
		{
			name: "crash of the run before, handled after a start",
			steps: func(t *testing.T, h *restartHarness, id string) {
				handleDuringStart(t, h, id, exitEvent(id, "die", 1, before))
			},
			wantStatus: models.SandboxStatusStarted,
		},
		{
			name: "stop event of the run before, handled after a start",
			steps: func(t *testing.T, h *restartHarness, id string) {
				handleDuringStart(t, h, id, exitEvent(id, "stop", 0, before))
			},
			wantStatus: models.SandboxStatusStarted,
		},
		{
			name: "OOM kill of the run before does not label the new run's crash",
			steps: func(t *testing.T, h *restartHarness, id string) {
				h.event(t, id, "oom", 0)
				handleDuringStart(t, h, id, exitEvent(id, "die", 137, before))
				if err := h.svc.handleDockerEvent(ctx, exitEvent(id, "die", 1, after)); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
		{
			// The stop's die is late: the start comes first. It is ignored,
			// and the stop's expectation goes with the start, so the new
			// run's crash is a crash, not the user's stop.
			name: "user stop's die handled after the next start, then the new run crashes",
			steps: func(t *testing.T, h *restartHarness, id string) {
				if _, err := h.svc.StopSandbox(ctx, id); err != nil {
					t.Fatal(err)
				}
				handleDuringStart(t, h, id, exitEvent(id, "die", 143, before))
				if row := h.row(t, id); row.Status != models.SandboxStatusStarted || row.StatusReason != "" {
					t.Fatalf("after the late die: status %q reason %q, want started", row.Status, row.StatusReason)
				}
				if err := h.svc.handleDockerEvent(ctx, exitEvent(id, "die", 1, after)); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
		{
			name: "crash of the current run during the start",
			steps: func(t *testing.T, h *restartHarness, id string) {
				handleDuringStart(t, h, id, exitEvent(id, "die", 1, after))
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
		{
			name: "crash and stop event of the current run",
			steps: func(t *testing.T, h *restartHarness, id string) {
				if _, err := h.svc.StartSandbox(ctx, id); err != nil {
					t.Fatal(err)
				}
				for _, ev := range []docker.DockerEvent{exitEvent(id, "die", 1, after), exitEvent(id, "stop", 0, after)} {
					if err := h.svc.handleDockerEvent(ctx, ev); err != nil {
						t.Fatal(err)
					}
				}
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
		{
			name: "user stop of the current run",
			steps: func(t *testing.T, h *restartHarness, id string) {
				if _, err := h.svc.StartSandbox(ctx, id); err != nil {
					t.Fatal(err)
				}
				if _, err := h.svc.StopSandbox(ctx, id); err != nil {
					t.Fatal(err)
				}
				h.event(t, id, "die", 143)
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonUserStop,
		},
		{
			// Nothing to tell the runs apart by: handled as before.
			name: "exit event without a time",
			steps: func(t *testing.T, h *restartHarness, id string) {
				handleDuringStart(t, h, id, exitEvent(id, "die", 1, time.Time{}))
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
		{
			name:        "runtime that does not say when the run started",
			noStartTime: true,
			steps: func(t *testing.T, h *restartHarness, id string) {
				handleDuringStart(t, h, id, exitEvent(id, "die", 1, before))
			},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed, wantExit: intPtr(1), wantTimers: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-run"
			h.seedRestarting(t, id, models.Lifecycle{})
			state := &models.SandboxRuntimeState{ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStarted}
			if !tc.noStartTime {
				state.StartedAt = runStart
			}
			h.rt.startState = state

			tc.steps(t, h, id)

			row := h.row(t, id)
			wantReason(t, row, tc.wantStatus, tc.wantReason, tc.wantExit)
			if got := h.clock.count(); got != tc.wantTimers {
				t.Fatalf("restart timers armed: %d, want %d", got, tc.wantTimers)
			}
			if (row.RestartAt != nil) != (tc.wantTimers > 0) {
				t.Fatalf("restart_at = %v, want scheduled=%v", row.RestartAt, tc.wantTimers > 0)
			}
		})
	}
}

func TestSandboxRunStarts(t *testing.T) {
	start := time.Date(2026, 11, 7, 10, 0, 0, 500, time.UTC)
	var r sandboxRunStarts
	if r.note("sb", time.Time{}) {
		t.Fatal("a zero start was recorded")
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{name: "before the start", at: start.Add(-time.Nanosecond), want: true},
		{name: "at the start", at: start},
		{name: "after the start", at: start.Add(time.Nanosecond)},
		{name: "no event time", at: time.Time{}},
	}
	if _, old := r.predates("sb", start.Add(-time.Hour)); old {
		t.Fatal("an event was old for a sandbox with no start")
	}
	if !r.note("sb", start) {
		t.Fatal("a start was not recorded")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, old := r.predates("sb", tc.at)
			if old != tc.want || (!tc.at.IsZero() && !got.Equal(start)) {
				t.Fatalf("predates = %v, %v; want %v, %v", got, old, start, tc.want)
			}
		})
	}
	// The latest start is the current run, even if its clock reads earlier.
	r.note("sb", start.Add(-time.Minute))
	if _, old := r.predates("sb", start.Add(-time.Second)); old {
		t.Fatal("an earlier start time was not taken as the current run")
	}
	r.forget("sb")
	if _, old := r.predates("sb", start.Add(-time.Hour)); old {
		t.Fatal("a forgotten start still fenced events")
	}
}

// TestDestroyForgetsTheRunStart: a row that is gone takes its run start
// with it, by an API destroy or by a destroy event.
func TestDestroyForgetsTheRunStart(t *testing.T) {
	ctx := context.Background()
	runStart := time.Now().UTC()
	cases := []struct {
		name    string
		destroy func(t *testing.T, h *restartHarness, id string)
	}{
		{name: "api destroy", destroy: func(t *testing.T, h *restartHarness, id string) {
			if err := h.svc.DestroySandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "destroy event", destroy: func(t *testing.T, h *restartHarness, id string) {
			h.event(t, id, "destroy", 0)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-gone"
			h.seedRestarting(t, id, models.Lifecycle{})
			h.rt.startState = &models.SandboxRuntimeState{ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStarted, StartedAt: runStart}
			if _, err := h.svc.StartSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, old := h.svc.runStarts.predates(id, runStart.Add(-time.Second)); !old {
				t.Fatal("the start was not recorded")
			}
			tc.destroy(t, h, id)
			if _, old := h.svc.runStarts.predates(id, runStart.Add(-time.Second)); old {
				t.Fatal("the run start outlived the row")
			}
		})
	}
}
