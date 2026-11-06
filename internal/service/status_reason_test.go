package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// statusReasonHarness is the OOM harness (a recording runtime whose events
// reach handleDockerEvent) on the Docker engine.
func newStatusReasonHarness(t *testing.T) *oomHarness {
	t.Helper()
	return newOOMHarness(t, oomEngines[0])
}

// seedStarted writes a started Docker sandbox, created and last active at
// the given ages.
func (h *oomHarness) seedStarted(t *testing.T, id string, lc models.Lifecycle, age, idle time.Duration) {
	t.Helper()
	now := time.Now().UTC()
	if err := h.st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "ubuntu:22.04", Runtime: models.RuntimeDocker, Engine: models.ContainerEngineDocker,
		Status: models.SandboxStatusStarted, ContainerID: id, ContainerIP: "10.0.0.7",
		CPU: 1, MemoryMB: 256, DiskGB: 1, Lifecycle: lc, AuditIncarnationID: "inc-" + id,
		CreatedAt: now.Add(-age), UpdatedAt: now, LastActiveAt: now.Add(-idle),
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func intPtr(v int) *int { return &v }

func wantReason(t *testing.T, sb *models.Sandbox, status models.SandboxStatus, reason string, exit *int) {
	t.Helper()
	if sb.Status != status || sb.StatusReason != reason {
		t.Fatalf("status %q reason %q, want %q %q", sb.Status, sb.StatusReason, status, reason)
	}
	switch {
	case exit == nil && sb.ExitCode != nil:
		t.Fatalf("exit_code = %d, want none", *sb.ExitCode)
	case exit != nil && (sb.ExitCode == nil || *sb.ExitCode != *exit):
		t.Fatalf("exit_code = %v, want %d", sb.ExitCode, *exit)
	}
}

// TestEveryStopPathRecordsItsReason is plan L2: each way a sandbox stops
// names why on the row, from the fixed set, with the exit code where there
// is an exit.
func TestEveryStopPathRecordsItsReason(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		lc     models.Lifecycle
		age    time.Duration
		idle   time.Duration
		global int // SB_IDLE_TIMEOUT_MIN
		stop   func(t *testing.T, h *oomHarness, id string)
		reason string
		exit   *int
	}{
		{name: "user stop", stop: func(t *testing.T, h *oomHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, reason: models.StatusReasonUserStop},
		{name: "facade pause", stop: func(t *testing.T, h *oomHarness, id string) {
			if _, err := h.svc.PauseSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, reason: models.StatusReasonUserStop},
		{name: "fleet suspend", stop: func(t *testing.T, h *oomHarness, id string) {
			if err := h.svc.StopByOwner(ctx, ""); err != nil {
				t.Fatal(err)
			}
		}, reason: models.StatusReasonUserStop},
		{name: "idle timer", lc: models.Lifecycle{StopIfIdleFor: time.Minute}, idle: 2 * time.Minute,
			stop: func(t *testing.T, h *oomHarness, _ string) { h.svc.runLifecycleSweep(ctx) }, reason: models.StatusReasonIdle},
		{name: "server idle default", global: 1, idle: 2 * time.Minute,
			stop: func(t *testing.T, h *oomHarness, _ string) { h.svc.runLifecycleSweep(ctx) }, reason: models.StatusReasonIdle},
		{name: "max age", lc: models.Lifecycle{StopAtAge: time.Minute}, age: 2 * time.Minute,
			stop: func(t *testing.T, h *oomHarness, _ string) { h.svc.runLifecycleSweep(ctx) }, reason: models.StatusReasonMaxAge},
		{name: "disk limit", stop: func(t *testing.T, h *oomHarness, id string) {
			sb := h.row(t, id)
			h.svc.stopForDiskLimit(ctx, sb, 5<<30)
		}, reason: models.StatusReasonDiskLimit},
		{name: "init exited cleanly", stop: func(t *testing.T, h *oomHarness, id string) {
			h.event(t, id, "die", 0)
		}, reason: models.StatusReasonProgramExited, exit: intPtr(0)},
		{name: "crash", stop: func(t *testing.T, h *oomHarness, id string) {
			h.event(t, id, "die", 3)
		}, reason: models.StatusReasonCrashed, exit: intPtr(3)},
		{name: "out of memory", stop: func(t *testing.T, h *oomHarness, id string) {
			h.event(t, id, "oom", 0)
			h.event(t, id, "die", 137)
		}, reason: models.StatusReasonOutOfMemory, exit: intPtr(137)},
		{name: "out of memory while a user stop was asked for", stop: func(t *testing.T, h *oomHarness, id string) {
			// The kernel reaped the init, not the stop: the OOM is the truth.
			h.svc.recordExpectedStopReason(id, stopModeManual, models.StatusReasonUserStop)
			h.event(t, id, "oom", 0)
			h.event(t, id, "die", 137)
		}, reason: models.StatusReasonOutOfMemory, exit: intPtr(137)},
		{name: "die event of a requested stop", stop: func(t *testing.T, h *oomHarness, id string) {
			// The die arrives before the stop call writes the row: it takes
			// the reason the call recorded, not one guessed from the exit.
			h.svc.recordExpectedStopReason(id, stopModeLifecycle, models.StatusReasonMaxAge)
			h.event(t, id, "die", 143)
		}, reason: models.StatusReasonMaxAge},
		{name: "stop event after die keeps the die's reason", stop: func(t *testing.T, h *oomHarness, id string) {
			h.event(t, id, "die", 3)
			h.event(t, id, "stop", 0)
		}, reason: models.StatusReasonCrashed, exit: intPtr(3)},
		{name: "stop call after the die keeps the die's reason", stop: func(t *testing.T, h *oomHarness, id string) {
			h.event(t, id, "die", 3)
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, reason: models.StatusReasonCrashed, exit: intPtr(3)},
		{name: "die after the stop call keeps the call's reason", stop: func(t *testing.T, h *oomHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
			h.event(t, id, "die", 0)
			h.event(t, id, "stop", 0)
		}, reason: models.StatusReasonUserStop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStatusReasonHarness(t)
			h.svc.cfg.IdleTimeoutMinutes = tc.global
			id := "sb-reason"
			h.seedStarted(t, id, tc.lc, tc.age, tc.idle)
			tc.stop(t, h, id)
			wantReason(t, h.row(t, id), models.SandboxStatusStopped, tc.reason, tc.exit)
		})
	}
}

// TestStartClearsTheStopReason: a start, by the API or out of band, answers
// whatever stopped the sandbox.
func TestStartClearsTheStopReason(t *testing.T) {
	ctx := context.Background()
	t.Run("api start", func(t *testing.T) {
		h := newStatusReasonHarness(t)
		h.seedStarted(t, "sb-s1", models.Lifecycle{}, 0, 0)
		h.event(t, "sb-s1", "die", 9)
		wantReason(t, h.row(t, "sb-s1"), models.SandboxStatusStopped, models.StatusReasonCrashed, intPtr(9))
		if _, err := h.svc.StartSandbox(ctx, "sb-s1"); err != nil {
			t.Fatal(err)
		}
		wantReason(t, h.row(t, "sb-s1"), models.SandboxStatusStarted, "", nil)
	})
	t.Run("out of band start event", func(t *testing.T) {
		h := newStatusReasonHarness(t)
		h.seedStarted(t, "sb-s2", models.Lifecycle{}, 0, 0)
		if _, err := h.svc.StopSandbox(ctx, "sb-s2"); err != nil {
			t.Fatal(err)
		}
		h.rt.inspect = map[string]*models.SandboxRuntimeState{
			"sb-s2": {ContainerID: "sb-s2", ContainerIP: "10.0.0.7", Status: models.SandboxStatusStarted},
		}
		h.event(t, "sb-s2", "start", 0)
		wantReason(t, h.row(t, "sb-s2"), models.SandboxStatusStarted, "", nil)
	})
}

// TestReconcileNamesAStopItOnlyFound: reconcile sees a started row whose
// container is stopped (the event was missed) and can only say so; it never
// replaces a reason the event path recorded.
func TestReconcileNamesAStopItOnlyFound(t *testing.T) {
	ctx := context.Background()
	h := newStatusReasonHarness(t)
	h.seedStarted(t, "sb-missed", models.Lifecycle{}, 0, 0)
	h.seedStarted(t, "sb-seen", models.Lifecycle{}, 0, 0)
	h.event(t, "sb-seen", "die", 5)
	stopped := &models.SandboxRuntimeState{ContainerIP: "10.0.0.7", Status: models.SandboxStatusStopped}
	h.rt.managed = map[string]*models.SandboxRuntimeState{
		"sb-missed": {ContainerID: "sb-missed", ContainerIP: stopped.ContainerIP, Status: stopped.Status},
		"sb-seen":   {ContainerID: "sb-seen", ContainerIP: stopped.ContainerIP, Status: stopped.Status},
	}
	if err := h.svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantReason(t, h.row(t, "sb-missed"), models.SandboxStatusStopped, models.StatusReasonReconcile, nil)
	wantReason(t, h.row(t, "sb-seen"), models.SandboxStatusStopped, models.StatusReasonCrashed, intPtr(5))

	// A container started out of band and found by reconcile is started,
	// with nothing left over from the stop.
	h.rt.managed["sb-seen"].Status = models.SandboxStatusStarted
	if err := h.svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantReason(t, h.row(t, "sb-seen"), models.SandboxStatusStarted, "", nil)
}

// TestReconcileWithAStaleReadKeepsTheEventsReason is the race the store's
// transition rule exists for: reconcile read the row as started, the die
// event then stopped it with its own reason, and reconcile's whole-row write
// (stopped, "reconcile") must not replace it.
func TestReconcileWithAStaleReadKeepsTheEventsReason(t *testing.T) {
	ctx := context.Background()
	h := newStatusReasonHarness(t)
	h.seedStarted(t, "sb-race", models.Lifecycle{}, 0, 0)
	stale := h.row(t, "sb-race")
	h.event(t, "sb-race", "die", 7)
	stale.Status = models.SandboxStatusStopped
	stale.StatusReason, stale.ExitCode = models.StatusReasonReconcile, nil
	if err := h.st.Upsert(ctx, stale); err != nil {
		t.Fatal(err)
	}
	wantReason(t, h.row(t, "sb-race"), models.SandboxStatusStopped, models.StatusReasonCrashed, intPtr(7))
}

// TestWasmStopPathsRecordReasons: an ephemeral WASM sandbox lost on a
// daemon restart is a reconcile finding.
func TestWasmStopPathsRecordReasons(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), &recordingRuntime{})
	svc.cfg.EnableWasm = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-wasm", Image: "mod", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		Durability: models.DurabilityEphemeral, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if !svc.reconcileWasmOfflineRow(ctx, sb) {
		t.Fatal("ephemeral row not handled")
	}
	got, err := st.Get(ctx, "sb-wasm")
	if err != nil {
		t.Fatal(err)
	}
	wantReason(t, got, models.SandboxStatusStopped, models.StatusReasonReconcile, nil)
}

// TestRecordFailoverReason: a sandbox the owner watcher recreated is started
// with reason failover; a missing row only logs.
func TestRecordFailoverReason(t *testing.T) {
	ctx := context.Background()
	h := newStatusReasonHarness(t)
	h.seedStarted(t, "sb-fo", models.Lifecycle{}, 0, 0)
	h.svc.recordFailoverReason(ctx, "sb-fo")
	wantReason(t, h.row(t, "sb-fo"), models.SandboxStatusStarted, models.StatusReasonFailover, nil)
	h.svc.recordFailoverReason(ctx, "sb-gone")
}

// TestLifecycleDecisionReasons pins which reason each lifecycle stop names.
func TestLifecycleDecisionReasons(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name   string
		lc     models.Lifecycle
		global time.Duration
		age    time.Duration
		idle   time.Duration
		action lifecycleAction
		reason string
	}{
		{"idle", models.Lifecycle{StopIfIdleFor: time.Minute}, 0, 0, 2 * time.Minute, lifecycleStop, models.StatusReasonIdle},
		{"age", models.Lifecycle{StopAtAge: time.Minute}, 0, 2 * time.Minute, 0, lifecycleStop, models.StatusReasonMaxAge},
		{"idle wins over age", models.Lifecycle{StopIfIdleFor: time.Minute, StopAtAge: time.Minute}, 0, 2 * time.Minute, 2 * time.Minute, lifecycleStop, models.StatusReasonIdle},
		{"server default", models.Lifecycle{}, time.Minute, 0, 2 * time.Minute, lifecycleStop, models.StatusReasonIdle},
		{"destroy has no stop reason", models.Lifecycle{DestroyAtAge: time.Minute}, 0, 2 * time.Minute, 0, lifecycleDestroy, ""},
		{"nothing due", models.Lifecycle{StopIfIdleFor: time.Hour}, 0, 0, 0, lifecycleNone, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := &models.Sandbox{Status: models.SandboxStatusStarted, Lifecycle: tc.lc, CreatedAt: now.Add(-tc.age), LastActiveAt: now.Add(-tc.idle)}
			action, reason := lifecycleDecision(sb, now, tc.global, time.Time{})
			if action != tc.action || reason != tc.reason {
				t.Fatalf("got (%v, %q), want (%v, %q)", action, reason, tc.action, tc.reason)
			}
		})
	}
	if a, r := lifecycleDecision(nil, now, 0, time.Time{}); a != lifecycleNone || r != "" {
		t.Fatalf("nil sandbox: (%v, %q)", a, r)
	}
}

// TestStopReasonHelpers pins the small mappings the stop paths share.
func TestStopReasonHelpers(t *testing.T) {
	for mode, want := range map[stopMode]string{
		stopModeManual:      models.StatusReasonUserStop,
		stopModeLifecycle:   models.StatusReasonIdle,
		stopModeInvoluntary: "",
	} {
		if got := defaultStopReason(mode); got != want {
			t.Fatalf("defaultStopReason(%v) = %q, want %q", mode, got, want)
		}
	}
	for _, tc := range []struct {
		oom    bool
		code   int
		reason string
	}{
		{true, 137, models.StatusReasonOutOfMemory},
		{false, 0, models.StatusReasonProgramExited},
		{false, 2, models.StatusReasonCrashed},
	} {
		reason, code := stopReasonForExit(tc.oom, tc.code)
		if reason != tc.reason || code == nil || *code != tc.code {
			t.Fatalf("stopReasonForExit(%v, %d) = %q %v", tc.oom, tc.code, reason, code)
		}
	}
	// An expectation that aged out is involuntary, with no reason.
	h := newStatusReasonHarness(t)
	h.svc.expectedStops = map[string]expectedStopRecord{"old": {mode: stopModeManual, reason: models.StatusReasonUserStop, recordedAt: time.Now().Add(-2 * expectedStopMaxAge)}}
	if mode, reason := h.svc.consumeExpectedStopReason("old"); mode != stopModeInvoluntary || reason != "" {
		t.Fatalf("stale expectation = (%v, %q)", mode, reason)
	}
}
