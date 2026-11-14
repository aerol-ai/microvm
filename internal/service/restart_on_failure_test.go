package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeRestartClock drives restart on failure without waiting: a settable
// clock, and timers that only fire when the test says so.
type fakeRestartClock struct {
	mu   sync.Mutex
	now  time.Time
	arms []*fakeRestartArm
}

type fakeRestartArm struct {
	delay   time.Duration
	fire    func()
	stopped bool
}

func (a *fakeRestartArm) Stop() bool {
	was := !a.stopped
	a.stopped = true
	return was
}

func (c *fakeRestartClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeRestartClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeRestartClock) after(d time.Duration, f func()) restartTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	arm := &fakeRestartArm{delay: d, fire: f}
	c.arms = append(c.arms, arm)
	return arm
}

// last is the most recent timer armed, or nil.
func (c *fakeRestartClock) last() *fakeRestartArm {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.arms) == 0 {
		return nil
	}
	return c.arms[len(c.arms)-1]
}

func (c *fakeRestartClock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.arms)
}

type restartHarness struct {
	*oomHarness
	clock *fakeRestartClock
	path  string
}

func newRestartHarness(t *testing.T) *restartHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	rt := &ruleRecordingRuntime{recordingRuntime: &recordingRuntime{}}
	svc, st, admitter := newServiceRuntimeHarnessAtPath(t, path, rt)
	svc.routeWriter = &recordingRouteWriter{}
	h := &restartHarness{
		oomHarness: &oomHarness{svc: svc, st: st, admitter: admitter, rt: rt},
		clock:      &fakeRestartClock{now: time.Now().UTC()},
		path:       path,
	}
	h.wire(svc)
	return h
}

func (h *restartHarness) wire(svc *Service) {
	svc.restartClock = h.clock.Now
	svc.restartAfterFunc = h.clock.after
}

// seedRestarting writes a started Docker sandbox that restarts on failure.
func (h *restartHarness) seedRestarting(t *testing.T, id string, lc models.Lifecycle) {
	t.Helper()
	lc.RestartOnFailure = true
	h.seedStarted(t, id, lc, 0, 0)
}

// fire runs the latest timer as its goroutine would.
func (h *restartHarness) fire(t *testing.T) {
	t.Helper()
	arm := h.clock.last()
	if arm == nil {
		t.Fatal("no restart timer armed")
	}
	arm.fire()
}

func TestRestartBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		0: 5 * time.Second, 1: 5 * time.Second, 2: 10 * time.Second, 3: 20 * time.Second,
		4: 40 * time.Second, 5: 80 * time.Second, 6: 160 * time.Second, 7: 5 * time.Minute, 30: 5 * time.Minute,
	} {
		if got := restartBackoff(failures); got != want {
			t.Fatalf("restartBackoff(%d) = %s, want %s", failures, got, want)
		}
	}
}

// TestRestartOnFailureCrashLoopBacksOffAndResets is L1's core: a crash
// restarts after 5 s, each crash soon after a restart doubles the wait, and
// one that comes after 10 minutes of running starts over at 5 s.
func TestRestartOnFailureCrashLoopBacksOffAndResets(t *testing.T) {
	h := newRestartHarness(t)
	id := "sb-loop"
	h.seedRestarting(t, id, models.Lifecycle{})
	lastActive := h.row(t, id).LastActiveAt

	crashAndRestart := func(wantFailures int, wantDelay time.Duration) {
		t.Helper()
		h.event(t, id, "die", 1)
		row := h.row(t, id)
		wantReason(t, row, models.SandboxStatusStopped, models.StatusReasonCrashed, intPtr(1))
		if row.RestartFailures != wantFailures || row.RestartAt == nil || !row.RestartAt.Equal(h.clock.Now().Add(wantDelay)) {
			t.Fatalf("scheduled failures=%d at=%v, want %d at now+%s", row.RestartFailures, row.RestartAt, wantFailures, wantDelay)
		}
		if arm := h.clock.last(); arm == nil || arm.delay != wantDelay {
			t.Fatalf("timer delay = %v, want %s", arm, wantDelay)
		}
		// Firing early (a timer that ran ahead of the stored time) re-arms
		// for the rest of the wait instead of starting now.
		h.fire(t)
		if got := h.row(t, id); got.Status != models.SandboxStatusStopped {
			t.Fatalf("restarted before its wait: %q", got.Status)
		}
		h.clock.advance(wantDelay)
		h.fire(t)
		row = h.row(t, id)
		wantReason(t, row, models.SandboxStatusStarted, models.StatusReasonRestarted, intPtr(1))
		if row.RestartAt != nil || row.LastRestartedAt == nil || !row.LastRestartedAt.Equal(h.clock.Now()) {
			t.Fatalf("after restart: restart_at=%v last_restarted_at=%v", row.RestartAt, row.LastRestartedAt)
		}
		if !row.LastActiveAt.Equal(lastActive) {
			t.Fatalf("a restart counted as activity: last_active_at %v -> %v", lastActive, row.LastActiveAt)
		}
	}

	crashAndRestart(1, 5*time.Second)
	h.clock.advance(time.Minute)
	crashAndRestart(2, 10*time.Second)
	h.clock.advance(time.Minute)
	crashAndRestart(3, 20*time.Second)
	h.clock.advance(restartResetAfter)
	crashAndRestart(1, 5*time.Second)

	// The stop event that follows a die is the same exit: nothing more.
	before := h.clock.count()
	h.event(t, id, "die", 1)
	h.event(t, id, "stop", 0)
	if row := h.row(t, id); row.RestartFailures != 2 {
		t.Fatalf("a duplicate event counted as a failure: %d", row.RestartFailures)
	}
	if h.clock.count() != before+1 {
		t.Fatalf("timers armed: %d, want 1 more", h.clock.count()-before)
	}
}

// TestRestartOnFailureKeepsTheOOMRecord: an OOM kill is a failure; after the
// restart the row still says how the last run ended.
func TestRestartOnFailureKeepsTheOOMRecord(t *testing.T) {
	h := newRestartHarness(t)
	id := "sb-oom"
	h.seedRestarting(t, id, models.Lifecycle{})
	h.event(t, id, "oom", 0)
	h.event(t, id, "die", 137)
	wantReason(t, h.row(t, id), models.SandboxStatusStopped, models.StatusReasonOutOfMemory, intPtr(137))
	h.clock.advance(5 * time.Second)
	h.fire(t)
	row := h.row(t, id)
	wantReason(t, row, models.SandboxStatusStarted, models.StatusReasonRestarted, intPtr(137))
	if !strings.Contains(row.LastError, "OOM") {
		t.Fatalf("last_error after restart = %q, want the OOM record kept", row.LastError)
	}
}

// TestRestartOnFailureNeverFights: no restart for a stop someone asked for,
// a clean exit, a sandbox without the option, or a waiting sandbox that was
// stopped, paused, started, destroyed or whose timer ran out meanwhile.
func TestRestartOnFailureNeverFights(t *testing.T) {
	ctx := context.Background()
	noSchedule := []struct {
		name   string
		lc     models.Lifecycle
		idle   time.Duration
		option bool
		stop   func(t *testing.T, h *restartHarness, id string)
	}{
		{name: "user stop", option: true, stop: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
			h.event(t, id, "die", 143)
		}},
		{name: "idle stop", option: true, lc: models.Lifecycle{StopIfIdleFor: time.Minute}, idle: 2 * time.Minute,
			stop: func(t *testing.T, h *restartHarness, id string) {
				h.svc.runLifecycleSweep(ctx)
				h.event(t, id, "die", 143)
			}},
		{name: "disk limit", option: true, stop: func(t *testing.T, h *restartHarness, id string) {
			h.svc.stopForDiskLimit(ctx, h.row(t, id), 9<<30)
			h.event(t, id, "die", 143)
		}},
		{name: "clean exit", option: true, stop: func(t *testing.T, h *restartHarness, id string) { h.event(t, id, "die", 0) }},
		{name: "option off", option: false, stop: func(t *testing.T, h *restartHarness, id string) { h.event(t, id, "die", 1) }},
	}
	for _, tc := range noSchedule {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-nf"
			lc := tc.lc
			lc.RestartOnFailure = tc.option
			h.seedStarted(t, id, lc, 0, tc.idle)
			tc.stop(t, h, id)
			if row := h.row(t, id); row.RestartAt != nil || h.clock.count() != 0 {
				t.Fatalf("restart scheduled: at=%v timers=%d reason=%q", row.RestartAt, h.clock.count(), row.StatusReason)
			}
		})
	}

	waiting := []struct {
		name       string
		lc         models.Lifecycle
		act        func(t *testing.T, h *restartHarness, id string)
		wantStatus models.SandboxStatus
		wantReason string
		gone       bool
	}{
		{name: "stop while waiting", act: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonUserStop},
		{name: "pause while waiting", act: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.PauseSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonUserStop},
		{name: "start while waiting", act: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.StartSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, wantStatus: models.SandboxStatusStarted, wantReason: ""},
		{name: "idle timer ran out while waiting", lc: models.Lifecycle{StopIfIdleFor: 3 * time.Second},
			act:        func(*testing.T, *restartHarness, string) {},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed},
		{name: "age timer ran out while waiting", lc: models.Lifecycle{DestroyAtAge: 3 * time.Second},
			act:        func(*testing.T, *restartHarness, string) {},
			wantStatus: models.SandboxStatusStopped, wantReason: models.StatusReasonCrashed},
		{name: "destroy while waiting", act: func(t *testing.T, h *restartHarness, id string) {
			if err := h.svc.DestroySandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, gone: true},
	}
	for _, tc := range waiting {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-wait"
			h.seedRestarting(t, id, tc.lc)
			h.event(t, id, "die", 1)
			arm := h.clock.last()
			if arm == nil {
				t.Fatal("crash scheduled no restart")
			}
			tc.act(t, h, id)
			starts := len(h.rt.startRefs)
			h.clock.advance(time.Minute)
			arm.fire()
			if len(h.rt.startRefs) != starts {
				t.Fatalf("the restart started the sandbox anyway (%d starts)", len(h.rt.startRefs)-starts)
			}
			if tc.gone {
				if _, err := h.st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("row after destroy: %v", err)
				}
				if !arm.stopped {
					t.Fatal("destroy left the restart timer running")
				}
				return
			}
			row := h.row(t, id)
			if row.Status != tc.wantStatus || row.StatusReason != tc.wantReason || row.RestartAt != nil {
				t.Fatalf("status %q reason %q restart_at %v, want %q %q none", row.Status, row.StatusReason, row.RestartAt, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

// TestRestartOnFailureSurvivesADaemonRestart: the backoff is stored, so a
// new daemon on the same database (no timers) arms the pending restart from
// its first sweep and keeps counting failures.
func TestRestartOnFailureSurvivesADaemonRestart(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	id := "sb-boot"
	h.seedRestarting(t, id, models.Lifecycle{})
	h.event(t, id, "die", 1)
	h.clock.advance(5 * time.Second)
	h.fire(t)
	h.clock.advance(time.Minute)
	h.event(t, id, "die", 1) // failure 2: due in 10 s

	// The old daemon is gone with its timers; a new one opens the database.
	rt := &recordingRuntime{}
	svc2, _, _ := newServiceRuntimeHarnessAtPath(t, h.path, rt)
	clock2 := &fakeRestartClock{now: h.clock.Now()}
	svc2.restartClock = clock2.Now
	svc2.restartAfterFunc = clock2.after
	svc2.runLifecycleSweep(ctx)
	arm := clock2.last()
	if arm == nil || arm.delay != 10*time.Second {
		t.Fatalf("sweep armed %v, want the remaining 10s", arm)
	}
	svc2.runLifecycleSweep(ctx)
	if clock2.count() != 1 {
		t.Fatalf("a second sweep armed again (%d timers)", clock2.count())
	}
	clock2.advance(10 * time.Second)
	arm.fire()
	row, err := svc2.store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != models.SandboxStatusStarted || row.StatusReason != models.StatusReasonRestarted || row.RestartFailures != 2 {
		t.Fatalf("after the new daemon's restart: %q %q failures=%d", row.Status, row.StatusReason, row.RestartFailures)
	}
}

// TestRestartOnFailureRetriesAFailedStart: a restart refused for capacity
// leaves the sandbox stopped and tries again after the next wait; one that
// marks the sandbox error stops the cycle.
func TestRestartOnFailureRetriesAFailedStart(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	id := "sb-full"
	h.seedRestarting(t, id, models.Lifecycle{})
	h.event(t, id, "die", 1)
	// The sandbox no longer fits the node while it waits.
	resize := func(cpu float64) {
		t.Helper()
		row := h.row(t, id)
		row.CPU = cpu
		if err := h.st.Upsert(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	resize(64)
	h.clock.advance(5 * time.Second)
	h.fire(t)
	row := h.row(t, id)
	if row.Status != models.SandboxStatusStopped || row.RestartFailures != 2 || row.RestartAt == nil {
		t.Fatalf("after a refused start: %q failures=%d at=%v", row.Status, row.RestartFailures, row.RestartAt)
	}
	if arm := h.clock.last(); arm.delay != 10*time.Second {
		t.Fatalf("retry delay %s, want 10s", arm.delay)
	}

	resize(1)
	h.rt.startErr = errors.New("engine exploded")
	h.clock.advance(10 * time.Second)
	h.fire(t)
	if row := h.row(t, id); row.Status != models.SandboxStatusError || h.clock.last().delay != 10*time.Second {
		t.Fatalf("after an engine failure: %q, last timer %s", row.Status, h.clock.last().delay)
	}
}

// TestRestartOnFailureRuntimes is P4's matrix: Docker, gVisor, containerd
// and a pre-migration row restart on failure (the crash tests above run on
// the Docker engine; TestRestartOnFailureOnEveryContainerEngine on the
// others); Firecracker, WASM and isolate refuse the option.
func TestRestartOnFailureRuntimes(t *testing.T) {
	lc := models.Lifecycle{RestartOnFailure: true}
	for runtime, ok := range map[string]bool{
		models.RuntimeDocker: true, models.RuntimeGvisor: true, "": true,
		models.RuntimeFirecracker: false, models.RuntimeWasm: false, models.RuntimeIsolate: false,
	} {
		err := validateLifecycleRuntime(lc, runtime)
		if (err == nil) != ok {
			t.Fatalf("runtime %q: err %v, want ok=%v", runtime, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "restart_on_failure is not supported") {
			t.Fatalf("runtime %q: unclear error %v", runtime, err)
		}
	}
	if err := validateLifecycleRuntime(models.Lifecycle{}, models.RuntimeWasm); err != nil {
		t.Fatalf("no options refused: %v", err)
	}

	ctx := context.Background()
	t.Run("create", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Image: "alpine", Runtime: models.RuntimeFirecracker, Lifecycle: &lc,
		})
		if err == nil || !strings.Contains(err.Error(), "restart_on_failure is not supported") {
			t.Fatalf("firecracker create = %v, want the restart_on_failure refusal", err)
		}
	})
	t.Run("lifecycle update", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		now := time.Now().UTC()
		for _, sb := range []*models.Sandbox{
			{ID: "sb-fc", Image: "alpine", Runtime: models.RuntimeFirecracker, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now},
			{ID: "sb-ok", Image: "alpine", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now},
		} {
			if err := st.Create(ctx, sb); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := svc.UpdateLifecycle(ctx, "sb-fc", lc); err == nil {
			t.Fatal("firecracker lifecycle update accepted restart_on_failure")
		}
		patch := func(*models.Sandbox) (models.Lifecycle, bool, error) { return lc, true, nil }
		if _, _, err := svc.ApplyLifecyclePatch(ctx, "sb-fc", patch); err == nil {
			t.Fatal("firecracker lifecycle patch accepted restart_on_failure")
		}
		got, err := svc.UpdateLifecycle(ctx, "sb-ok", lc)
		if err != nil || !got.Lifecycle.RestartOnFailure {
			t.Fatalf("docker lifecycle update = %v, %v", got, err)
		}
	})
}

// TestRestartOnFailureOnEveryContainerEngine: containerd's die events (runc
// and gVisor) reach the same path as Docker's.
func TestRestartOnFailureOnEveryContainerEngine(t *testing.T) {
	for _, eng := range oomEngines {
		t.Run(eng.name, func(t *testing.T) {
			h := newOOMHarness(t, eng)
			// The harness admitter only knows the docker runtime; admission
			// is not what this checks.
			h.svc.admitter = nil
			clock := &fakeRestartClock{now: time.Now().UTC()}
			h.svc.restartClock, h.svc.restartAfterFunc = clock.Now, clock.after
			now := time.Now().UTC()
			if err := h.st.Create(context.Background(), &models.Sandbox{
				ID: "sb-eng", Image: "alpine", Runtime: eng.runtime, Engine: eng.engine,
				Status: models.SandboxStatusStarted, ContainerID: "sb-eng", ContainerIP: "10.0.0.8",
				Lifecycle: models.Lifecycle{RestartOnFailure: true}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			h.event(t, "sb-eng", "die", 2)
			clock.advance(5 * time.Second)
			if arm := clock.last(); arm == nil {
				t.Fatal("no restart scheduled")
			} else {
				arm.fire()
			}
			if row := h.row(t, "sb-eng"); row.Status != models.SandboxStatusStarted || row.StatusReason != models.StatusReasonRestarted {
				t.Fatalf("%s: %q %q", eng.name, row.Status, row.StatusReason)
			}
		})
	}
}

// TestFleetSuspendStopsASandboxWaitingToRestart: a fleet suspend also stops
// a sandbox that would otherwise restart during the suspension.
func TestFleetSuspendStopsASandboxWaitingToRestart(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	h.seedRestarting(t, "sb-fleet", models.Lifecycle{})
	h.event(t, "sb-fleet", "die", 1)
	if err := h.svc.StopByOwner(ctx, ""); err != nil {
		t.Fatal(err)
	}
	row := h.row(t, "sb-fleet")
	if !row.FleetSuspended || row.RestartAt != nil || row.StatusReason != models.StatusReasonUserStop {
		t.Fatalf("suspended=%v restart_at=%v reason=%q", row.FleetSuspended, row.RestartAt, row.StatusReason)
	}
}

// TestRestartTimerBookkeeping covers the timer map's edges: a replaced or
// cancelled timer that fires anyway does nothing, and a timer that fires
// during shutdown does nothing.
func TestRestartTimerBookkeeping(t *testing.T) {
	h := newRestartHarness(t)
	h.seedRestarting(t, "sb-t", models.Lifecycle{})
	h.event(t, "sb-t", "die", 1)
	first := h.clock.last()
	h.svc.armRestart("sb-t", -time.Second) // replaces it; negative waits are now
	if !first.stopped || h.clock.last().delay != 0 {
		t.Fatalf("replace: first stopped=%v, new delay %s", first.stopped, h.clock.last().delay)
	}
	h.clock.advance(time.Minute)
	first.fire() // superseded
	if h.row(t, "sb-t").Status != models.SandboxStatusStopped {
		t.Fatal("a replaced timer restarted the sandbox")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.svc.setRestartBase(ctx)
	h.fire(t)
	if h.row(t, "sb-t").Status != models.SandboxStatusStopped {
		t.Fatal("a timer restarted the sandbox during shutdown")
	}
	h.svc.cancelRestartTimer("sb-t")
	h.svc.cancelRestartTimer("sb-none")
	h.svc.cancelPendingRestart(context.Background(), nil, "")
}

// TestStopFailsWhenItCannotCancelTheRestart: a stop or pause of a sandbox
// waiting to restart after a crash must drop the stored restart. When that
// write fails, the call fails too, so the caller retries; reporting the
// stop while the sweep would start the sandbox again a minute later is
// what this guards against. The retry then holds.
func TestStopFailsWhenItCannotCancelTheRestart(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func(*Service, string) error
	}{
		{"stop", func(s *Service, id string) error { _, err := s.StopSandbox(ctx, id); return err }},
		{"pause", func(s *Service, id string) error { _, err := s.PauseSandbox(ctx, id); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-cancel"
			h.seedRestarting(t, id, models.Lifecycle{})
			h.event(t, id, "die", 1)
			if h.row(t, id).RestartAt == nil {
				t.Fatal("crash scheduled no restart")
			}
			cb96SQL(t, h.path, `CREATE TRIGGER fail_cancel BEFORE UPDATE OF restart_at ON sandboxes WHEN NEW.restart_at IS NULL BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`)
			if err := tc.call(h.svc, id); err == nil {
				t.Fatal("the call reported success with the restart still stored")
			}
			cb96SQL(t, h.path, `DROP TRIGGER fail_cancel`)
			if err := tc.call(h.svc, id); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if row := h.row(t, id); row.RestartAt != nil || row.Status != models.SandboxStatusStopped {
				t.Fatalf("after the retry: status %s, restart_at %v", row.Status, row.RestartAt)
			}
			starts := len(h.rt.startRefs)
			h.clock.advance(time.Hour)
			h.svc.runLifecycleSweep(ctx)
			if len(h.rt.startRefs) != starts {
				t.Fatal("the sweep restarted a sandbox the caller stopped")
			}
		})
	}
}
