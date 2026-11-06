package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Restart on failure (plans/agent-sandbox-feature-parity.md L1; owner row
// P4). A sandbox with lifecycle.restart_on_failure is started again after a
// crash or an OOM kill of its init, as the die event reports them. The wait
// doubles from 5 s up to 5 min, and goes back to 5 s once the sandbox has run
// for 10 minutes since its last restart.
//
// Only Docker and containerd (gVisor included) send the die events this
// hangs off (pkg/daemon/container_engine_wiring.go); Firecracker, WASM and
// isolate refuse the option at create and on a lifecycle update. Firecracker
// needs a VMM-exit event source that also covers adopted VMMs first.
//
// The backoff state lives in the store (restart_failures, restart_at,
// last_restarted_at), not only in memory, so it survives a daemon restart: a
// crash-looping sandbox on a node whose daemon also restarts keeps backing
// off instead of restarting at full speed after every daemon restart. The
// in-memory timer is the fast path; the one-minute lifecycle sweep arms any
// pending restart that has no timer (the case after a daemon restart), so a
// due restart runs at most a minute late.
//
// It never fights:
//   - a stop someone asked for: the expected-stop record makes its die event
//     a user_stop (not a crash), and a stop or pause of a sandbox already
//     waiting to restart cancels the restart (cancelPendingRestart). The
//     check, the start and the cancel all run inside the lifecycle boundary
//     (lifecycle_boundary.go), so a stop that comes while a restart is
//     starting the sandbox waits for it and then stops it;
//   - a start: StartSandbox cancels a pending restart;
//   - the idle and age timers: a restart does not count as activity
//     (LastActiveAt is kept), and a restart that comes due after a stop or
//     destroy timer has run out is dropped, leaving that timer to act;
//   - the OOM record: out_of_memory is a failure like a crash, and the restart
//     keeps last_error and the exit code (status_reason "restarted");
//   - a destroy: the row is gone, and destroy paths drop the timer.
const (
	restartBackoffInitial = 5 * time.Second
	restartBackoffMax     = 5 * time.Minute
	restartResetAfter     = 10 * time.Minute
	// restartStartTimeout bounds one restart: a start does not pull an
	// image, so a minute is plenty, and a stuck engine must not pin the
	// timer goroutine forever.
	restartStartTimeout = 2 * time.Minute
)

// systemActionRestart is the audit record of a restart on failure: a start
// the daemon did on its own, caller system:lifecycle.
const systemActionRestart = "lifecycle.restart_on_failure"

// restartBackoff is the wait before the restart that follows the nth
// consecutive failure: 5 s, 10 s, 20 s, ... capped at 5 min.
func restartBackoff(failures int) time.Duration {
	d := restartBackoffInitial
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= restartBackoffMax {
			return restartBackoffMax
		}
	}
	return d
}

// restartOnFailureRuntimeSupported reports whether a runtime's sandboxes can
// restart on failure: the ones whose engine reports die events. An empty
// runtime is a pre-migration row on the host default, which is a container
// runtime (config refuses firecracker, wasm and isolate as the default).
func restartOnFailureRuntimeSupported(runtime string) bool {
	switch runtime {
	case models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate:
		return false
	}
	return true
}

// validateLifecycleRuntime refuses the lifecycle options a runtime cannot
// honour, so a create or update fails with a clear 400 instead of storing a
// promise nothing keeps.
func validateLifecycleRuntime(l models.Lifecycle, runtime string) error {
	if l.RestartOnFailure && !restartOnFailureRuntimeSupported(runtime) {
		return fmt.Errorf("invalid lifecycle: restart_on_failure is not supported on runtime %q; only docker, gvisor and containerd sandboxes restart on failure", runtime)
	}
	return validateLifecycleExitRuntime(l, runtime)
}

// isRestartFailureReason reports whether a stop reason is a failure restart
// on failure answers.
func isRestartFailureReason(reason string) bool {
	return reason == models.StatusReasonCrashed || reason == models.StatusReasonOutOfMemory
}

// restartPending reports whether sb is stopped, waiting for a restart on
// failure.
func restartPending(sb *models.Sandbox) bool {
	return sb != nil && sb.Status == models.SandboxStatusStopped && sb.RestartAt != nil &&
		sb.Lifecycle.RestartOnFailure && isRestartFailureReason(sb.StatusReason)
}

// restartTimer is the part of *time.Timer the restart code uses; a seam so
// tests drive restarts without waiting.
type restartTimer interface{ Stop() bool }

type restartTimerEntry struct {
	timer restartTimer
	gen   uint64
}

func (s *Service) restartNow() time.Time {
	if s.restartClock != nil {
		return s.restartClock()
	}
	return time.Now().UTC()
}

func (s *Service) restartAfter(d time.Duration, f func()) restartTimer {
	if s.restartAfterFunc != nil {
		return s.restartAfterFunc(d, f)
	}
	return time.AfterFunc(d, f)
}

// setRestartBase records the daemon context restarts run under, so a timer
// that fires during shutdown does nothing.
func (s *Service) setRestartBase(ctx context.Context) {
	s.restartMu.Lock()
	s.restartBase = ctx
	s.restartMu.Unlock()
}

// armRestart (re)arms id's restart timer to fire after delay, replacing any
// timer it had. The generation lets a timer that already fired tell it was
// replaced.
func (s *Service) armRestart(id string, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	if s.restartTimers == nil {
		s.restartTimers = make(map[string]restartTimerEntry)
	}
	if old, ok := s.restartTimers[id]; ok {
		old.timer.Stop()
	}
	s.restartGen++
	gen := s.restartGen
	s.restartTimers[id] = restartTimerEntry{gen: gen, timer: s.restartAfter(delay, func() { s.runScheduledRestart(id, gen) })}
}

// ensureRestartArmed arms a timer for a pending restart that has none: the
// sweep's backstop after a daemon restart lost the in-memory timers.
func (s *Service) ensureRestartArmed(sb *models.Sandbox) {
	s.restartMu.Lock()
	_, armed := s.restartTimers[sb.ID]
	s.restartMu.Unlock()
	if armed {
		return
	}
	s.armRestart(sb.ID, sb.RestartAt.Sub(s.restartNow()))
}

// cancelRestartTimer drops id's timer, if any.
func (s *Service) cancelRestartTimer(id string) {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	if entry, ok := s.restartTimers[id]; ok {
		entry.timer.Stop()
		delete(s.restartTimers, id)
	}
}

// takeRestartTimer removes id's timer entry if gen is still the current one,
// and returns the context the restart runs under; ok is false for a timer
// that was replaced or cancelled after it fired.
func (s *Service) takeRestartTimer(id string, gen uint64) (context.Context, bool) {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	entry, ok := s.restartTimers[id]
	if !ok || entry.gen != gen {
		return nil, false
	}
	delete(s.restartTimers, id)
	base := s.restartBase
	if base == nil {
		base = context.Background()
	}
	return base, true
}

// scheduleRestartAfterFailure runs after the die event recorded a stop, in
// the same hold of the lifecycle boundary (handleDockerEvent), so no stop,
// pause or start can come between the crash's record and its restart. It
// schedules a restart when the stored row (re-read, so a duplicate event or
// a stop that won the race cannot schedule one) is a failure of a sandbox
// that asked for restarts.
func (s *Service) scheduleRestartAfterFailure(ctx context.Context, id string) {
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return
	}
	if sb.Status != models.SandboxStatusStopped || !sb.Lifecycle.RestartOnFailure ||
		!isRestartFailureReason(sb.StatusReason) || !restartOnFailureRuntimeSupported(sb.Runtime) {
		return
	}
	now := s.restartNow()
	if sb.RestartAt != nil && sb.RestartAt.After(now) {
		// Already scheduled for this stop (a second event for one exit).
		s.ensureRestartArmed(sb)
		return
	}
	failures := sb.RestartFailures
	if sb.LastRestartedAt == nil || now.Sub(*sb.LastRestartedAt) >= restartResetAfter {
		failures = 0
	}
	failures++
	delay := restartBackoff(failures)
	if err := s.store.ScheduleRestart(ctx, id, failures, now.Add(delay)); err != nil {
		s.logger.Warn("restart on failure: not scheduled", "sandbox_id", id, "error", err)
		return
	}
	s.armRestart(id, delay)
	s.logger.Info("restart on failure scheduled", "sandbox_id", id, "reason", sb.StatusReason,
		"failures", failures, "delay", delay.String())
}

// runScheduledRestart is the timer callback.
func (s *Service) runScheduledRestart(id string, gen uint64) {
	base, ok := s.takeRestartTimer(id, gen)
	if !ok || base.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(withAuditSubsystem(base, auditSubsystemLifecycle), restartStartTimeout)
	defer cancel()
	s.restartIfDue(ctx, id)
}

// restartIfDue restarts id if its restart is still pending and due. It holds
// the lifecycle boundary (lifecycle_boundary.go) from the check through the
// start and its record, so no start, stop, pause, resume, destroy or
// lifecycle update of the same sandbox can come between them (review 2
// finding 9). Before, start, stop and destroy took no lock: a stop that came
// while this was inside the runtime start succeeded, cancelled the stored
// restart, and then this wrote "started" over it.
//
// The checks, after the boundary is held:
//   - right before the start: the restart is still pending (status stopped
//     after a crash or OOM kill, restart_at set). Any stop, pause or start
//     that got the boundary first cancelled it, and a destroy removed the
//     row, so nothing is started.
//   - right after the start: the sandbox is still started before the row
//     says "restarted". A die event can still land meanwhile (events wait
//     for the boundary only around their own record); then the crash's
//     record stays, and that event schedules the next restart once this
//     returns.
//
// A stop that comes while this holds the boundary waits for it, then stops
// the restarted sandbox: the stop always has the last word. A wait that
// outlasts ctx gives up; the sweep arms the restart again.
func (s *Service) restartIfDue(ctx context.Context, id string) {
	unlock, err := s.lifecycleLocks.lock(ctx, id)
	if err != nil {
		s.logger.Warn("restart on failure: lifecycle busy; the sweep retries", "sandbox_id", id, "error", err)
		return
	}
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if err != nil || !restartPending(sb) || !restartOnFailureRuntimeSupported(sb.Runtime) {
		return
	}
	now := s.restartNow()
	if sb.RestartAt.After(now) {
		s.armRestart(id, sb.RestartAt.Sub(now))
		return
	}
	// Timers win: a stop or destroy timer that has already run out would
	// stop or delete the sandbox on the next sweep, so starting it now only
	// fights that timer. Judged as if it were running, since that is what a
	// restart would make it.
	running := *sb
	running.Status = models.SandboxStatusStarted
	if action, _ := lifecycleDecision(&running, now, s.cfg.IdleTimeout(), time.Time{}); action != lifecycleNone {
		if err := s.store.CancelRestart(ctx, id, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("restart on failure: cancel after a timer ran out", "sandbox_id", id, "error", err)
		}
		s.logger.Info("restart on failure skipped: a lifecycle timer has run out", "sandbox_id", id)
		return
	}

	// The record says what it answered: the crash or the OOM kill.
	done := s.beginSystemActionReason(ctx, id, systemActionRestart, sb.StatusReason)
	_, err = s.startSandboxLocked(ctx, id, startForRestart)
	done(err)
	if err != nil {
		s.retryRestartAfterError(ctx, id, err)
		return
	}
	// The restart ran: the next failure's backoff counts from now.
	if err := s.store.MarkRestarted(ctx, id, now); err != nil {
		s.logger.Warn("restart on failure: restart not recorded", "sandbox_id", id, "error", err)
	}
	// The start cleared the crash's reason with the status change; say why
	// the sandbox is running, keeping the crash's exit code. Only while it
	// still runs: a sandbox that died again at once keeps that die's record.
	set, err := s.store.SetStatusReasonIfStatus(ctx, id, models.SandboxStatusStarted, models.StatusReasonRestarted, sb.ExitCode)
	if err != nil {
		s.logger.Warn("restart on failure: reason not recorded", "sandbox_id", id, "error", err)
	} else if !set {
		s.logger.Info("restart on failure: stopped again right after the restart", "sandbox_id", id)
		return
	}
	s.logger.Info("audit restart on failure", "sandbox_id", id, "failures", sb.RestartFailures)
}

// retryRestartAfterError backs off again after a restart that did not start
// the sandbox. A start that left it stopped (no capacity, a transient engine
// error) is retried with the next wait; one that marked it error stops the
// cycle: that needs a person.
func (s *Service) retryRestartAfterError(ctx context.Context, id string, startErr error) {
	sb, err := s.store.Get(ctx, id)
	if err != nil || !restartPending(sb) {
		s.logger.Warn("restart on failure: start failed; not retrying", "sandbox_id", id, "error", startErr)
		return
	}
	failures := sb.RestartFailures + 1
	delay := restartBackoff(failures)
	if err := s.store.ScheduleRestart(ctx, id, failures, s.restartNow().Add(delay)); err != nil {
		s.logger.Warn("restart on failure: retry not scheduled", "sandbox_id", id, "error", err)
		return
	}
	s.armRestart(id, delay)
	s.logger.Warn("restart on failure: start failed; retrying", "sandbox_id", id, "error", startErr, "delay", delay.String())
}

// cancelPendingRestart drops a pending restart because someone stopped,
// paused or started the sandbox. reason replaces the crash's reason on a
// sandbox that was waiting stopped (so it reads user_stop, not crashed);
// "" keeps the reason. A no-op for a sandbox that never asked for restarts.
func (s *Service) cancelPendingRestart(ctx context.Context, sb *models.Sandbox, reason string) error {
	if sb == nil || !sb.Lifecycle.RestartOnFailure {
		return nil
	}
	s.cancelRestartTimer(sb.ID)
	if err := s.store.CancelRestart(ctx, sb.ID, reason); err != nil && !errors.Is(err, store.ErrNotFound) {
		// The timer is gone, but the stored restart_at would let the
		// sweep start the sandbox again within a minute. A stop or pause
		// returns this so its caller retries; a start only logs it.
		s.logger.Warn("restart on failure: cancel failed", "sandbox_id", sb.ID, "error", err)
		return fmt.Errorf("cancel the pending restart on failure: %w", err)
	}
	return nil
}
