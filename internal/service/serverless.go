package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stopMode tags every stop with the reason sandboxd is performing it so the
// wake-arming policy can be applied uniformly without each call site
// reinventing the rules. It is intentionally NOT a wire-visible value — the
// public Sandbox model only exposes Lifecycle.Serverless and the internal
// WakeArmed bookkeeping; callers outside the service package never need to
// reason about which mode produced a given stop.
type stopMode int

const (
	// stopModeManual is the operator-initiated stop (API StopSandbox).
	// Manual stops always clear wake_armed: the operator asked the
	// sandbox to be down, so we honor that request even when the
	// sandbox is serverless. The next HTTP request gets the "manually
	// stopped" sentinel from EnsureSandboxAwakeForHTTP instead of an
	// auto-resume.
	stopModeManual stopMode = iota
	// stopModeLifecycle is a sandboxd-driven stop from the lifecycle
	// sweep (idle-timer fired or stop-at-age reached). Arms wake when
	// the sandbox is serverless so the next inbound HTTP request
	// transparently brings it back up.
	stopModeLifecycle
	// stopModeInvoluntary is a Docker-observed stop we did not ask for
	// (process exit, crash, OOM, out-of-band `docker stop`). Arms wake
	// when the sandbox is serverless under the conservative default
	// from the plan: a serverless web app that crashed should restart
	// on the next request, matching the "auto-recovers on traffic"
	// expectation. Hard failure loops are kept in check by the wake
	// circuit breaker, not by refusing to arm here.
	stopModeInvoluntary
)

// expectedStopRecord is the value stored in Service.expectedStops. It pairs
// the mode with the time we recorded the expectation so a janitor can
// reap entries that never produce a Docker event (Docker daemon went away
// mid-stop, network blip on the events stream, etc.). At sweep time any
// entry older than expectedStopMaxAge is silently dropped — the
// corresponding event, if it ever arrives late, then gets treated as
// involuntary, which is the safe default.
type expectedStopRecord struct {
	mode      stopMode
	recordedAt time.Time
}

// expectedStopMaxAge bounds how long an expectation lives without a
// matching Docker event. 5 minutes is comfortably longer than any
// realistic Docker stop (default grace is 10s) but short enough that a
// stale entry can't shield a future involuntary exit from being armed.
const expectedStopMaxAge = 5 * time.Minute

// recordExpectedStop notes that sandboxd is about to issue a stop for id
// with the given mode. The matching die/stop/oom event is then consumed
// by consumeExpectedStop in the events handler. Safe to call concurrently
// — entries with the same id silently overwrite, which is the right
// behavior for retries that issue a fresh stop.
func (s *Service) recordExpectedStop(id string, mode stopMode) {
	s.expectedStopsMu.Lock()
	defer s.expectedStopsMu.Unlock()
	if s.expectedStops == nil {
		s.expectedStops = make(map[string]expectedStopRecord)
	}
	s.expectedStops[id] = expectedStopRecord{mode: mode, recordedAt: time.Now()}
}

// consumeExpectedStop returns the mode recorded by recordExpectedStop and
// removes the entry. If no expectation was recorded (or the entry has
// aged out), it returns stopModeInvoluntary so the caller treats the
// event as an unplanned exit.
func (s *Service) consumeExpectedStop(id string) stopMode {
	s.expectedStopsMu.Lock()
	defer s.expectedStopsMu.Unlock()
	rec, ok := s.expectedStops[id]
	if !ok {
		return stopModeInvoluntary
	}
	delete(s.expectedStops, id)
	if time.Since(rec.recordedAt) > expectedStopMaxAge {
		return stopModeInvoluntary
	}
	return rec.mode
}

// stopSandboxInternal is the single code path for stopping a sandbox row.
// All wake-arming policy lives here so manual / lifecycle / recreate
// callers cannot drift apart on whether wake gets set or cleared.
//
// Wake arming rules (D5 in plans/serverless-sandbox-http-wake.md):
//   - mode=stopModeManual → wake_armed cleared. Operator wants the
//     sandbox down; an HTTP request must NOT silently bring it back.
//   - mode=stopModeLifecycle + Lifecycle.Serverless → wake_armed set.
//     This is the cold-start path: the idle timer hit, drop the
//     container, but next request resurrects it.
//   - mode=stopModeLifecycle + !Lifecycle.Serverless → wake_armed
//     cleared. Lifecycle stop on a non-serverless sandbox is final.
//   - cfg.EnableServerless=false → wake_armed cleared regardless of
//     mode. The rollout gate must produce identical behavior to the
//     pre-feature codebase.
//
// Ordering (D5): we set wake_armed in the store BEFORE removing the
// Caddy route in the wake-arming case, so a request that lands between
// docker.Stop and DeleteSandboxRoute hits the wake-aware proxy with
// wake_armed=true already visible. For non-wake stops the legacy
// caddy-first ordering is preserved.
//
// recordExpectedStop must be called before docker.Stop so the events
// handler does not race the stop and classify it as involuntary.
func (s *Service) stopSandboxInternal(ctx context.Context, id string, mode stopMode) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	arm := s.shouldArmWake(sandbox, mode)
	s.recordExpectedStop(id, mode)

	if err := s.docker.Stop(ctx, sandboxContainerRef(sandbox)); err != nil {
		// Stop failed → drop the expectation so a later involuntary
		// exit is correctly classified rather than masked.
		s.consumeExpectedStop(id)
		return nil, err
	}

	// Release the admitter slot now that the container is no longer running.
	// A stopped sandbox holds no CPU/RAM on the host; keeping the reservation
	// would let the host budget run out even though nothing is consuming it,
	// and admins routinely use Stop+Start to free capacity for new work.
	// StartSandbox re-Admits on the way back up. Release is idempotent so a
	// concurrent die event running the same path is safe.
	if s.admitter != nil {
		s.admitter.Release(id)
	}
	if err := s.mounts.UnmountAll(id); err != nil {
		s.logger.Warn("unmount on stop failed", "sandbox_id", id, "error", err)
	}

	if arm {
		// Wake-arming order: store first, then caddy. A request landing
		// between docker.Stop and DeleteSandboxRoute now sees
		// wake_armed=true and is funneled through the wake helper
		// rather than 502'ing against a dead upstream IP.
		if err := s.store.SetWakeArmed(ctx, id, true); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("arm wake on stop failed", "sandbox_id", id, "error", err)
		}
	} else {
		// Non-wake stops should clear any stale arming (a previous
		// lifecycle stop may have armed and the operator is now
		// manually stopping; we must honor the operator's intent).
		if err := s.store.SetWakeArmed(ctx, id, false); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("clear wake on stop failed", "sandbox_id", id, "error", err)
		}
	}

	// Drop the Caddy routes while the container is down so requests hit the
	// fallback "sandbox not found" handler instead of a 502 from a stale
	// upstream IP. StartSandbox re-upserts every route on the way back up.
	for _, port := range sandbox.ExposedPorts {
		if err := s.deleteExposedPortRoute(ctx, sandbox, port); err != nil {
			s.logger.Warn("caddy port route cleanup on stop failed", "sandbox_id", id, "port", port.Port, "protocol", port.Protocol, "error", err)
		}
	}
	if err := s.caddy.DeleteSandboxRoute(ctx, sandbox.ID); err != nil {
		s.logger.Warn("caddy route cleanup on stop failed", "sandbox_id", id, "error", err)
	}

	sandbox.Status = models.SandboxStatusStopped
	sandbox.WakeArmed = arm
	sandbox.UpdatedAt = time.Now().UTC()
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return sandbox, nil
}

// shouldArmWake centralizes the wake-arming decision so the runtime stop
// path and the events path apply identical rules. cfg.EnableServerless
// is the rollout gate: when off, no sandbox arms wake regardless of the
// per-sandbox flag, so an operator can disable the feature host-wide
// without rewriting every Lifecycle row.
func (s *Service) shouldArmWake(sandbox *models.Sandbox, mode stopMode) bool {
	if sandbox == nil || mode == stopModeManual {
		return false
	}
	if !s.cfg.EnableServerless {
		return false
	}
	if !sandbox.Lifecycle.Serverless {
		return false
	}
	return true
}

// classifyDockerStopEvent maps a Docker die/stop/oom event to the stop
// mode that should drive wake arming. OOM is treated as involuntary
// even when sandboxd issued the stop: an OOM-kill mid-stop means the
// kernel reaped the container, not the operator. Otherwise we trust
// the expected-stop bookkeeping populated by stopSandboxInternal.
func (s *Service) classifyDockerStopEvent(id string, event docker.DockerEvent) stopMode {
	if event.Action == "oom" {
		// Drop any expectation so the slot is freed for a retry.
		s.expectedStopsMu.Lock()
		delete(s.expectedStops, id)
		s.expectedStopsMu.Unlock()
		return stopModeInvoluntary
	}
	return s.consumeExpectedStop(id)
}

// ErrSandboxManuallyStopped is returned by the wake helper when the
// sandbox was stopped via the manual StopSandbox path. Surfaces 409
// at the control-plane proxy so the caller knows to call StartSandbox
// explicitly instead of triggering an implicit resume.
var ErrSandboxManuallyStopped = errors.New("sandbox manually stopped (do not wake)")

// ErrWakeCircuitOpen is returned when the per-sandbox wake breaker is
// tripped (D3). Surfaces 503 + Retry-After: 60 at the control-plane
// proxy so a sandbox stuck in a cold-start failure loop does not
// thrash StartSandbox on every request for the full open window.
var ErrWakeCircuitOpen = errors.New("wake circuit open")

// Wake circuit-breaker policy (D3 in plans/serverless-sandbox-http-wake.md):
//
//	wakeFailureThreshold consecutive wake failures inside
//	wakeFailureWindow trip the breaker, which then stays open for
//	wakeCircuitOpenFor. The window is sliding-on-first-failure:
//	failures separated by more than wakeFailureWindow reset the
//	counter so a slow drip of transient errors over hours does not
//	open the circuit. wakeStartTimeout bounds how long we hold the
//	caller waiting on StartSandbox before surfacing a timeout (D6:
//	15s, hardcoded — no SB_HTTP_WAKE_TIMEOUT knob).
const (
	wakeFailureThreshold = 5
	wakeFailureWindow    = 60 * time.Second
	wakeCircuitOpenFor   = 60 * time.Second
	wakeStartTimeout     = 15 * time.Second
)

// wakeFlight is the per-sandbox single-flight + breaker record stored
// in Service.wakeFlights. The mutex serializes wake attempts for one
// sandbox so a burst of concurrent HTTP requests produces one
// StartSandbox call. The breaker fields are protected by the same
// mutex — every wake attempt that mutates them already holds it.
type wakeFlight struct {
	mu             sync.Mutex
	failures       int
	firstFailureAt time.Time
	openUntil      time.Time
	gaugeHeld      bool
}

// wakeFlightFor returns (and lazily creates) the wakeFlight for id.
// The returned pointer is stable for the lifetime of the daemon —
// callers may safely cache it across calls and lock it directly.
func (s *Service) wakeFlightFor(id string) *wakeFlight {
	s.wakeFlightsMu.Lock()
	defer s.wakeFlightsMu.Unlock()
	if s.wakeFlights == nil {
		s.wakeFlights = make(map[string]*wakeFlight)
	}
	w, ok := s.wakeFlights[id]
	if !ok {
		w = &wakeFlight{}
		s.wakeFlights[id] = w
	}
	return w
}

// EnsureSandboxAwakeForHTTP is the single chokepoint the control-plane
// HTTP proxies (v1 toolbox, daytona toolbox, e2b runtime) call before
// resolving the toolbox endpoint. It returns the current sandbox row
// so the caller can route to ContainerIP without re-fetching.
//
// Behavior:
//   - sandbox started → fast-path return (no lock, no metric latency
//     observation; only a requests_total tick).
//   - sandbox stopped + (gate off OR Lifecycle.Serverless=false OR
//     WakeArmed=false) → ErrSandboxManuallyStopped. The proxy maps
//     this to 409 so the SDK can explicitly call StartSandbox.
//   - sandbox stopped + eligible to wake → take the per-sandbox
//     wake lock, recheck under the lock (a concurrent flight may have
//     finished), enforce the circuit breaker, then call StartSandbox
//     with a 15s budget. On admission failure or start error the
//     breaker counter advances; 5 failures inside 60s trip it for
//     60s. Success resets the counter.
//
// Same single-flight pattern as EnsureLayer4Ready, but per-sandbox:
// the wave of HTTP requests waking the same sandbox collapses to one
// StartSandbox; waves to different sandboxes proceed concurrently.
func (s *Service) EnsureSandboxAwakeForHTTP(ctx context.Context, id string) (*models.Sandbox, error) {
	finish := beginWakeMetric()
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		finish(false, err)
		return nil, err
	}
	if sandbox.Status == models.SandboxStatusStarted {
		finish(false, nil)
		return sandbox, nil
	}

	// Gate / opt-in checks. The wake helper is wired into every
	// control-plane proxy, so when the rollout gate is off OR the
	// sandbox is not serverless we MUST be transparent — return the
	// row as-is and let the caller's existing ToolboxTarget handle a
	// stopped sandbox the way it always did. Anything else would
	// change error semantics for non-serverless callers, violating
	// the rollout-gate contract.
	if sandbox.Status != models.SandboxStatusStopped {
		finish(false, nil)
		return sandbox, nil
	}
	if !s.cfg.EnableServerless || !sandbox.Lifecycle.Serverless {
		finish(false, nil)
		return sandbox, nil
	}
	// Stopped serverless sandbox: WakeArmed=false means the operator
	// (or a non-armed involuntary classifier) explicitly disarmed
	// wake. Refuse to auto-resume; the caller surfaces 409.
	if !sandbox.WakeArmed {
		finish(false, ErrSandboxManuallyStopped)
		return nil, ErrSandboxManuallyStopped
	}

	flight := s.wakeFlightFor(id)
	flight.mu.Lock()
	defer flight.mu.Unlock()

	if !flight.allowAttempt(time.Now()) {
		finish(false, ErrWakeCircuitOpen)
		return nil, ErrWakeCircuitOpen
	}

	// Re-read under the lock: a concurrent wake may have just finished
	// (status=started, wake_armed cleared) and we don't want to spend a
	// cold-start budget on a sandbox that is already up.
	sandbox, err = s.store.Get(ctx, id)
	if err != nil {
		finish(false, err)
		return nil, err
	}
	if sandbox.Status == models.SandboxStatusStarted {
		finish(false, nil)
		return sandbox, nil
	}

	startCtx, cancel := context.WithTimeout(ctx, wakeStartTimeout)
	defer cancel()
	started, startErr := s.StartSandbox(startCtx, id)
	if startErr != nil {
		flight.recordFailure(time.Now())
		finish(true, startErr)
		return nil, startErr
	}
	flight.recordSuccess()
	finish(true, nil)
	return started, nil
}

// allowAttempt returns false when the breaker is open at now and
// drops the open flag (decrementing the gauge) the moment the open
// window has elapsed so the next call gets a real attempt. Must be
// called with flight.mu held.
func (w *wakeFlight) allowAttempt(now time.Time) bool {
	if w.openUntil.IsZero() {
		return true
	}
	if now.Before(w.openUntil) {
		return false
	}
	// Window elapsed. Drop the gauge and clear breaker state so the
	// next attempt starts with a fresh failure counter.
	w.openUntil = time.Time{}
	w.failures = 0
	w.firstFailureAt = time.Time{}
	if w.gaugeHeld {
		wakeCircuitOpen.Add(-1)
		w.gaugeHeld = false
	}
	return true
}

// recordFailure advances the breaker after a failed wake attempt.
// Sliding-on-first-failure window: failures more than
// wakeFailureWindow apart restart the counter rather than
// accumulating across hours of transient blips. Must be called with
// flight.mu held.
func (w *wakeFlight) recordFailure(now time.Time) {
	if w.firstFailureAt.IsZero() || now.Sub(w.firstFailureAt) > wakeFailureWindow {
		w.failures = 1
		w.firstFailureAt = now
		return
	}
	w.failures++
	if w.failures >= wakeFailureThreshold && w.openUntil.IsZero() {
		w.openUntil = now.Add(wakeCircuitOpenFor)
		if !w.gaugeHeld {
			wakeCircuitOpen.Add(1)
			w.gaugeHeld = true
		}
	}
}

// recordSuccess clears the breaker after a successful wake. The
// gauge is dropped if it was held — successful wake closes any
// previously-open breaker even mid-window. Must be called with
// flight.mu held.
func (w *wakeFlight) recordSuccess() {
	w.failures = 0
	w.firstFailureAt = time.Time{}
	w.openUntil = time.Time{}
	if w.gaugeHeld {
		wakeCircuitOpen.Add(-1)
		w.gaugeHeld = false
	}
}

// formatStopAuditFields returns the structured slog fields the audit
// log emits on every stop. Centralized so manual / lifecycle / event
// paths all emit the same shape and downstream log queries don't need
// per-path special-casing.
func formatStopAuditFields(id string, mode stopMode, armed bool) []any {
	return []any{
		"sandbox_id", id,
		"stop_mode", mode.String(),
		"wake_armed", armed,
	}
}

func (m stopMode) String() string {
	switch m {
	case stopModeManual:
		return "manual"
	case stopModeLifecycle:
		return "lifecycle"
	case stopModeInvoluntary:
		return "involuntary"
	default:
		return fmt.Sprintf("stopMode(%d)", int(m))
	}
}
