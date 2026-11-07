package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Lifecycle state-transition errors. A facade words them for its own SDK
// (apihttp.Classify maps both to 409); the sentinels are the precondition a
// pause/resume could not meet, decided once here instead of in each facade
// (D7).
var (
	// ErrSandboxNotRunning is returned by PauseSandbox when the sandbox is in
	// a state that cannot be paused (anything but started or already stopped).
	ErrSandboxNotRunning = errors.New("sandbox is not running")
	// ErrSandboxNotResumable is returned by ResumeSandbox when the sandbox is
	// in a state that cannot be resumed (anything but stopped or already
	// started).
	ErrSandboxNotResumable = errors.New("sandbox is not resumable")
)

// PauseSandbox stops a running sandbox inside the lifecycle boundary
// (lifecycle_boundary.go) so the state check and the stop are one critical
// section. An already-stopped
// sandbox is a no-op (a retried pause is idempotent); any other state is
// ErrSandboxNotRunning. This is the single definition of "can this be paused"
// the E2B pause and Runloop suspend handlers used to each carry (D7).
func (s *Service) PauseSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	switch sandbox.Status {
	case models.SandboxStatusStopped:
		// Already down, but maybe waiting for a restart on failure: a pause
		// means stay down.
		if restartPending(sandbox) {
			if err := s.cancelPendingRestart(ctx, sandbox, models.StatusReasonUserStop); err != nil {
				return nil, err
			}
			return s.scopedGet(ctx, id)
		}
		return sandbox, nil
	case models.SandboxStatusStarted:
		return s.stopSandboxLocked(ctx, id, stopModeManual, defaultStopReason(stopModeManual))
	default:
		return nil, ErrSandboxNotRunning
	}
}

// ResumeSandbox starts a stopped sandbox inside the lifecycle boundary.
// An already-started sandbox is a no-op (a retried resume is idempotent); any
// other state is ErrSandboxNotResumable. This is the single definition of "can
// this be resumed" the E2B connect and Runloop resume handlers used to each
// carry (D7).
func (s *Service) ResumeSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	switch sandbox.Status {
	case models.SandboxStatusStarted:
		return sandbox, nil
	case models.SandboxStatusStopped:
		return s.startSandboxLocked(ctx, id, startRequested)
	default:
		return nil, ErrSandboxNotResumable
	}
}

// ApplyLifecyclePatch atomically reads the sandbox under the per-sandbox
// lifecycle lock, lets patch compute the desired Lifecycle from the current
// state, and writes it back. patch returns the desired Lifecycle and whether
// anything changed — returning (_, false, nil) leaves the sandbox untouched
// (the E2B reconnect rule that never shortens a longer timeout). This replaces
// the facades' own read→mutate→UpdateLifecycle, whose window raced: two field
// patches on the same sandbox could each read the same base and the later
// write would drop the earlier field (D7).
func (s *Service) ApplyLifecyclePatch(ctx context.Context, id string, patch func(*models.Sandbox) (models.Lifecycle, bool, error)) (*models.Sandbox, bool, error) {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return nil, false, err
	}
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, false, err
	}
	desired, changed, err := patch(sandbox)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return sandbox, false, nil
	}
	if err := resolveLifecycleUpdate(&desired, sandbox); err != nil {
		return nil, false, err
	}
	if err := s.validateLifecycle(desired); err != nil {
		return nil, false, fmt.Errorf("invalid lifecycle: %w", err)
	}
	if err := validateLifecycleRuntime(desired, s.sandboxRuntime(sandbox)); err != nil {
		return nil, false, err
	}
	return s.writeLifecycleLocked(ctx, id, desired, sandbox)
}

// withDefaultLifecycle applies the server's default destroy timers
// (SB_DEFAULT_DESTROY_IF_IDLE_FOR, SB_MAX_AGE; plans/agent-sandbox-feature-
// parity.md L4) to a create that sets no lifecycle timers of its own, the
// same condition SB_IDLE_TIMEOUT_MIN uses. A sandbox with any timer of its
// own keeps exactly its own: the defaults never destroy it.
//
// The defaults are written into the new sandbox's lifecycle, not applied at
// sweep time like SB_IDLE_TIMEOUT_MIN, so a caller sees them on GET and can
// change them, and turning them on never reaches sandboxes created before:
// setting SB_MAX_AGE cannot delete every old sandbox on the next sweep.
// Because a written lifecycle is no longer "no timers", the legacy idle stop
// would stop applying; it is written alongside when it comes first, so a
// server that has both keeps both. Pure: no I/O on the create path.
func (s *Service) withDefaultLifecycle(l *models.Lifecycle) *models.Lifecycle {
	idle, age := s.cfg.DefaultDestroyIfIdleFor, s.cfg.MaxAge
	if (idle <= 0 && age <= 0) || (l != nil && !l.IsZero()) {
		return l
	}
	out := models.Lifecycle{}
	if l != nil {
		// Only non-timer fields can be set here (restart_on_failure).
		out = *l
	}
	out.DestroyIfIdleFor, out.DestroyAtAge = idle, age
	if g := s.cfg.IdleTimeout(); g > 0 && g <= models.MaxLifecycleDuration && (idle <= 0 || g <= idle) {
		out.StopIfIdleFor = g
	}
	return &out
}

// NormalizeCreateLifecycle turns a create's lifecycle.destroy_at (L6) into
// destroy_at_age, measured from now, the sandbox's creation. It runs where
// a create request enters: createSandbox, and the cluster create paths
// before they record the replicated spec, so the spec only ever carries the
// age. It works on a copy: the caller's request struct is not changed
// behind its back. A past time, or destroy_at with destroy_at_age, is a 400.
func NormalizeCreateLifecycle(req *models.CreateSandboxRequest, now time.Time) error {
	if req == nil || req.Lifecycle == nil || req.Lifecycle.DestroyAt == nil {
		return nil
	}
	l := *req.Lifecycle
	if err := l.ResolveDestroyAt(now, now); err != nil {
		return fmt.Errorf("invalid lifecycle: %w", err)
	}
	req.Lifecycle = &l
	return nil
}

// resolveLifecycleUpdate turns an update's destroy_at into destroy_at_age
// from the sandbox's own creation time.
func resolveLifecycleUpdate(l *models.Lifecycle, sb *models.Sandbox) error {
	if err := l.ResolveDestroyAt(sb.CreatedAt, time.Now().UTC()); err != nil {
		return fmt.Errorf("invalid lifecycle: %w", err)
	}
	return nil
}
