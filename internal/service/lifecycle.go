package service

import (
	"context"
	"errors"
	"fmt"

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

// PauseSandbox stops a running sandbox under the per-sandbox lifecycle lock so
// the state check and the stop are one critical section. An already-stopped
// sandbox is a no-op (a retried pause is idempotent); any other state is
// ErrSandboxNotRunning. This is the single definition of "can this be paused"
// the E2B pause and Runloop suspend handlers used to each carry (D7).
func (s *Service) PauseSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	unlock := s.lifecycleLocks.lock(id)
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	switch sandbox.Status {
	case models.SandboxStatusStopped:
		return sandbox, nil
	case models.SandboxStatusStarted:
		return s.stopSandboxInternal(ctx, id, stopModeManual)
	default:
		return nil, ErrSandboxNotRunning
	}
}

// ResumeSandbox starts a stopped sandbox under the per-sandbox lifecycle lock.
// An already-started sandbox is a no-op (a retried resume is idempotent); any
// other state is ErrSandboxNotResumable. This is the single definition of "can
// this be resumed" the E2B connect and Runloop resume handlers used to each
// carry (D7).
func (s *Service) ResumeSandbox(ctx context.Context, id string) (*models.Sandbox, error) {
	unlock := s.lifecycleLocks.lock(id)
	defer unlock()
	sandbox, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	switch sandbox.Status {
	case models.SandboxStatusStarted:
		return sandbox, nil
	case models.SandboxStatusStopped:
		return s.StartSandbox(ctx, id)
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
	unlock := s.lifecycleLocks.lock(id)
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
	if err := s.validateLifecycle(desired); err != nil {
		return nil, false, fmt.Errorf("invalid lifecycle: %w", err)
	}
	return s.writeLifecycleLocked(ctx, id, desired, sandbox)
}
