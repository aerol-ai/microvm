package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// leftoverInstanceError says a runtime instance holds the sandbox ID while
// no row does, and this create holds the ID's create lease. Nothing live
// can own it then: another create of the ID on this node would hold the
// lease, and a finished one would have a row. Only a failed earlier create
// of the ID can have left it, typically one whose client hung up while the
// engine was creating the container (Docker's /containers/create and
// containerd's NewContainer finish the container after the caller has gone,
// so the driver never learns its ID and cannot undo it). An Idempotency-Key
// retry derives the same ID and used to meet that container as a 409
// "sandbox already exists" until the orphan sweep came by (UC-450 live,
// 2026-11-06, on both engines). It still reads as ErrSandboxExists, so a
// caller that does not remove the leftover answers as before.
type leftoverInstanceError struct {
	rt      runtime.Runtime
	runtime string
	engine  string
	cause   error
}

func (e *leftoverInstanceError) Error() string {
	return fmt.Sprintf("%v: a failed earlier create of this id left its runtime instance (%v)", models.ErrSandboxExists, e.cause)
}

func (e *leftoverInstanceError) Unwrap() error { return models.ErrSandboxExists }

// asLeftoverInstance turns the ErrSandboxExists a runtime create's name
// collision ended in into a leftoverInstanceError when the instance can only
// be a failed create's leftover: this create holds the ID's lease and the
// store has no row for it. Any other error, or a lookup that fails, is
// returned as it was.
func (s *Service) asLeftoverInstance(ctx context.Context, err error, rt runtime.Runtime, sandboxID, runtimeName, engine string) error {
	if rt == nil || !errors.Is(err, models.ErrSandboxExists) || !holdsCreateLease(ctx, sandboxID) {
		return err
	}
	if _, getErr := s.store.Get(ctx, sandboxID); !errors.Is(getErr, store.ErrNotFound) {
		return err
	}
	return &leftoverInstanceError{rt: rt, runtime: runtimeName, engine: engine, cause: err}
}

// removeLeftoverInstance destroys a failed create's leftover instance the way
// the orphan sweep would (removeOrphans), runtime state only: the Caddy route
// and the mounts under this ID belong to the create that found it. It reads
// the instance first, for its address, so the runtime clears the rules and
// the gateway attach keyed by it.
func (s *Service) removeLeftoverInstance(ctx context.Context, sandboxID string, e *leftoverInstanceError) error {
	stub := &models.Sandbox{ID: sandboxID, ContainerID: sandboxID, Runtime: e.runtime, Engine: e.engine}
	if state, err := e.rt.Inspect(ctx, sandboxID); err == nil && state != nil {
		if state.ContainerID != "" {
			stub.ContainerID = state.ContainerID
		}
		stub.ContainerIP = state.ContainerIP
	}
	if s.logger != nil {
		s.logger.Warn("create: removing a failed earlier create's leftover instance, then creating again",
			"sandbox_id", sandboxID, "runtime", e.runtime, "engine", e.engine, "container_id", stub.ContainerID)
	}
	return e.rt.Destroy(s.gatewayReleaserCtx(ctx, stub, true), stub)
}
