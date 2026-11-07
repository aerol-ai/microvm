package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/internal/store"
)

// A failed create whose rollback could not finish (plan item C5, invariant
// I8: a create reported as failed leaves nothing once things converge).
//
// A cluster create commits its placement in a promote after the local create
// succeeded. When the promote (or the seal before it) fails because the
// leader is gone (an election), the rollback's destroy needs the same leader
// for its placement fence and fails too, leaving the local row and its
// runtime. Two things then used to turn the failed create into a live,
// billed sandbox: the ownership replay (boot and every reconcile) published
// the leftover row, promoting the reservation or placing it afresh; and
// nothing ever retried the destroy.
//
// So every cluster-create rollback (pkg/api/clustercreate retractFailedPromote,
// retractReservedCreate, RollbackLocalCreate) marks the row rollback-pending
// before it destroys. The
// mark is durable (store column rollback_pending) and only ever set: the
// row's delete ends it. A marked row is never published by the ownership
// replay (assertClusterOwnership), is refused as a create replay
// (ErrCreateRollbackPending), and reconcile retries its destroy every pass
// until it succeeds (reconcileRollbackPending).

// ErrCreateRollbackPending answers a create of an id whose earlier create
// was reported failed and is still being rolled back here: replaying that
// sandbox would hand the client one that reconcile is about to destroy. It is
// an ErrCreateInProgress, so the API answers 503 with Retry-After, and a retry
// after the rollback has finished creates afresh.
var ErrCreateRollbackPending = fmt.Errorf("%w: the previous attempt failed and its rollback has not finished", ErrCreateInProgress)

// MarkRollbackPending records that the create of id was reported failed and
// its rollback has not finished. A cluster create's rollback calls it before
// it destroys, so neither a destroy that fails nor a crash before it can let
// the row be published. A missing row is nothing to roll back, not an error.
func (s *Service) MarkRollbackPending(ctx context.Context, id string) error {
	if s == nil || s.store == nil {
		return nil
	}
	if err := s.store.MarkSandboxRollbackPending(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// reconcileRollbackPending retries the destroy of every row marked
// rollback-pending. A failure (the leader is still away) is logged and the
// next pass retries; a row already gone counts as done. The scan is a partial
// index probe that finds no row in the steady state.
func (s *Service) reconcileRollbackPending(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	ids, err := s.store.ListRollbackPendingIDs(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("rollback-pending sweep: list failed; will retry", "error", err)
		}
		return
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := s.DestroySandbox(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			if s.logger != nil {
				s.logger.Warn("rollback-pending sweep: destroy of a failed create failed; will retry",
					"sandbox_id", id, "error", err)
			}
			continue
		}
		if s.logger != nil {
			s.logger.Info("rollback-pending sweep: destroyed a failed create", "sandbox_id", id)
		}
	}
}
