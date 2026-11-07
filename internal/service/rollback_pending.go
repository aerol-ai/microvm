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
// before it destroys. The mark is durable (store column rollback_pending) and
// only ever set: the row's delete ends it. A marked row is never published by
// the ownership replay (assertClusterOwnership) and never handed back as a
// create replay. Two things finish its destroy, both through
// finishRollbackPending: reconcile, every pass until it succeeds
// (reconcileRollbackPending), and a retry of the same create, once, when it
// finds the row (FinishRollbackPending); the retry then creates afresh, or
// answers ErrCreateRollbackPending when the destroy still cannot finish.
//
// The two can meet on one row. Both act only under the row's lifecycle lock
// and only while the row they read under it is still marked, so the first
// destroys it and the second finds it gone; and a sweep holding a list read
// before a retry finished the rollback and created afresh finds the new row
// unmarked and leaves it alone.

// ErrCreateRollbackPending answers a create of an id whose earlier create
// was reported failed and whose rollback could not be finished now either:
// replaying that sandbox would hand the client one that is about to be
// destroyed. It is an ErrCreateInProgress, so the API answers 503 with
// Retry-After, and a retry after the rollback has finished creates afresh.
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
		if s.testBeforeRollbackSweepDestroy != nil {
			s.testBeforeRollbackSweepDestroy(id)
		}
		if err := s.finishRollbackPending(ctx, id); err != nil {
			if s.logger != nil {
				s.logger.Warn("rollback-pending sweep: destroy of a failed create failed; will retry",
					"sandbox_id", id, "error", err)
			}
			continue
		}
		if s.logger != nil {
			s.logger.Info("rollback-pending sweep: failed create rolled back", "sandbox_id", id)
		}
	}
}

// FinishRollbackPending makes one attempt, for a retry of a create that found
// its earlier attempt's row marked, to run that attempt's pending destroy.
// nil means nothing of it is left and the retry may create afresh; otherwise
// the error is an ErrCreateRollbackPending and the row stays marked for
// reconcile. The caller holds the id's create lease, so no create of the id
// can run meanwhile. The attempt is bounded by createRollbackTimeout, the
// budget a create's own rollback gets; each control-plane call inside it is
// bounded by the destroy path's own timeouts.
func (s *Service) FinishRollbackPending(ctx context.Context, id string) error {
	rbCtx, cancel := context.WithTimeout(ctx, createRollbackTimeout)
	defer cancel()
	if err := s.finishRollbackPending(rbCtx, id); err != nil {
		return fmt.Errorf("%w: %v", ErrCreateRollbackPending, err)
	}
	return nil
}

// finishRollbackPending destroys id if, under its lifecycle lock, its row is
// still marked rollback-pending. A row that is gone, or that is no longer
// marked (a retry finished the rollback and created afresh), is done. It is
// the one place the reconcile sweep and create retries finish a rollback.
func (s *Service) finishRollbackPending(ctx context.Context, id string) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	row, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !row.RollbackPending {
		return nil
	}
	if err := s.destroySandboxLocked(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
