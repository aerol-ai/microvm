package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// request_idempotency rows used to live forever: ClaimIdempotentRequest
// reclaims an expired row when the same key comes back, but nothing removed
// the keys that never did. The sweep below runs from the claim path itself —
// at most once per idempotencySweepInterval per process, one bounded batch
// at a time — so the table tracks the live replay window without another
// background loop to start, stop and test.
const (
	idempotencySweepInterval = time.Minute
	idempotencySweepBatch    = 500
)

// ListIdempotentRequests returns one page of a scope's rows in one state,
// after the cursor fingerprint (see the store method). Used by claimers that
// recover outstanding work after a restart; a service with no store
// (embedded wiring) has none.
func (s *Service) ListIdempotentRequests(ctx context.Context, scope, state, afterFingerprint string, limit int) ([]*models.IdempotentRequestRecord, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	return s.store.ListIdempotentRequests(ctx, scope, state, afterFingerprint, limit)
}

// maybeSweepIdempotentRequests deletes one batch of expired rows when the
// interval has passed. The CAS on idempotencySweepAt makes it single-flight
// without a lock, and the sweep runs detached so no claim waits on it. It
// reads the wall clock rather than the claim's now: expiry for collection is
// real time, whatever instant a caller evaluates its own claim at.
//
// The first claim of a process only schedules a sweep, one interval out:
// rows are written at wall-clock time, so nothing a fresh process could
// collect is urgent, and no sweep races the first requests after a start.
func (s *Service) maybeSweepIdempotentRequests() {
	now := time.Now()
	next := s.idempotencySweepAt.Load()
	if next == 0 {
		s.idempotencySweepAt.CompareAndSwap(0, now.Add(idempotencySweepInterval).UnixNano())
		return
	}
	if now.UnixNano() < next {
		return
	}
	if !s.idempotencySweepAt.CompareAndSwap(next, now.Add(idempotencySweepInterval).UnixNano()) {
		return
	}
	go s.sweepIdempotentRequests(now)
}

func (s *Service) sweepIdempotentRequests(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deleted, err := s.store.DeleteExpiredIdempotentRequests(ctx, now, idempotencySweepBatch)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("request idempotency sweep failed", "error", err)
		}
		return
	}
	// Collect deleted-sandbox tombstones past their replay window on the same
	// pass, reusing this single-flight sweep instead of starting another loop.
	tombstoned, err := s.store.DeleteExpiredDeletedSandboxViews(ctx, now.Add(-deletedViewRetention), idempotencySweepBatch)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("deleted sandbox view sweep failed", "error", err)
		}
	}
	if deleted == idempotencySweepBatch || tombstoned == idempotencySweepBatch {
		// A full batch means a backlog (first run after the upgrade, or a
		// burst of expiries): make the sweep due again, so the next claim
		// continues it rather than waiting out a whole interval.
		s.idempotencySweepAt.Store(1)
	}
}

// SetIdempotentRequestTarget stores a pending row's result without moving it
// to ready (see the store method).
func (s *Service) SetIdempotentRequestTarget(ctx context.Context, scope, fingerprint, targetID string) error {
	return s.store.SetIdempotentRequestTarget(ctx, scope, fingerprint, targetID, time.Now())
}
