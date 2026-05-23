package service

import (
	"context"
	"log/slog"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

// SnapshotPushStore is the narrow store surface the reconciler needs.
// Pulled out as an interface so the reconciler is testable without a
// real SQLite store and so future store backends can satisfy it
// without growing the reconciler's dependency surface.
type SnapshotPushStore interface {
	ListSnapshotsPendingPush(ctx context.Context) ([]*models.SandboxSnapshot, error)
	SetSnapshotPushState(ctx context.Context, name, state, errMsg string) error
	UpdateSnapshotImageDistribution(ctx context.Context, name, mode, registryRef, digest string) error
}

// SnapshotPushReconciler walks rows the snapshot-create path flagged
// `push_state IN ('pending', 'error')` and re-tries them. One ticker
// per node; fan-out inside a single tick is capped to keep a recovery
// storm from saturating the local Docker daemon or AOCR.
//
// Like AutoImportReconciler, the type does not own a goroutine — RunOnce
// is the unit of work and the ticker lives in main.go. That keeps the
// type fully testable (table-driven, no time.Tick) and lets an operator
// trigger an immediate retry from a debug endpoint if they want.
type SnapshotPushReconciler struct {
	pusher      *SnapshotPusher
	store       SnapshotPushStore
	logger      *slog.Logger
	maxInFlight int
}

// NewSnapshotPushReconciler builds the reconciler. Returns nil if the
// pusher is nil (snapshot push disabled) so callers can
// `if r == nil { return }` cheaply. maxInFlight clamps fan-out per
// tick; pass 0 for the safe default (2 — pushes are I/O-heavy).
func NewSnapshotPushReconciler(pusher *SnapshotPusher, store SnapshotPushStore, logger *slog.Logger, maxInFlight int) *SnapshotPushReconciler {
	if pusher == nil || store == nil {
		return nil
	}
	if maxInFlight <= 0 {
		maxInFlight = 2
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SnapshotPushReconciler{
		pusher:      pusher,
		store:       store,
		logger:      logger,
		maxInFlight: maxInFlight,
	}
}

// SnapshotPushReconcileStats is what RunOnce reports back. Used by tests
// and by the metrics-collection wrapper in main.go.
type SnapshotPushReconcileStats struct {
	Scanned   int
	Succeeded int
	Failed    int
	Skipped   int
}

// RunOnce processes one sweep of the push-pending queue. Blocks until
// all per-snapshot attempts have returned (success, failure, or context
// cancel). The bounded semaphore caps in-flight Docker push streams;
// the AOCR side is usually fine with the load but the local daemon's
// network/IO is not infinitely parallel.
func (r *SnapshotPushReconciler) RunOnce(ctx context.Context) (SnapshotPushReconcileStats, error) {
	if r == nil {
		return SnapshotPushReconcileStats{}, nil
	}
	pending, err := r.store.ListSnapshotsPendingPush(ctx)
	if err != nil {
		return SnapshotPushReconcileStats{}, err
	}
	stats := SnapshotPushReconcileStats{Scanned: len(pending)}
	if len(pending) == 0 {
		return stats, nil
	}

	sem := make(chan struct{}, r.maxInFlight)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, snapshot := range pending {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(snapshot *models.SandboxSnapshot) {
			defer wg.Done()
			defer func() { <-sem }()

			outcome := r.pushOne(ctx, snapshot)
			mu.Lock()
			switch outcome {
			case snapshotPushSucceeded:
				stats.Succeeded++
			case snapshotPushFailed:
				stats.Failed++
			case snapshotPushSkipped:
				stats.Skipped++
			}
			mu.Unlock()
		}(snapshot)
	}
	wg.Wait()
	return stats, nil
}

type snapshotPushOutcome int

const (
	snapshotPushSucceeded snapshotPushOutcome = iota
	snapshotPushFailed
	snapshotPushSkipped
)

// pushOne pushes a single snapshot. Errors are logged and turned into
// `snapshotPushFailed` (the row stays in 'error' for the next tick);
// they are not propagated up because one bad snapshot should not abort
// the whole sweep. The retry is best-effort by design — the snapshot
// is still usable on the originating node either way.
func (r *SnapshotPushReconciler) pushOne(ctx context.Context, snapshot *models.SandboxSnapshot) snapshotPushOutcome {
	if snapshot == nil {
		return snapshotPushSkipped
	}
	name := snapshot.Name

	// Defensive guard: a concurrent reconcile (or operator-cleared row)
	// may have moved the snapshot to a terminal state between the scan
	// and this goroutine running. The 'pushing' state is the visible
	// signal that someone has claimed this row.
	if !SnapshotNeedsPush(snapshot) {
		// Already non-local (e.g. someone re-registered with a remote ref).
		// Treat as already-distributed; flip state to active so the
		// reconciler stops picking it up.
		if err := r.store.SetSnapshotPushState(ctx, name, models.SnapshotPushStateActive, ""); err != nil {
			r.logger.Warn("snapshot push: clear non-local row failed",
				"snapshot", name, "error", err)
		}
		return snapshotPushSkipped
	}

	// Move to 'pushing' so a concurrent RunOnce won't double-claim. This
	// is the moral equivalent of the AutoImporter's flag-clear-before-call:
	// state machine guards against duplicate work.
	if err := r.store.SetSnapshotPushState(ctx, name, models.SnapshotPushStatePushing, ""); err != nil {
		r.logger.Warn("snapshot push: claim row failed",
			"snapshot", name, "error", err)
		return snapshotPushFailed
	}

	result, err := r.pusher.PushOnce(ctx, snapshot)
	if err != nil {
		// Persist the error so the operator can see why retries are
		// failing (surfaced via the Daytona facade's errorReason field).
		if setErr := r.store.SetSnapshotPushState(ctx, name, models.SnapshotPushStateError, err.Error()); setErr != nil {
			r.logger.Warn("snapshot push: record failure failed",
				"snapshot", name, "error", setErr, "push_error", err)
		}
		r.logger.Warn("snapshot push: failed",
			"snapshot", name, "error", err)
		return snapshotPushFailed
	}

	// Success — flip the distribution metadata first (so a crash between
	// the two updates leaves the row still reachable by `aocr` mode), then
	// clear the push state. Digest is empty for now — the Docker push API
	// does not surface RepoDigests without an extra Inspect call; the
	// ImageVerifiedAt timestamp written below is enough to prove the push
	// completed for downstream consumers.
	if err := r.store.UpdateSnapshotImageDistribution(ctx, name, models.ImageDistributionAOCR, result.RegistryRef, ""); err != nil {
		// Mark error so we re-attempt next tick rather than silently leaving
		// the row in 'pushing' forever.
		if setErr := r.store.SetSnapshotPushState(ctx, name, models.SnapshotPushStateError, err.Error()); setErr != nil {
			r.logger.Warn("snapshot push: record post-success metadata failure failed",
				"snapshot", name, "error", setErr)
		}
		r.logger.Warn("snapshot push: succeeded but metadata update failed",
			"snapshot", name, "error", err)
		return snapshotPushFailed
	}
	if err := r.store.SetSnapshotPushState(ctx, name, models.SnapshotPushStateActive, ""); err != nil {
		r.logger.Warn("snapshot push: succeeded but state-clear failed",
			"snapshot", name, "error", err)
		return snapshotPushFailed
	}
	r.logger.Info("snapshot push: succeeded",
		"snapshot", name, "registry_ref", result.RegistryRef)
	return snapshotPushSucceeded
}
