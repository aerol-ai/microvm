package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// SnapshotPushStore is the narrow store surface the reconciler needs.
// Pulled out as an interface so the reconciler is testable without a
// real SQLite store and so future store backends can satisfy it
// without growing the reconciler's dependency surface.
//
// A listed row is only a candidate: the reconciler owns a row from the
// claim that matches it to the completion or release fenced by that
// claim's stamp (see internal/store/push_queue.go).
type SnapshotPushStore interface {
	ListSnapshotsPendingPushPage(ctx context.Context, after store.SnapshotPushCursor, limit int) ([]*models.SandboxSnapshot, error)
	ClaimSnapshotPush(ctx context.Context, ownerRef, name string) (*models.SandboxSnapshot, time.Time, bool, error)
	CompleteSnapshotPush(ctx context.Context, ownerRef, name string, claimedAt time.Time, mode, registryRef, digest string) (bool, error)
	ReleaseSnapshotPush(ctx context.Context, ownerRef, name string, claimedAt time.Time, state, errMsg string) (bool, error)
}

// snapshotPushPageSize is how many queued rows one store read returns. A
// sweep reads page after page, so it bounds memory, not the sweep.
const snapshotPushPageSize = 64

// SnapshotPushReconciler pushes the rows the snapshot-create path flagged
// `push_state IN ('pending', 'error')` (and claims whose lease ran out) to
// AOCR. It is the node's one snapshot push worker: Run sweeps on a ticker
// and whenever Kick wakes it, RunOnce never sweeps alongside another
// RunOnce, and maxInFlight bounds the pushes in flight on the node — not per
// sweep — so a recovery storm cannot saturate the local engine or AOCR.
type SnapshotPushReconciler struct {
	pusher      *SnapshotPusher
	store       SnapshotPushStore
	logger      *slog.Logger
	maxInFlight int
	pageSize    int
	// slots holds one token per push in flight on this node.
	slots chan struct{}
	gate  *pushSweepGate
	// testAfterList, when set, runs after every page is listed. Nil in
	// production; tests use it to line two sweeps up on the same rows.
	testAfterList func()
}

// NewSnapshotPushReconciler builds the reconciler. Returns nil if the
// pusher is nil (snapshot push disabled) so callers can
// `if r == nil { return }` cheaply. maxInFlight bounds concurrent pushes
// on the node; pass 0 for the safe default (2 — pushes are I/O-heavy).
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
		pageSize:    snapshotPushPageSize,
		slots:       make(chan struct{}, maxInFlight),
		gate:        newPushSweepGate(),
	}
}

// SnapshotPushReconcileStats is what RunOnce reports back. Used by tests
// and by the daemon's sweep log.
type SnapshotPushReconcileStats struct {
	Scanned   int
	Succeeded int
	Failed    int
	Skipped   int
	// Coalesced is set when RunOnce found a sweep already running and
	// handed its request to that sweep instead of sweeping itself.
	Coalesced bool
}

func (s *SnapshotPushReconcileStats) add(o SnapshotPushReconcileStats) {
	s.Scanned += o.Scanned
	s.Succeeded += o.Succeeded
	s.Failed += o.Failed
	s.Skipped += o.Skipped
}

// Kick wakes the worker started by Run without blocking: the snapshot-create
// path calls it so a fresh row is pushed now rather than on the next tick.
// Safe on a nil or never-run reconciler (the wake-up waits for Run).
func (r *SnapshotPushReconciler) Kick() {
	if r == nil {
		return
	}
	r.gate.kick()
}

// Run is the node's snapshot push worker: it sweeps every interval and on
// every Kick until ctx ends. report, when non-nil, receives every sweep's
// outcome. Start it once per reconciler.
func (r *SnapshotPushReconciler) Run(ctx context.Context, interval time.Duration, report func(SnapshotPushReconcileStats, error)) {
	if r == nil || r.gate == nil {
		return
	}
	runPushWorker(ctx, interval, r.gate.wake, func(ctx context.Context) {
		stats, err := r.RunOnce(ctx)
		if report != nil {
			report(stats, err)
		}
	})
}

// RunOnce sweeps the push queue and blocks until every push it started has
// returned. A call that arrives while another sweep runs does not sweep
// beside it: it asks that sweep to go round once more and returns at once
// (Coalesced), so the rows it came for are still picked up.
func (r *SnapshotPushReconciler) RunOnce(ctx context.Context) (SnapshotPushReconcileStats, error) {
	if r == nil || r.gate == nil {
		return SnapshotPushReconcileStats{}, nil
	}
	if !r.gate.enter() {
		return SnapshotPushReconcileStats{Coalesced: true}, nil
	}
	var total SnapshotPushReconcileStats
	for {
		stats, err := r.sweep(ctx)
		total.add(stats)
		if !r.gate.again(err != nil) {
			return total, err
		}
	}
}

// sweep walks the queue page by page, claiming and pushing each row through
// the node-wide slots. The cursor only moves forward, so a row whose push
// fails in this sweep waits for the next one.
func (r *SnapshotPushReconciler) sweep(ctx context.Context) (SnapshotPushReconcileStats, error) {
	var (
		stats  SnapshotPushReconcileStats
		wg     sync.WaitGroup
		mu     sync.Mutex
		cursor store.SnapshotPushCursor
	)
	for {
		page, err := r.store.ListSnapshotsPendingPushPage(ctx, cursor, r.pageSize)
		if err != nil {
			wg.Wait()
			return stats, err
		}
		if r.testAfterList != nil {
			r.testAfterList()
		}
		for _, snapshot := range page {
			if err := acquirePushSlot(ctx, r.slots); err != nil {
				wg.Wait()
				return stats, err
			}
			mu.Lock()
			stats.Scanned++
			mu.Unlock()
			wg.Add(1)
			go func(snapshot *models.SandboxSnapshot) {
				defer wg.Done()
				defer func() { <-r.slots }()
				outcome := r.pushOne(ctx, snapshot)
				mu.Lock()
				defer mu.Unlock()
				switch outcome {
				case snapshotPushSucceeded:
					stats.Succeeded++
				case snapshotPushFailed:
					stats.Failed++
				case snapshotPushSkipped:
					stats.Skipped++
				}
			}(snapshot)
		}
		if len(page) < r.pageSize {
			wg.Wait()
			return stats, nil
		}
		cursor = store.SnapshotPushCursorAfter(page[len(page)-1])
	}
}

type snapshotPushOutcome int

const (
	snapshotPushSucceeded snapshotPushOutcome = iota
	snapshotPushFailed
	snapshotPushSkipped
)

// pushOne claims and pushes a single snapshot. Errors are logged and turned
// into `snapshotPushFailed` (the row goes to 'error' for the next sweep);
// they are not propagated up because one bad snapshot should not abort the
// whole sweep. The snapshot stays usable on its own node either way.
//
// The row is this call's only between its claim and the completion or
// release fenced by the claim's stamp. A claim that matches nothing (another
// worker has it, or it left the queue) is a skip, not a failure; a fenced
// write that matches nothing means a newer claim took over after the lease
// ran out, or the row was deleted, and this call writes nothing more.
func (r *SnapshotPushReconciler) pushOne(ctx context.Context, listed *models.SandboxSnapshot) snapshotPushOutcome {
	if listed == nil {
		return snapshotPushSkipped
	}
	owner, name := listed.OwnerRef, listed.Name
	snapshot, claimedAt, claimed, err := r.store.ClaimSnapshotPush(ctx, owner, name)
	if err != nil {
		r.logger.Warn("snapshot push: claim row failed", "snapshot", name, "error", err)
		return snapshotPushFailed
	}
	if !claimed {
		return snapshotPushSkipped
	}

	if !SnapshotNeedsPush(snapshot) {
		// Already distributable (e.g. re-registered with a remote ref):
		// nothing to push, so take it out of the queue.
		if _, err := r.store.ReleaseSnapshotPush(ctx, owner, name, claimedAt, models.SnapshotPushStateActive, ""); err != nil {
			r.logger.Warn("snapshot push: clear non-local row failed", "snapshot", name, "error", err)
		}
		return snapshotPushSkipped
	}

	// A push may not outlive its claim: past the lease another worker can
	// take the row and push it again, and this push could only be fenced
	// off. The cap also keeps one hung registry call from holding a slot,
	// and the sweep that waits for it, forever.
	pushCtx, cancel := context.WithTimeout(ctx, store.PushClaimLease)
	result, err := r.pusher.PushOnce(pushCtx, snapshot)
	cancel()
	if err != nil {
		// Persist the error so the operator can see why retries are
		// failing (surfaced via the Daytona facade's errorReason field).
		r.release(ctx, snapshot, claimedAt, err.Error())
		r.logger.Warn("snapshot push: failed", "snapshot", name, "error", err)
		return snapshotPushFailed
	}

	// Distribution metadata and the 'active' state land in one fenced
	// statement. Digest comes from the push stream; a registry that did not
	// report one leaves it "" rather than a fabricated value.
	applied, err := r.store.CompleteSnapshotPush(ctx, owner, name, claimedAt, models.ImageDistributionAOCR, result.RegistryRef, result.Digest)
	if err != nil {
		// Mark error so the next sweep pushes again (same tag, same
		// content) rather than leaving the row 'pushing' until the lease.
		r.release(ctx, snapshot, claimedAt, err.Error())
		r.logger.Warn("snapshot push: succeeded but metadata update failed", "snapshot", name, "error", err)
		return snapshotPushFailed
	}
	if !applied {
		r.logger.Warn("snapshot push: finished after losing its claim; the row's current owner decides",
			"snapshot", name, "registry_ref", result.RegistryRef, "digest", result.Digest)
		return snapshotPushSkipped
	}
	r.logger.Info("snapshot push: succeeded", "snapshot", name, "registry_ref", result.RegistryRef)
	return snapshotPushSucceeded
}

// release moves a claimed row to 'error' with reason, fenced by the claim.
func (r *SnapshotPushReconciler) release(ctx context.Context, snapshot *models.SandboxSnapshot, claimedAt time.Time, reason string) {
	if _, err := r.store.ReleaseSnapshotPush(ctx, snapshot.OwnerRef, snapshot.Name, claimedAt, models.SnapshotPushStateError, reason); err != nil {
		r.logger.Warn("snapshot push: record failure failed", "snapshot", snapshot.Name, "error", err, "push_error", reason)
	}
}
