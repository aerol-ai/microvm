package service

import (
	"context"
	"log/slog"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateArtifactPushStore is the narrow store surface the template
// push reconciler needs. Pulled out as an interface so the reconciler
// is testable without a real SQLite store. Mirrors SnapshotPushStore.
type TemplateArtifactPushStore interface {
	ListTemplatesPendingPush(ctx context.Context) ([]*models.Template, error)
	SetTemplatePushState(ctx context.Context, id, state, errMsg string) error
	UpdateTemplatePushDistribution(ctx context.Context, id, ref, digest string) error
}

// TemplateArtifactPushReconciler walks rows the build success path
// flagged `push_state IN ('pending', 'error')` and re-tries them. One
// ticker per node; fan-out inside a single tick is capped so a
// recovery storm doesn't saturate the local Docker daemon or AOCR.
//
// Like SnapshotPushReconciler, the type does not own a goroutine —
// RunOnce is the unit of work and the ticker lives in main.go. That
// keeps the type fully testable (table-driven, no time.Tick) and lets
// an operator trigger an immediate retry from a debug endpoint.
type TemplateArtifactPushReconciler struct {
	pusher      *TemplateArtifactPusher
	store       TemplateArtifactPushStore
	logger      *slog.Logger
	maxInFlight int
}

// NewTemplateArtifactPushReconciler builds the reconciler. Returns nil
// if the pusher is nil (push disabled) so callers can
// `if r == nil { return }` cheaply. maxInFlight clamps fan-out per
// tick; pass 0 for the safe default (2 — template pushes are even
// heavier than snapshot pushes because the rootfs.ext4 layer can run
// hundreds of MB).
func NewTemplateArtifactPushReconciler(pusher *TemplateArtifactPusher, store TemplateArtifactPushStore, logger *slog.Logger, maxInFlight int) *TemplateArtifactPushReconciler {
	if pusher == nil || store == nil {
		return nil
	}
	if maxInFlight <= 0 {
		maxInFlight = 2
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TemplateArtifactPushReconciler{
		pusher:      pusher,
		store:       store,
		logger:      logger,
		maxInFlight: maxInFlight,
	}
}

// TemplateArtifactPushStats is what RunOnce reports back. Used by
// tests and by the metrics-collection wrapper in main.go (PR 6-E).
type TemplateArtifactPushStats struct {
	Scanned   int
	Succeeded int
	Failed    int
	Skipped   int
}

// RunOnce processes one sweep of the template push-pending queue.
// Blocks until all per-template attempts have returned. The bounded
// semaphore caps in-flight Docker push streams; the AOCR side is
// usually fine with the load but the local daemon's network/IO is not
// infinitely parallel — and a template tar is much larger than a
// snapshot's, so even a small fanout consumes real bandwidth.
func (r *TemplateArtifactPushReconciler) RunOnce(ctx context.Context) (TemplateArtifactPushStats, error) {
	if r == nil {
		return TemplateArtifactPushStats{}, nil
	}
	pending, err := r.store.ListTemplatesPendingPush(ctx)
	if err != nil {
		return TemplateArtifactPushStats{}, err
	}
	// Sample the push-state gauges off the rows we already have. The
	// list is filtered to push_state IN ('pending','error'); partitioning
	// it gives operators a per-state count without a second query.
	gaugeRows := make([]*templatePushGaugeRow, 0, len(pending))
	for _, tpl := range pending {
		gaugeRows = append(gaugeRows, &templatePushGaugeRow{PushState: tpl.PushState})
	}
	recordTemplatePushGauges(gaugeRows)
	stats := TemplateArtifactPushStats{Scanned: len(pending)}
	if len(pending) == 0 {
		return stats, nil
	}

	sem := make(chan struct{}, r.maxInFlight)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, tpl := range pending {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tpl *models.Template) {
			defer wg.Done()
			defer func() { <-sem }()

			outcome := r.pushOne(ctx, tpl)
			mu.Lock()
			switch outcome {
			case templatePushSucceeded:
				stats.Succeeded++
				templatePushSucceededTotal.Add(1)
			case templatePushFailed:
				stats.Failed++
				templatePushFailedTotal.Add(1)
			case templatePushSkipped:
				stats.Skipped++
			}
			mu.Unlock()
		}(tpl)
	}
	wg.Wait()
	return stats, nil
}

type templatePushOutcome int

const (
	templatePushSucceeded templatePushOutcome = iota
	templatePushFailed
	templatePushSkipped
)

// pushOne pushes a single template's artifacts. Errors are logged and
// turned into `templatePushFailed` (the row stays in 'error' for the
// next tick); they are not propagated up because one bad template
// should not abort the whole sweep. Mirrors SnapshotPushReconciler's
// pushOne — the failure-path consistency is the same: row stays in
// 'error' with 'push_error' populated, next tick retries.
func (r *TemplateArtifactPushReconciler) pushOne(ctx context.Context, tpl *models.Template) templatePushOutcome {
	if tpl == nil {
		return templatePushSkipped
	}
	id := tpl.ID

	// Defensive guard: a concurrent reconcile or operator-driven row
	// flip may have moved the template out of 'ready' between the
	// scan and this goroutine running. Pushing a non-ready template
	// (e.g. an `unhealthy` row that someone is about to rebuild) would
	// either propagate corrupt bytes to AOCR or race the rebuild.
	if !TemplateNeedsPush(tpl) {
		// Row is no longer push-eligible (e.g. transitioned to
		// 'unhealthy'). Flip state to active so the reconciler stops
		// picking it up — the rebuild path will re-mark it pending
		// after the successful retry.
		if err := r.store.SetTemplatePushState(ctx, id, models.TemplatePushStateActive, ""); err != nil {
			r.logger.Warn("template push: clear non-ready row failed",
				"template", id, "error", err)
		}
		return templatePushSkipped
	}

	// Claim the row so a concurrent RunOnce won't double-push. Mirrors
	// the snapshot pusher's 'pushing' state machine — the column is
	// the source of truth for "who is working on this".
	if err := r.store.SetTemplatePushState(ctx, id, models.TemplatePushStatePushing, ""); err != nil {
		r.logger.Warn("template push: claim row failed",
			"template", id, "error", err)
		return templatePushFailed
	}

	result, err := r.pusher.PushOnce(ctx, tpl)
	if err != nil {
		if setErr := r.store.SetTemplatePushState(ctx, id, models.TemplatePushStateError, err.Error()); setErr != nil {
			r.logger.Warn("template push: record failure failed",
				"template", id, "error", setErr, "push_error", err)
		}
		r.logger.Warn("template push: failed",
			"template", id, "error", err)
		return templatePushFailed
	}

	// Success — flip the distribution metadata first (so a crash
	// between the two updates leaves the row still discoverable via
	// the registry ref), then clear the push state. Digest may be
	// empty for older daemons; we store "" rather than fabricating.
	if err := r.store.UpdateTemplatePushDistribution(ctx, id, result.RegistryRef, result.Digest); err != nil {
		if setErr := r.store.SetTemplatePushState(ctx, id, models.TemplatePushStateError, err.Error()); setErr != nil {
			r.logger.Warn("template push: record post-success metadata failure failed",
				"template", id, "error", setErr)
		}
		r.logger.Warn("template push: succeeded but metadata update failed",
			"template", id, "error", err)
		return templatePushFailed
	}
	if err := r.store.SetTemplatePushState(ctx, id, models.TemplatePushStateActive, ""); err != nil {
		r.logger.Warn("template push: succeeded but state-clear failed",
			"template", id, "error", err)
		return templatePushFailed
	}
	r.logger.Info("template push: succeeded",
		"template", id, "registry_ref", result.RegistryRef)
	return templatePushSucceeded
}
