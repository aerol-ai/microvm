package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateArtifactPushStore is the narrow store surface the template
// push reconciler needs. Pulled out as an interface so the reconciler
// is testable without a real SQLite store. Mirrors SnapshotPushStore.
//
// Like the snapshot queue, a listed row is only a candidate: the reconciler
// owns a template from the claim that matches it to the completion or
// release fenced by that claim's stamp (internal/store/push_queue.go).
type TemplateArtifactPushStore interface {
	ListTemplatesPendingPush(ctx context.Context) ([]*models.Template, error)
	ClaimTemplatePush(ctx context.Context, id string) (*models.Template, time.Time, bool, error)
	CompleteTemplatePush(ctx context.Context, id string, claimedAt time.Time, registryRef, digest string) (bool, error)
	ReleaseTemplatePush(ctx context.Context, id string, claimedAt time.Time, state, errMsg string) (bool, error)
	ScheduleSnapshotRegistryRetirement(ctx context.Context, r store.SnapshotRegistryRetirement) error
}

// TemplatePushStore wraps the raw store the push reconciler writes through so
// every push-metadata change also invalidates the replicated catalogue.
//
// The reconciler is wired independently of the Service and writes
// RegistryRef, PushDigest and PushState straight to SQLite. Those fields are
// part of the row the catalogue publishes, so without this seam a successful
// push left the fleet-visible DTO saying "pending" with an empty registry
// reference — and nothing marked the kind dirty, so no maintenance pass ever
// repaired it. Wrapping the STORE rather than adding a callback means a
// future writer on this path is covered by construction.
func (s *Service) TemplatePushStore(inner TemplateArtifactPushStore) TemplateArtifactPushStore {
	if s == nil || inner == nil {
		return inner
	}
	return &templatePushStoreSeam{inner: inner, svc: s}
}

type templatePushStoreSeam struct {
	inner TemplateArtifactPushStore
	svc   *Service
}

func (t *templatePushStoreSeam) ListTemplatesPendingPush(ctx context.Context) ([]*models.Template, error) {
	return t.inner.ListTemplatesPendingPush(ctx)
}

func (t *templatePushStoreSeam) ClaimTemplatePush(ctx context.Context, id string) (*models.Template, time.Time, bool, error) {
	tpl, claimedAt, ok, err := t.inner.ClaimTemplatePush(ctx, id)
	if ok {
		t.svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	}
	return tpl, claimedAt, ok, err
}

func (t *templatePushStoreSeam) CompleteTemplatePush(ctx context.Context, id string, claimedAt time.Time, registryRef, digest string) (bool, error) {
	applied, err := t.inner.CompleteTemplatePush(ctx, id, claimedAt, registryRef, digest)
	if applied {
		t.svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	}
	return applied, err
}

func (t *templatePushStoreSeam) ScheduleSnapshotRegistryRetirement(ctx context.Context, r store.SnapshotRegistryRetirement) error {
	return t.inner.ScheduleSnapshotRegistryRetirement(ctx, r)
}

func (t *templatePushStoreSeam) ReleaseTemplatePush(ctx context.Context, id string, claimedAt time.Time, state, errMsg string) (bool, error) {
	applied, err := t.inner.ReleaseTemplatePush(ctx, id, claimedAt, state, errMsg)
	if applied {
		t.svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	}
	return applied, err
}

// TemplateArtifactPushReconciler walks rows the build success path
// flagged `push_state IN ('pending', 'error')` and re-tries them. Like
// SnapshotPushReconciler it is the node's one template push worker: Run
// sweeps on a ticker and on Kick, sweeps never overlap, and maxInFlight
// bounds the pushes in flight on the node, so a recovery storm doesn't
// saturate the local Docker daemon or AOCR.
type TemplateArtifactPushReconciler struct {
	pusher      *TemplateArtifactPusher
	store       TemplateArtifactPushStore
	logger      *slog.Logger
	maxInFlight int
	slots       chan struct{}
	gate        *pushSweepGate
	// testAfterList, when set, runs after the queue is listed. Nil in
	// production.
	testAfterList func()
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
		slots:       make(chan struct{}, maxInFlight),
		gate:        newPushSweepGate(),
	}
}

// TemplateArtifactPushStats is what RunOnce reports back. Used by
// tests and by the metrics-collection wrapper in main.go (PR 6-E).
type TemplateArtifactPushStats struct {
	Scanned   int
	Succeeded int
	Failed    int
	Skipped   int
	// Coalesced: a sweep was already running and took this request over.
	Coalesced bool
}

func (s *TemplateArtifactPushStats) add(o TemplateArtifactPushStats) {
	s.Scanned += o.Scanned
	s.Succeeded += o.Succeeded
	s.Failed += o.Failed
	s.Skipped += o.Skipped
}

// Kick wakes the worker started by Run without blocking; the build path
// calls it once a template is marked for push.
func (r *TemplateArtifactPushReconciler) Kick() {
	if r == nil {
		return
	}
	r.gate.kick()
}

// Run is the node's template push worker: a sweep every interval and on
// every Kick until ctx ends. report, when non-nil, receives each outcome.
func (r *TemplateArtifactPushReconciler) Run(ctx context.Context, interval time.Duration, report func(TemplateArtifactPushStats, error)) {
	if r == nil || r.gate == nil {
		return
	}
	runPushWorker(ctx, interval, r.gate.wake, func(ctx context.Context) {
		stats, err := r.RunOnce(ctx)
		if report != nil && !cutShortByShutdown(ctx, err) {
			report(stats, err)
		}
	})
}

// RunOnce sweeps the template push queue and blocks until every push it
// started has returned. A call that arrives while another sweep runs asks
// that sweep to go round once more and returns at once (Coalesced) instead
// of sweeping beside it. Templates are few per node, so the queue is read
// in one go rather than paged.
func (r *TemplateArtifactPushReconciler) RunOnce(ctx context.Context) (TemplateArtifactPushStats, error) {
	if r == nil || r.gate == nil {
		return TemplateArtifactPushStats{}, nil
	}
	if !r.gate.enter() {
		return TemplateArtifactPushStats{Coalesced: true}, nil
	}
	var total TemplateArtifactPushStats
	for {
		stats, err := r.sweep(ctx)
		total.add(stats)
		if !r.gate.again(err != nil) {
			return total, err
		}
	}
}

func (r *TemplateArtifactPushReconciler) sweep(ctx context.Context) (TemplateArtifactPushStats, error) {
	pending, err := r.store.ListTemplatesPendingPush(ctx)
	if err != nil {
		return TemplateArtifactPushStats{}, err
	}
	if r.testAfterList != nil {
		r.testAfterList()
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

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, tpl := range pending {
		if err := acquirePushSlot(ctx, r.slots); err != nil {
			wg.Wait()
			return stats, err
		}
		wg.Add(1)
		go func(tpl *models.Template) {
			defer wg.Done()
			defer func() { <-r.slots }()

			outcome := r.pushOne(ctx, tpl)
			mu.Lock()
			defer mu.Unlock()
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

// pushOne claims and pushes a single template's artifacts. Errors are
// logged and turned into `templatePushFailed` (the row goes to 'error' for
// the next sweep); they are not propagated up because one bad template
// should not abort the whole sweep. As for snapshots, the row is this call's
// only between its claim and the write fenced by the claim's stamp.
func (r *TemplateArtifactPushReconciler) pushOne(ctx context.Context, listed *models.Template) templatePushOutcome {
	if listed == nil {
		return templatePushSkipped
	}
	id := listed.ID
	tpl, claimedAt, claimed, err := r.store.ClaimTemplatePush(ctx, id)
	if err != nil {
		r.logger.Warn("template push: claim row failed", "template", id, "error", err)
		return templatePushFailed
	}
	if !claimed {
		return templatePushSkipped
	}

	// Defensive guard: the template may have left 'ready' between the
	// scan and the claim. Pushing a non-ready template (e.g. an
	// `unhealthy` row that someone is about to rebuild) would either
	// propagate corrupt bytes to AOCR or race the rebuild; take it out of
	// the queue instead — the rebuild path re-marks it pending.
	if !TemplateNeedsPush(tpl) {
		if _, err := r.store.ReleaseTemplatePush(ctx, id, claimedAt, models.TemplatePushStateActive, ""); err != nil {
			r.logger.Warn("template push: clear non-ready row failed", "template", id, "error", err)
		}
		return templatePushSkipped
	}

	// Capped at the claim's lease, as for snapshots: past it the push
	// could only be fenced off, and a hung call must not hold its slot.
	pushCtx, cancel := context.WithTimeout(ctx, store.PushClaimLease)
	result, err := r.pusher.PushOnce(pushCtx, tpl)
	cancel()
	if err != nil {
		r.release(ctx, id, claimedAt, err.Error())
		r.logger.Warn("template push: failed", "template", id, "error", err)
		return templatePushFailed
	}

	// Registry ref, digest and 'active' land in one fenced statement, so
	// the pull side never sees a ref without its state or the reverse.
	// Digest may be empty for older daemons; we store "" rather than
	// fabricating.
	applied, err := r.store.CompleteTemplatePush(ctx, id, claimedAt, result.RegistryRef, result.Digest)
	if err != nil {
		r.release(ctx, id, claimedAt, err.Error())
		r.logger.Warn("template push: succeeded but metadata update failed", "template", id, "error", err)
		return templatePushFailed
	}
	if !applied {
		// A newer claim owns the row, or the row was deleted while this
		// push ran, and then nothing will ever name the copy just pushed.
		// Either way it is recorded for retirement, as for snapshots: the
		// worker drops the obligation if a row names this manifest, and
		// waits while this template still has a push to land.
		if err := r.store.ScheduleSnapshotRegistryRetirement(ctx, store.SnapshotRegistryRetirement{
			RegistryRef: result.RegistryRef, Digest: result.Digest, Name: id,
		}); err != nil {
			r.logger.Warn("template push: record retirement of an unclaimed push failed",
				"template", id, "registry_ref", result.RegistryRef, "error", err)
		}
		r.logger.Warn("template push: finished after losing its claim; its copy is scheduled for retirement",
			"template", id, "registry_ref", result.RegistryRef, "digest", result.Digest)
		return templatePushSkipped
	}
	r.logger.Info("template push: succeeded", "template", id, "registry_ref", result.RegistryRef)
	return templatePushSucceeded
}

// release moves a claimed template to 'error' with reason, fenced by the claim.
func (r *TemplateArtifactPushReconciler) release(ctx context.Context, id string, claimedAt time.Time, reason string) {
	if _, err := r.store.ReleaseTemplatePush(ctx, id, claimedAt, models.TemplatePushStateError, reason); err != nil {
		r.logger.Warn("template push: record failure failed", "template", id, "error", err, "push_error", reason)
	}
}
