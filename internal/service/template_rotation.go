package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateRotationStoreAdapter wraps the real *store.Store into the
// narrow TemplateRotationStore interface the reconciler uses. Lives in
// this package so the rotation reconciler has zero dependencies on
// internal/store at the type-level (the adapter is a one-method shim;
// the rest of the file stays unit-testable with a fake).
type TemplateRotationStoreAdapter struct {
	Store templateReadyBeforeQuerier
}

// templateReadyBeforeQuerier is the slice of *store.Store the adapter
// needs. Named so callers can spell out exactly which methods the
// adapter touches; *store.Store satisfies it via its
// ListTemplatesReadyBefore method.
type templateReadyBeforeQuerier interface {
	ListTemplatesReadyBefore(ctx context.Context, cutoff time.Time) ([]*models.Template, error)
}

// ListTemplatesReadyBefore satisfies TemplateRotationStore by mapping
// the *models.Template rows the store returns into the minimal
// candidate shape the reconciler consumes.
func (a *TemplateRotationStoreAdapter) ListTemplatesReadyBefore(ctx context.Context, cutoff time.Time) ([]*templateRotationCandidate, error) {
	if a == nil || a.Store == nil {
		return nil, errors.New("TemplateRotationStoreAdapter: store is required")
	}
	rows, err := a.Store.ListTemplatesReadyBefore(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	out := make([]*templateRotationCandidate, 0, len(rows))
	for _, tpl := range rows {
		if tpl == nil {
			continue
		}
		ready := time.Time{}
		if tpl.ReadyAt != nil {
			ready = *tpl.ReadyAt
		}
		out = append(out, &templateRotationCandidate{ID: tpl.ID, ReadyAt: ready})
	}
	return out, nil
}

// TemplateRotationStore is the narrow store surface the rotation
// reconciler needs. Mirrors TemplateArtifactPushStore in shape so the
// reconciler is testable without a real SQLite store, and so a future
// refactor that splits store responsibilities along sub-interfaces
// doesn't have to revisit this file.
type TemplateRotationStore interface {
	// ListTemplatesReadyBefore returns templates with status='ready'
	// and ready_at older than cutoff. The reconciler is the only caller.
	ListTemplatesReadyBefore(ctx context.Context, cutoff time.Time) ([]*templateRotationCandidate, error)
}

// templateRotationCandidate is the minimal view of a Template the
// rotation path needs. The reconciler hands IDs to MarkTemplateUnhealthy;
// no other column matters. Local struct (not pkg/models.Template) so the
// fake in template_rotation_test.go doesn't have to carry the full row.
type templateRotationCandidate struct {
	ID      string
	ReadyAt time.Time
}

// TemplateRotationConfig pins the operator-tunable knobs the reconciler
// reads. Cached on the struct rather than re-read off cfg every tick so
// a config rewrite under a live reconciler doesn't change MaxAge
// mid-sweep. (Production has no config-rewrite path; this is defensive.)
type TemplateRotationConfig struct {
	Interval time.Duration
	MaxAge   time.Duration
}

// IsEnabled returns true when both knobs are non-zero. Rotation is
// opt-in (Phase 6 PR-E); a daemon that sets Interval but leaves MaxAge
// zero would tick forever and find nothing — main.go warns at boot.
func (c TemplateRotationConfig) IsEnabled() bool {
	return c.Interval > 0 && c.MaxAge > 0
}

// TemplateRotationReconciler walks `ready` templates whose ready_at is
// older than MaxAge and re-kicks the snapshot rebuild via
// MarkSnapshotCorrupt(reason="rotation"). That re-uses the Phase 6 PR-A
// rebuild pipeline — same CAS, same gauge accounting, same
// recordTemplateUnhealthyGauge transitions — so rotation does not need
// its own rebuild plumbing.
//
// Like the other reconcilers in this package, the type does not own a
// goroutine. RunOnce is the unit of work; the ticker lives in main.go.
// That keeps the type fully unit-testable and lets an operator trigger
// an immediate rotation sweep from a debug endpoint (future).
type TemplateRotationReconciler struct {
	cfg    TemplateRotationConfig
	store  TemplateRotationStore
	marker rotationMarker
	logger *slog.Logger
	now    func() time.Time
}

// rotationMarker is the seam the reconciler uses to trigger rebuilds.
// Production wires this to (*Service).MarkSnapshotCorrupt; tests stub
// it to count invocations without depending on a real Service.
type rotationMarker interface {
	MarkSnapshotCorrupt(ctx context.Context, templateID, reason string) error
}

// NewTemplateRotationReconciler builds the reconciler. Returns nil if
// rotation is disabled so callers can `if r == nil { return }` cheaply.
// store/marker must both be non-nil when rotation is enabled.
func NewTemplateRotationReconciler(cfg TemplateRotationConfig, store TemplateRotationStore, marker rotationMarker, logger *slog.Logger) (*TemplateRotationReconciler, error) {
	if !cfg.IsEnabled() {
		return nil, nil
	}
	if store == nil {
		return nil, errors.New("TemplateRotationReconciler: store is required")
	}
	if marker == nil {
		return nil, errors.New("TemplateRotationReconciler: marker is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TemplateRotationReconciler{
		cfg:    cfg,
		store:  store,
		marker: marker,
		logger: logger,
		now:    time.Now,
	}, nil
}

// TemplateRotationStats is what RunOnce reports. Used by tests and by
// the metrics-aware ticker wrapper in main.go.
type TemplateRotationStats struct {
	Scanned int
	Marked  int
	Skipped int
}

// RunOnce processes a single rotation sweep. Each stale `ready` row is
// passed through MarkSnapshotCorrupt, whose CAS gates the transition —
// rows that another path already flipped to unhealthy are skipped
// without error. Unbounded fanout would be unsafe (every rebuild ties
// up a Firecracker VMM slot for the snapshot capture) so this method
// iterates serially; rotation is opt-in and not latency-sensitive, so
// "one rebuild kicked per tick" is fine.
//
// Failure modes:
//   - store.ListTemplatesReadyBefore failure: returned to the caller;
//     the ticker wrapper logs and waits for the next tick.
//   - MarkSnapshotCorrupt failure on an individual row: logged, stats
//     count it as skipped, the sweep continues with the next row. One
//     bad row should not abort the whole sweep.
func (r *TemplateRotationReconciler) RunOnce(ctx context.Context) (TemplateRotationStats, error) {
	if r == nil {
		return TemplateRotationStats{}, nil
	}
	cutoff := r.now().Add(-r.cfg.MaxAge)
	candidates, err := r.store.ListTemplatesReadyBefore(ctx, cutoff)
	if err != nil {
		return TemplateRotationStats{}, err
	}
	stats := TemplateRotationStats{Scanned: len(candidates)}
	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if cand == nil || cand.ID == "" {
			stats.Skipped++
			continue
		}
		// MarkSnapshotCorrupt is idempotent (CAS-gated). reason="rotation"
		// is what surfaces in audit logs and in the row's snapshot_error
		// column — operators can grep for rotation-driven rebuilds vs
		// corruption-driven ones.
		if err := r.marker.MarkSnapshotCorrupt(ctx, cand.ID, "rotation"); err != nil {
			if r.logger != nil {
				r.logger.Warn("template rotation: mark unhealthy failed",
					"template_id", cand.ID, "ready_at", cand.ReadyAt, "error", err)
			}
			stats.Skipped++
			continue
		}
		stats.Marked++
		if r.logger != nil {
			r.logger.Info("audit template rotation kicked",
				"template_id", cand.ID, "ready_at", cand.ReadyAt,
				"age", r.now().Sub(cand.ReadyAt).Truncate(time.Minute),
				"reason", "rotation")
		}
	}
	return stats, nil
}
