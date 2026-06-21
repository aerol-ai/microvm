package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// VolumeReclaimer deletes the backend bytes of a deleted platform volume. The
// concrete implementation (pkg/volumes.Reclaimer) shells out to the AWS CLI / a
// transient NFS mount; the interface keeps the service offline-testable.
type VolumeReclaimer interface {
	Reclaim(ctx context.Context, backendKind, source string) error
}

// SetVolumeReclaimer installs the backend reclaimer. Called once during daemon
// wiring before the worker starts; nil disables byte reclaim.
func (s *Service) SetVolumeReclaimer(r VolumeReclaimer) {
	s.volumeReclaimer = r
}

// volumeReclaimSweepLimit caps rows processed per tick. Each S3 row is a serial
// CLI round-trip (and NFS a mount/umount), so an unbounded backlog after a burst
// of deletes would stall the janitor; the cap drains it over several ticks.
const volumeReclaimSweepLimit = 128

// StartVolumeReclaim launches the backend-reclaim janitor that drains the
// pending_volume_deletions ledger. No-op when platform volumes are disabled, no
// reclaimer was wired, or the interval is non-positive — the metadata delete
// path is unaffected either way, only byte reclaim pauses.
func (s *Service) StartVolumeReclaim(ctx context.Context) {
	if !s.cfg.PlatformVolumes.Enabled || s.volumeReclaimer == nil {
		return
	}
	interval := s.cfg.PlatformVolumes.ReclaimInterval
	if interval <= 0 {
		return
	}
	s.startPeriodic(ctx, interval, 60*time.Second, s.runVolumeReclaim)
}

// runVolumeReclaim is one pass of the volume-reclaim janitor. For each pending
// row it:
//
//  1. Skips (and clears the ledger row for) volumes whose source is still owned
//     by a live volume — a delete-then-recreate of the same deterministic name
//     reuses the coordinate, so its bytes must survive. This is the resurrection
//     guard that lets GetOrCreateVolume safely keep the ledger row on recreate.
//  2. Otherwise deletes the backend bytes, then removes the ledger row.
//
// Idempotent and failure-tolerant: a failed Reclaim leaves the row so the next
// tick retries; deletes of an already-empty prefix/dir succeed. Failures are
// logged, never returned — the janitor must not block on one bad row.
func (s *Service) runVolumeReclaim(ctx context.Context) {
	pending, err := s.store.ListPendingVolumeDeletions(ctx)
	if err != nil {
		s.logger.Warn("volume reclaim list failed", "error", err)
		return
	}
	if len(pending) > volumeReclaimSweepLimit {
		pending = pending[:volumeReclaimSweepLimit]
	}
	if len(pending) == 0 {
		return
	}

	// Bounded fanout: each row is an independent backend delete (serial CLI /
	// mount round-trip), so a few in flight keeps a burst-delete backlog draining
	// across ticks without hammering the backend. The store is single-writer, but
	// the row deletes are short and serialized there; the parallelism is in the
	// backend I/O, which is what dominates.
	workers := s.cfg.PlatformVolumes.ReclaimConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(pending) {
		workers = len(pending)
	}

	jobs := make(chan models.PendingVolumeDeletion)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				s.reclaimOne(ctx, p)
			}
		}()
	}
	for _, p := range pending {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
}

// reclaimOne processes a single ledger row: skip+clear when a live volume still
// owns the source (resurrection guard), otherwise delete the backend bytes and
// clear the row. Errors are logged and the row left for the next tick to retry.
func (s *Service) reclaimOne(ctx context.Context, p models.PendingVolumeDeletion) {
	meta := s.volumeMeta()
	if v, err := meta.ByID(ctx, p.Tenant, p.VolumeID); err == nil && v.Source == p.Source {
		// The delete path writes the ledger before removing the user-visible row.
		// If the janitor catches that in-between state, keep the row so the next
		// tick can reclaim after the delete commits.
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Warn("volume reclaim live-row check failed", "volume_id", p.VolumeID, "error", err)
		return
	}
	live, err := meta.ExistsForSource(ctx, p.Source)
	if err != nil {
		s.logger.Warn("volume reclaim live-source check failed", "volume_id", p.VolumeID, "error", err)
		return
	}
	if live {
		// A recreated volume now owns this source; do not delete its data.
		// Drop the stale ledger row so we stop re-checking it.
		if err := s.store.DeletePendingVolumeDeletion(ctx, p.VolumeID); err != nil {
			s.logger.Warn("volume reclaim stale row clear failed", "volume_id", p.VolumeID, "error", err)
		}
		return
	}
	if err := s.volumeReclaimer.Reclaim(ctx, p.Backend, p.Source); err != nil {
		// Leave the row for the next tick to retry.
		s.logger.Warn("volume reclaim backend delete failed", "volume_id", p.VolumeID, "backend", p.Backend, "source", p.Source, "error", err)
		return
	}
	if err := s.store.DeletePendingVolumeDeletion(ctx, p.VolumeID); err != nil {
		s.logger.Warn("volume reclaim row clear failed", "volume_id", p.VolumeID, "error", err)
	}
}
