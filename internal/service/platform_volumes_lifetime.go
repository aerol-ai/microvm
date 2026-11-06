package service

import (
	"context"
	"errors"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// delete_with_sandbox volumes (plans/agent-sandbox-feature-parity.md V1)
// go, record and bytes, once the last sandbox attached to one is destroyed.
//
// The attachment index is what says "last": SQLite drops a sandbox's
// attachments with its row (FK cascade), the cluster FSM with its placement
// delete. Once they are gone nothing links the volume to any sandbox, so
// the cleanup obligation is written by that same transition, never only by
// the destroy around it (review 2 finding 7):
//
//   - single node: store.Delete writes the reclaim-ledger row
//     (pending_volume_deletions) of every delete_with_sandbox volume the
//     sandbox was the last holder of, in the transaction that deletes the
//     sandbox row.
//   - cluster: opDelete records a replicated cluster.VolumeReclaim for each
//     such volume, in the apply that releases the attachments
//     (cluster/fsm_volume_reclaims.go). It survives the loss of the worker
//     that destroyed the sandbox and covers the leader's expiry of an
//     abandoned delete; it goes only when a node acks the deleted bytes.
//
// Around that, a destroy still works in two steps, the fast path:
//
//  1. recordSandboxVolumeDeletes, once the destroy is committed (its delete
//     fence is in) and before the attachments go: find the sandbox's
//     delete_with_sandbox volumes and write each into this node's ledger.
//     A failed lookup here loses nothing; the transition above records it.
//  2. finishSandboxVolumeDeletes, after the row or placement is gone: delete
//     each volume's row unless another sandbox still holds it. The sweep
//     deletes the bytes, as for any deleted volume.
//
// Rollback rule: nothing is undone. A row delete that fails, or is refused
// because a lagging replica still counts this sandbox's attachment, leaves
// the obligation; the sweep (reclaimOne) deletes the volume row once nothing
// holds it and then the bytes. An obligation for a volume another sandbox
// still holds is dropped after deleteWithSandboxPendingGrace, since that
// sandbox's own destroy records it again.

// deleteWithSandboxPendingGrace is how long the sweep keeps the ledger row of
// a delete_with_sandbox volume that is still attached. It covers a destroy
// still running (its own attachment not yet released) or a replica that has
// not applied the release; past it, the holder is another live sandbox.
const deleteWithSandboxPendingGrace = 10 * time.Minute

// deleteWithSandboxRetryDelays spaces the background retries of a delete
// that was refused because the volume still looked attached. In a cluster
// the node that just committed a destroy's placement delete reads its own
// replica, which may apply that delete a moment later, so the dying sandbox
// still counts as a holder (UC-412/413 live, 2026-11-06: the row then waited
// for the 5-minute reclaim sweep). About 16 s in all; a holder still there
// after that is real, and the sweep decides. A variable for tests.
var deleteWithSandboxRetryDelays = []time.Duration{
	250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
}

// recordSandboxVolumeDeletes writes the reclaim-ledger row of every
// delete_with_sandbox volume sb is attached to and returns those volumes for
// finishSandboxVolumeDeletes. Best effort: a destroy never fails on it. A
// volume it misses is not lost: the row or placement delete records it
// (see above), and the sweep deletes it a pass later instead of now.
func (s *Service) recordSandboxVolumeDeletes(ctx context.Context, sb *models.Sandbox) []models.Volume {
	if s == nil || sb == nil || !s.cfg.PlatformVolumes.Enabled || s.store == nil {
		return nil
	}
	meta := s.volumeMeta()
	attachments, err := meta.AttachmentsForSandbox(ctx, sb.ID)
	if err != nil {
		s.logger.Warn("platform volumes: cannot list the sandbox's volumes; any delete_with_sandbox volume is kept",
			"sandbox_id", sb.ID, "error", err)
		return nil
	}
	seen := map[string]bool{}
	var out []models.Volume
	for _, a := range attachments {
		key := a.Tenant + "\x00" + a.VolumeID
		if seen[key] {
			continue
		}
		seen[key] = true
		vol, err := meta.ByID(ctx, a.Tenant, a.VolumeID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.logger.Warn("platform volumes: volume lookup failed; it is kept", "sandbox_id", sb.ID, "volume_id", a.VolumeID, "error", err)
			}
			continue
		}
		if !vol.DeleteWithSandbox {
			continue
		}
		source, err := s.volumeSource(*vol)
		if err == nil {
			err = s.store.SchedulePendingVolumeDeletion(ctx, *vol, source)
		}
		if err != nil {
			// The finish step still tries; only the crash safety net is lost.
			s.logger.Warn("platform volumes: delete_with_sandbox volume not recorded for the sweep", "sandbox_id", sb.ID, "volume_id", vol.ID, "error", err)
		}
		out = append(out, *vol)
	}
	return out
}

// finishSandboxVolumeDeletes deletes the rows of the volumes
// recordSandboxVolumeDeletes found, now that the destroyed sandbox's
// attachments are gone. One another sandbox still holds stays; any other
// failure is the sweep's to retry.
func (s *Service) finishSandboxVolumeDeletes(ctx context.Context, sandboxID string, vols []models.Volume) {
	for _, vol := range vols {
		err := s.deleteVolumeRowIfUnattached(ctx, vol)
		switch {
		case err == nil:
			s.logger.Info("platform volumes: delete_with_sandbox volume deleted with its last sandbox; its files go with the next reclaim pass",
				"sandbox_id", sandboxID, "volume_id", vol.ID)
		case errors.Is(err, store.ErrVolumeInUse):
			// Another sandbox holds it (its destroy records it again), or, in
			// a cluster, this node's replica has not applied the placement
			// delete yet: retry briefly off the destroy's path. One node's
			// SQLite has no lag, so there the holder is real.
			if s.cfg.EnableCluster {
				go s.retrySandboxVolumeDelete(sandboxID, vol)
			}
		case errors.Is(err, store.ErrNotFound):
			// A concurrent destroy already deleted it.
		default:
			s.logger.Warn("platform volumes: delete_with_sandbox volume delete failed; the reclaim sweep retries it",
				"sandbox_id", sandboxID, "volume_id", vol.ID, "error", err)
		}
	}
}

// retrySandboxVolumeDelete retries finishSandboxVolumeDeletes' delete of
// one volume while it still looks attached, with deleteWithSandboxRetryDelays
// between tries. It stops once the row is gone or another error says the
// sweep should handle it.
func (s *Service) retrySandboxVolumeDelete(sandboxID string, vol models.Volume) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, delay := range deleteWithSandboxRetryDelays {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		err := s.deleteVolumeRowIfUnattached(ctx, vol)
		switch {
		case err == nil:
			s.logger.Info("platform volumes: delete_with_sandbox volume deleted with its last sandbox once the cluster caught up",
				"sandbox_id", sandboxID, "volume_id", vol.ID)
			return
		case errors.Is(err, store.ErrNotFound):
			return
		case errors.Is(err, store.ErrVolumeInUse):
			continue
		default:
			s.logger.Warn("platform volumes: delete_with_sandbox volume delete failed; the reclaim sweep retries it",
				"sandbox_id", sandboxID, "volume_id", vol.ID, "error", err)
			return
		}
	}
}

// volumeSource is the volume's frozen backend coordinate, recomputed from
// config only for a row older than the source column.
func (s *Service) volumeSource(vol models.Volume) (string, error) {
	if vol.Source != "" {
		return vol.Source, nil
	}
	return volumes.MountSource(volumeBackendFor(s.cfg.PlatformVolumes, vol.Backend), vol.Tenant, vol.Name)
}

// sweepDeleteWithSandbox is the reclaim sweep's retry for an obligation whose
// delete_with_sandbox volume row is still there. It reports whether the row
// is gone, so the caller goes on to delete the bytes.
func (s *Service) sweepDeleteWithSandbox(ctx context.Context, vol models.Volume, p volumeObligation) bool {
	meta := s.volumeMeta()
	n, err := meta.AttachmentCount(ctx, vol.Tenant, vol.ID)
	if err != nil {
		s.logger.Warn("volume reclaim attachment count failed", "volume_id", vol.ID, "error", err)
		return false
	}
	if n > 0 {
		// Held again, by a sandbox that attached it after the release (its
		// own destroy records the volume again), or, for a moment, by a
		// replica that has not applied the release yet. The grace tells the
		// two apart.
		if time.Since(p.recordedAt()) > deleteWithSandboxPendingGrace {
			s.clearVolumeObligation(ctx, p)
		}
		return false
	}
	if err := meta.DeleteRow(ctx, vol.Tenant, vol.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		// ErrVolumeInUse: a sandbox attached it since the count.
		if !errors.Is(err, store.ErrVolumeInUse) {
			s.logger.Warn("volume reclaim delete_with_sandbox row delete failed", "volume_id", vol.ID, "error", err)
		}
		return false
	}
	return true
}
