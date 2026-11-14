package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
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

// runVolumeReclaim is one pass of the volume-reclaim janitor. For each
// obligation (a pending_volume_deletions row, or in a cluster a replicated
// delete_with_sandbox reclaim, see volumeObligations) it:
//
//  1. Skips (and clears the obligation for) volumes whose source is still owned
//     by a live volume — a delete-then-recreate of the same deterministic name
//     reuses the coordinate, so its bytes must survive. This is the resurrection
//     guard that lets GetOrCreateVolume safely keep the ledger row on recreate.
//  2. Otherwise deletes the backend bytes, then clears the obligation.
//
// Idempotent and failure-tolerant: a failed Reclaim leaves the obligation so
// the next tick retries; deletes of an already-empty prefix/dir succeed.
// Failures are logged, never returned — the janitor must not block on one bad
// row.
func (s *Service) runVolumeReclaim(ctx context.Context) {
	pending := s.volumeObligations(ctx)
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

	jobs := make(chan volumeObligation)
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

// volumeObligation is one record that a volume's bytes are owed a delete:
// this node's pending_volume_deletions row, the cluster's replicated
// delete_with_sandbox reclaim (cluster/fsm_volume_reclaims.go), or both for
// the same volume, which one reclaim then clears together.
type volumeObligation struct {
	models.PendingVolumeDeletion
	local bool                   // a row in this node's ledger
	fsm   *cluster.VolumeReclaim // the cluster's entry for the volume
}

func localVolumeObligation(p models.PendingVolumeDeletion) volumeObligation {
	return volumeObligation{PendingVolumeDeletion: p, local: true}
}

// recordedAt is when the obligation was last written; the newer of the two
// records when both exist.
func (o volumeObligation) recordedAt() time.Time {
	at := o.CreatedAt
	if o.fsm != nil {
		if t := time.Unix(0, o.fsm.RecordedUnixNano); t.After(at) {
			at = t
		}
	}
	return at
}

// volumeObligations is one pass's work: this node's ledger rows, then the
// cluster's reclaims this node drains. A reclaim for a volume that also has
// a ledger row here rides that row, so the bytes are deleted once.
func (s *Service) volumeObligations(ctx context.Context) []volumeObligation {
	var out []volumeObligation
	byVolume := map[string]int{}
	pending, err := s.store.ListPendingVolumeDeletions(ctx)
	if err != nil {
		s.logger.Warn("volume reclaim list failed", "error", err)
	}
	if len(pending) > volumeReclaimSweepLimit {
		pending = pending[:volumeReclaimSweepLimit]
	}
	for _, p := range pending {
		byVolume[p.VolumeID] = len(out)
		out = append(out, localVolumeObligation(p))
	}
	for _, r := range s.clusterVolumeReclaims(ctx) {
		r := r
		if i, ok := byVolume[r.VolumeID]; ok {
			out[i].fsm = &r
			continue
		}
		out = append(out, volumeObligation{
			PendingVolumeDeletion: models.PendingVolumeDeletion{
				VolumeID: r.VolumeID, Tenant: r.Tenant, Name: r.Name, Backend: r.Backend, Source: r.Source,
				CreatedAt: time.Unix(0, r.RecordedUnixNano).UTC(),
			},
			fsm: &r,
		})
	}
	return out
}

// clusterVolumeReclaims returns the cluster's delete_with_sandbox reclaims
// this node drains: the ones it recorded, plus the ones it took over from a
// node that is gone or never drains (a claim, so one node retries each, not
// the fleet). Nil when clustering is off or the client has no ledger.
func (s *Service) clusterVolumeReclaims(ctx context.Context) []cluster.VolumeReclaim {
	if !s.cfg.EnableCluster {
		return nil
	}
	c := s.Cluster()
	rc, ok := c.(cluster.VolumeReclaimClient)
	if !ok {
		return nil
	}
	self := strings.TrimSpace(c.SelfNodeID())
	list, err := rc.VolumeReclaimsFor(ctx, self, volumeReclaimSweepLimit)
	if err != nil {
		s.logger.Warn("volume reclaim: cluster list failed; retried next pass", "error", err)
		return nil
	}
	out := make([]cluster.VolumeReclaim, 0, len(list))
	for _, r := range list {
		if r.NodeID != self {
			if err := rc.ClaimVolumeReclaim(ctx, r, self); err != nil {
				// Another node took it, it was acked, or raft is away: not ours this pass.
				s.logger.Debug("volume reclaim: claim skipped", "volume_id", r.VolumeID, "node_id", r.NodeID, "error", err)
				continue
			}
			s.logger.Info("volume reclaim: took over a delete_with_sandbox volume from a node that will not drain it",
				"volume_id", r.VolumeID, "from_node", r.NodeID, "sandbox_id", r.SandboxID)
			r.NodeID = self
		}
		out = append(out, r)
	}
	return out
}

// clearVolumeObligation drops the records of a finished obligation: this
// node's ledger row, and the cluster's entry, the latter only if it is still
// the version this pass read (an ack names it), so a newer release of the
// same volume is never dropped.
func (s *Service) clearVolumeObligation(ctx context.Context, o volumeObligation) {
	if o.local {
		if err := s.store.DeletePendingVolumeDeletion(ctx, o.VolumeID); err != nil {
			s.logger.Warn("volume reclaim row clear failed", "volume_id", o.VolumeID, "error", err)
		}
	}
	if o.fsm != nil {
		if rc, ok := s.Cluster().(cluster.VolumeReclaimClient); ok {
			if err := rc.AckVolumeReclaim(ctx, *o.fsm); err != nil {
				s.logger.Warn("volume reclaim cluster ack failed; retried next pass", "volume_id", o.VolumeID, "error", err)
			}
		}
	}
}

// reclaimOne processes a single obligation: skip+clear when a live volume still
// owns the source (resurrection guard), otherwise delete the backend bytes and
// clear it. Errors are logged and the obligation left for the next tick.
func (s *Service) reclaimOne(ctx context.Context, p volumeObligation) {
	meta := s.volumeMeta()
	if v, err := meta.ByID(ctx, p.Tenant, p.VolumeID); err == nil && v.Source == p.Source {
		// The delete path writes the ledger before removing the user-visible row.
		// If the janitor catches that in-between state, keep the row so the next
		// tick can reclaim after the delete commits. A delete_with_sandbox
		// volume's destroy may never get to remove it (a crash, the store
		// unreachable, a replica that still counted the sandbox), so the sweep
		// removes it itself once nothing holds it, and goes on to the bytes.
		if !v.DeleteWithSandbox || !s.sweepDeleteWithSandbox(ctx, *v, p) {
			return
		}
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
		// Drop the stale obligation so we stop re-checking it.
		s.clearVolumeObligation(ctx, p)
		return
	}
	if err := s.volumeReclaimer.Reclaim(ctx, p.Backend, p.Source); err != nil {
		// Leave the obligation for the next tick to retry.
		s.logger.Warn("volume reclaim backend delete failed", "volume_id", p.VolumeID, "backend", p.Backend, "source", p.Source, "error", err)
		return
	}
	s.clearVolumeObligation(ctx, p)
}
