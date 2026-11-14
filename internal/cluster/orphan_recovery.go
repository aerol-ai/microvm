package cluster

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"sync"
	"time"
)

// Orphaned failover recoveries (R14).
//
// A failover.policy=recreate sandbox is orphaned, not moved, when no live
// node has room for it as its owner dies (evictOwnerPlacements), or when the
// node it was moved to refuses it for capacity (handBackRefusedPlacement).
// Before R14 nothing looked at it again: the owner watchers page only their
// own placements, and only the recorded previous owner may claim an orphan.
// A zone lost while the survivors were full stayed down after the
// autoscaler brought machines back, against the plan's G1 promise that the
// rest recover as machines arrive.
//
// So the leader pages the orphaned recreate-policy placements on every
// dead-owner pass and moves each to a node that has room now, with the same
// fenced opReassign a failover uses: it expects the row to be orphaned (no
// owner) and the same lifetime, so a previous owner that reclaims it, a
// delete, or a new lifetime wins over a retry it races. The page is
// bounded, and a cursor walks the whole backlog across passes. Nothing new
// goes into Raft: the backlog is the FSM's derived orphanedRecoveryIndex.

const orphanRetryPage = 64

// orphanRetryAliveWait is how long an orphan whose previous owner is alive
// waits before it is moved elsewhere: a node that came back reclaims its
// own sandboxes (ClaimOrphan), and one that refused it for capacity is
// not asked again at once. A var for tests.
var orphanRetryAliveWait = 30 * time.Second

var (
	// failoverRecoveryBacklog is how many orphaned recreate-policy
	// sandboxes wait for a node with room, as of the leader's last pass.
	failoverRecoveryBacklog = expvar.NewInt("aerolvm_cluster_failover_recovery_backlog")
	// failoverRecoveryRecovered counts orphans moved to a node with room.
	failoverRecoveryRecovered = expvar.NewInt("aerolvm_cluster_failover_recovery_recovered_total")
)

// orphanRetryCursor is where the leader's walk of the backlog resumes.
type orphanRetryCursor struct {
	mu    sync.Mutex
	after string
}

// retryOrphanedRecoveries moves the orphaned recreate-policy placements of
// one page to nodes with room, and reports how many it moved. The leader's
// dead-owner loop calls it after its evictions.
func (c *Cluster) retryOrphanedRecoveries(ctx context.Context) int {
	c.orphanRetry.mu.Lock()
	after := c.orphanRetry.after
	c.orphanRetry.mu.Unlock()
	ids, end := c.fsm.orphanedRecoveryPage(after, orphanRetryPage)
	next := ""
	if !end && len(ids) > 0 {
		next = ids[len(ids)-1]
	}
	c.orphanRetry.mu.Lock()
	c.orphanRetry.after = next
	c.orphanRetry.mu.Unlock()

	moved := 0
	defer func() { failoverRecoveryBacklog.Set(int64(c.fsm.orphanedRecoveryLen())) }()
	now := time.Now()
	for _, id := range ids {
		p, ok := c.fsm.get(id)
		if !ok || !p.IsOrphaned() || !placementWantsFailoverRecreate(p) {
			continue
		}
		prev := strings.TrimSpace(p.OrphanedOwnerNodeID)
		var exclude []string
		if prev != "" && !c.fsm.isNodeDenied(prev) {
			if m, ok := c.gossip.lookupMember(prev); ok && m.Alive {
				if now.Sub(time.Unix(p.OrphanedUnix, 0)) < orphanRetryAliveWait {
					continue
				}
				exclude = []string{prev}
			}
		}
		target, err := c.selectRecreationTargetAvoiding(p, c.lastKnownZone(prev), exclude...)
		if err != nil {
			// Still no room (or a placement rule nothing satisfies yet):
			// the next pass looks again.
			continue
		}
		if c.orphanRetryBeforeApply != nil {
			c.orphanRetryBeforeApply(id)
		}
		err = c.applyCommand(ctx, command{
			Op:                     opReassign,
			SandboxID:              id,
			OwnerNodeID:            target.NodeID,
			OwnerAPIURL:            target.APIURL,
			OwnerDataPlaneHost:     target.DataPlaneHost,
			ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
			ExpectedOwnerNodeID:    "",
			ExpectedOwnerNodeIDSet: true,
			ReassignCause:          reassignCauseFailover,
		})
		switch {
		case err == nil:
			moved++
			failoverRecoveryRecovered.Add(1)
			c.logger.Info("cluster: an orphaned failover sandbox found a node with room",
				"sandbox_id", id, "orphaned_from", prev, "new_owner", target.NodeID)
		case errors.Is(err, ErrStuckReassignNotOwner), errors.Is(err, ErrIncarnationConflict), errors.Is(err, ErrReservationConflict):
			// Reclaimed, replaced by a new lifetime, or being deleted since
			// the read: nothing to recover.
		default:
			c.logger.Warn("cluster: moving an orphaned failover sandbox failed; will retry on the next pass",
				"sandbox_id", id, "new_owner", target.NodeID, "err", err)
			return moved
		}
	}
	return moved
}
