package cluster

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
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

// The leader drains the backlog in its own loop (startOrphanRetryLoop),
// every orphanRetryEvery, oldest orphan first. One pass reads pages of
// orphanRetryPage and stops at the first of: the backlog's end (the next
// pass starts from the oldest again), the moves the rate allows in one
// tick (cfg.ClusterOrphanRetryRate, SB_CLUSTER_ORPHAN_RETRY_RATE),
// orphanRetryBudget of time (the rest of the tick is the leader's for
// creates and everything else), or orphanRetryScanCap rows looked at, so
// a backlog nothing has room for costs one bounded walk. A pass that stops
// early resumes from where it stopped. Before, one page of 64 every 5 s
// capped recovery at 12.8 sandboxes a second: about 43 minutes of waiting
// alone for the 33,000 sandboxes of a lost zone in a 100,000-sandbox cell,
// after capacity was back.
const orphanRetryPage = 64

var (
	orphanRetryEvery  = time.Second
	orphanRetryBudget = 500 * time.Millisecond
	// orphanRetryScanCap is a var for tests.
	orphanRetryScanCap = 4096
)

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
	// failoverRecoveryOldest is how long the oldest of them has waited, in
	// seconds (0 with none), as of the leader's last pass.
	failoverRecoveryOldest = expvar.NewInt("aerolvm_cluster_failover_recovery_oldest_seconds")
)

// orphanRetryCursor is where the leader's walk of the backlog resumes. mu
// also keeps passes one at a time.
type orphanRetryCursor struct {
	mu    sync.Mutex
	after orphanKey
}

// orphanRetryMoves is how many moves one pass may make.
func orphanRetryMoves(rate int) int {
	if rate <= 0 {
		rate = defaultOrphanRetryRate
	}
	return max(1, int(int64(rate)*int64(orphanRetryEvery)/int64(time.Second)))
}

// defaultOrphanRetryRate matches config's default, for a Cluster built
// without one (tests).
const defaultOrphanRetryRate = 200

// startOrphanRetryLoop runs the leader's backlog passes until Shutdown.
func (c *Cluster) startOrphanRetryLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.orphanRetryLoopStop = cancel
	go func() {
		t := time.NewTicker(orphanRetryEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// A tick that fired as the loop was stopped does nothing.
				if ctx.Err() == nil {
					c.orphanRetryTick(ctx)
				}
			}
		}
	}()
}

// orphanRetryTick is one tick of the loop: a pass on the leader, nothing
// elsewhere. A server that is not the leader forgets its place, so a new
// leader starts from the oldest orphan.
func (c *Cluster) orphanRetryTick(ctx context.Context) int {
	if c.raft == nil || c.raft.raft.State() != raft.Leader {
		c.orphanRetry.mu.Lock()
		c.orphanRetry.after = orphanKey{}
		c.orphanRetry.mu.Unlock()
		return 0
	}
	if c.fsm.orphanedRecoveryLen() == 0 {
		c.publishOrphanBacklog(time.Now())
		return 0
	}
	return c.retryOrphanedRecoveries(ctx)
}

func (c *Cluster) publishOrphanBacklog(now time.Time) {
	failoverRecoveryBacklog.Set(int64(c.fsm.orphanedRecoveryLen()))
	oldest := int64(0)
	if unix, ok := c.fsm.orphanedRecoveryOldest(); ok && unix > 0 {
		oldest = max(0, now.Unix()-unix)
	}
	failoverRecoveryOldest.Set(oldest)
}

// retryOrphanedRecoveries is one pass over the backlog (above), and reports
// how many sandboxes it moved to a node with room.
func (c *Cluster) retryOrphanedRecoveries(ctx context.Context) int {
	c.orphanRetry.mu.Lock()
	defer c.orphanRetry.mu.Unlock()
	start := time.Now()
	defer func() { c.publishOrphanBacklog(time.Now()) }()
	limit := orphanRetryMoves(c.cfg.ClusterOrphanRetryRate)
	moved, scanned := 0, 0
	after := c.orphanRetry.after
	for {
		keys, end := c.fsm.orphanedRecoveryPage(after, orphanRetryPage)
		for _, k := range keys {
			if moved >= limit || scanned >= orphanRetryScanCap || time.Since(start) >= orphanRetryBudget || ctx.Err() != nil {
				c.orphanRetry.after = after
				return moved
			}
			scanned++
			ok, stop := c.retryOrphan(ctx, k.id, start)
			if stop {
				// This row is retried first next pass.
				c.orphanRetry.after = after
				return moved
			}
			after = k
			if ok {
				moved++
			}
		}
		if end {
			c.orphanRetry.after = orphanKey{}
			return moved
		}
	}
}

// retryOrphan moves one orphan to a node with room, if there is one now.
// stop is true after a move failed for a reason other than losing a race:
// the pass ends, and the row stays orphaned for the next one.
func (c *Cluster) retryOrphan(ctx context.Context, id string, now time.Time) (moved, stop bool) {
	p, ok := c.fsm.get(id)
	if !ok || !p.IsOrphaned() || !placementWantsFailoverRecreate(p) {
		return false, false
	}
	prev := strings.TrimSpace(p.OrphanedOwnerNodeID)
	var exclude []string
	if prev != "" && !c.fsm.isNodeDenied(prev) {
		if m, ok := c.gossip.lookupMember(prev); ok && m.Alive {
			if now.Sub(time.Unix(p.OrphanedUnix, 0)) < orphanRetryAliveWait {
				return false, false
			}
			exclude = []string{prev}
		}
	}
	target, err := c.selectRecreationTargetAvoiding(p, c.lastKnownZone(prev), exclude...)
	if err != nil {
		// Still no room (or a placement rule nothing satisfies yet): a
		// later pass looks again.
		return false, false
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
		failoverRecoveryRecovered.Add(1)
		c.logger.Info("cluster: an orphaned failover sandbox found a node with room",
			"sandbox_id", id, "orphaned_from", prev, "new_owner", target.NodeID)
		return true, false
	case errors.Is(err, ErrStuckReassignNotOwner), errors.Is(err, ErrIncarnationConflict), errors.Is(err, ErrReservationConflict):
		// Reclaimed, replaced by a new lifetime, or being deleted since
		// the read: nothing to recover.
		return false, false
	default:
		c.logger.Warn("cluster: moving an orphaned failover sandbox failed; will retry on the next pass",
			"sandbox_id", id, "new_owner", target.NodeID, "err", err)
		return false, true
	}
}
