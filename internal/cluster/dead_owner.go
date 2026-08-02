package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// deadOwnerTracker holds per-node "first observed dead at" timestamps so the
// reconciler can decide which nodes have outlasted the grace period.
type deadOwnerTracker struct {
	mu        sync.Mutex
	firstSeen map[string]time.Time
}

func newDeadOwnerTracker() *deadOwnerTracker {
	return &deadOwnerTracker{firstSeen: make(map[string]time.Time)}
}

// markDead records nodeID as dead-since-now if it isn't already tracked. Returns
// the timestamp the node was first observed dead (which may be earlier than
// the call if a previous mark stuck).
func (t *deadOwnerTracker) markDead(nodeID string, now time.Time) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.firstSeen[nodeID]; ok {
		return existing
	}
	t.firstSeen[nodeID] = now
	return now
}

func (t *deadOwnerTracker) clear(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.firstSeen, nodeID)
}

func (t *deadOwnerTracker) snapshot() map[string]time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]time.Time, len(t.firstSeen))
	for k, v := range t.firstSeen {
		out[k] = v
	}
	return out
}

// handleMemberLeave is invoked from the memberlist leave callback. It only
// records the death timestamp; the periodic reconciler does the actual
// orphaning + voter removal once the grace period elapses.
func (c *Cluster) handleMemberLeave(nodeID string) {
	if nodeID == "" || nodeID == c.nodeID || c.deadOwners == nil {
		return
	}
	c.deadOwners.markDead(nodeID, time.Now())
}

// cancelDeadOwnerWatch is invoked from the join callback so a flapped node
// that comes back doesn't get evicted.
func (c *Cluster) cancelDeadOwnerWatch(nodeID string) {
	if c.deadOwners == nil {
		return
	}
	c.deadOwners.clear(nodeID)
}

// startDeadOwnerLoop spawns the periodic reconciler that evicts nodes whose
// grace period has passed. The loop is leader-gated: followers track marks
// (cheap) but never act, since raft config changes have to go through the
// leader's log anyway. If leadership changes, the new leader inherits the
// in-memory tracker and the next tick takes over.
func (c *Cluster) startDeadOwnerLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.deadOwnerLoopStop = cancel
	go func() {
		// 5s tick is plenty: dead-owner handling is a coarse-grained recovery
		// flow and faster ticking just hammers GetConfiguration during steady
		// state without changing the user-visible recovery time.
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.reconcileDeadOwners(ctx)
			}
		}
	}()
}

// reconcileDeadOwners is the leader-side step that actually evicts nodes whose
// grace has expired. Called from the periodic loop.
//
// Order of operations matters: orphan the placements FIRST, then RemoveServer.
// If we removed the voter first and then crashed before orphaning, on restart
// the FSM would still show the dead node as owner with no way to discover
// it's gone (raft no longer tracks it). Doing placements first means a
// crashed leader leaves observably-orphaned rows that the next leader's tick
// will idempotently re-orphan (no-op) and then remove the server (idempotent
// at the raft layer).
func (c *Cluster) reconcileDeadOwners(ctx context.Context) {
	if c.raft == nil || c.raft.raft.State() != raft.Leader {
		return
	}
	grace := c.cfg.ClusterDeadOwnerGrace
	if grace <= 0 {
		grace = 30 * time.Second
	}

	// Refresh the dead set from gossip: any tracked node that's actually
	// alive should be cleared (covers events we missed during a leadership
	// flap), and any non-alive node we don't yet track should be marked.
	live := make(map[string]bool)
	for _, m := range c.gossip.members() {
		if m.NodeID == "" {
			continue
		}
		if m.Alive {
			live[m.NodeID] = true
			c.deadOwners.clear(m.NodeID)
		}
	}

	// Sweep raft configuration for voters that gossip says aren't alive — this
	// catches the case where a node is fully gone from gossip (no Leave event
	// fired because we joined after it died).
	if cfgFut := c.raft.raft.GetConfiguration(); cfgFut.Error() == nil {
		for _, srv := range cfgFut.Configuration().Servers {
			id := string(srv.ID)
			if id == c.nodeID || live[id] {
				continue
			}
			c.deadOwners.markDead(id, time.Now())
		}
	}

	now := time.Now()
	for nodeID, since := range c.deadOwners.snapshot() {
		if now.Sub(since) < grace {
			continue
		}
		if live[nodeID] {
			c.deadOwners.clear(nodeID)
			continue
		}
		c.evictDeadOwner(ctx, nodeID)
	}
}

// evictDeadOwner handles every placement owned by nodeID and removes the dead
// node from the raft configuration. Sandboxes that opted into
// failover.policy=recreate are reassigned to a live peer scored against their
// replicated spec; the owner watcher on that peer re-materializes the
// container. All remaining placements are orphaned (OwnerNodeID="") so the API
// surfaces ErrOrphaned (410 Gone).
//
// All steps are idempotent so a partial failure is safe to retry on the next
// tick: a placement already orphaned stays orphaned, and RemoveServer is a
// no-op once the dead node is gone.
func (c *Cluster) evictDeadOwner(ctx context.Context, nodeID string) {
	ids := c.fsm.idsOwnedBy(nodeID)
	var reassigned int
	for _, id := range ids {
		p, ok := c.fsm.get(id)
		if !ok {
			continue
		}
		if !placementWantsFailoverRecreate(p) {
			continue
		}
		newOwnerID, newOwnerURL, newOwnerDataPlaneHost := c.pickRecreationTarget(p.Spec)
		if newOwnerID == "" {
			c.logger.Warn("cluster: no failover recreation target; placement will be orphaned",
				"sandbox_id", id, "dead_node", nodeID)
			continue
		}
		cmd := command{
			Op:                 opReassign,
			SandboxID:          id,
			OwnerNodeID:        newOwnerID,
			OwnerAPIURL:        newOwnerURL,
			OwnerDataPlaneHost: newOwnerDataPlaneHost,
			ReassignCause:      reassignCauseFailover,
		}
		if err := c.applyCommand(ctx, cmd); err != nil {
			c.logger.Warn("cluster: reassign placement failed; will retry next tick",
				"sandbox_id", id, "dead_node", nodeID, "new_owner", newOwnerID, "err", err)
			return
		}
		// The leader apply wrapper increments the metric only when the FSM
		// reports a real transition. reassigned is a local log counter and
		// deliberately still counts successful acknowledgements.
		reassigned++
	}
	orphaned := len(c.fsm.idsOwnedBy(nodeID))
	if err := c.orphanOwner(ctx, nodeID); err != nil {
		c.logger.Warn("cluster: orphan dead-owner placements failed; will retry next tick",
			"dead_node", nodeID, "err", err)
		return
	}
	if reassigned > 0 || orphaned > 0 {
		c.logger.Warn("cluster: handled placements after owner death",
			"dead_node", nodeID, "reassigned", reassigned, "orphaned", orphaned)
	}
	c.removeDeadOwnerServer(nodeID)
}

func (c *Cluster) orphanOwner(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	return c.applyCommand(ctx, command{Op: opOrphanOwner, NodeID: nodeID})
}

func (c *Cluster) removeDeadOwnerServer(nodeID string) {
	if _, ok := c.configuredServer(nodeID); ok {
		f := c.raft.raft.RemoveServer(raft.ServerID(nodeID), 0, c.commitTimeout)
		if err := f.Error(); err != nil {
			c.logger.Warn("cluster: RemoveServer failed; will retry next tick",
				"dead_node", nodeID, "err", err)
			return
		}
	}
	c.deadOwners.clear(nodeID)
	c.logger.Info("cluster: evicted dead node from control plane", "dead_node", nodeID)
}

// startReservationGCLoop spawns the periodic sweep that cancels expired
// opReserve rows. Leader-gated for the same reason as the dead-owner loop:
// CancelReservation routes through raft anyway, and ticking on every node
// would just multiply leader-forwarded no-ops. 5s tick matches the dead-
// owner loop; with the 120s reservation TTL the worst-case orphan window is
// ~125s.
func (c *Cluster) startReservationGCLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.reservationGCStop = cancel
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.reconcileReservations(ctx)
			}
		}
	}()
}

// reconcileReservations cancels any reservation whose expiry has passed.
// Cancel is best-effort + idempotent: a reservation that was promoted to
// Placed between enumeration and Apply is left alone (opCancelReserve is a no-op
// on placed rows), and a reservation already cancelled by the router's
// rollback path is also a no-op. So a partial sweep on leader-flap re-runs
// safely on the next tick.
func (c *Cluster) reconcileReservations(ctx context.Context) {
	if c.raft == nil || c.raft.raft.State() != raft.Leader {
		return
	}
	now := time.Now().Unix()
	for _, id := range c.fsm.expiredReservationIDs(now) {
		p, _ := c.fsm.get(id)
		if err := c.CancelReservation(ctx, id); err != nil {
			c.logger.Warn("cluster: cancel expired reservation failed; will retry next tick",
				"sandbox_id", id, "owner", p.OwnerNodeID, "err", err)
			continue
		}
		recordExpiredReservation()
		c.logger.Info("cluster: cancelled expired reservation",
			"sandbox_id", id, "owner", p.OwnerNodeID)
	}
}

// pickRecreationTarget runs placement scoring against the replicated spec to
// pick a live node for the recreated sandbox. Returns empty strings if spec is
// nil (caller treats that as the orphan path) or if SelectPlacement errors out.
// Self is a perfectly valid choice — the leader is a normal recreation target.
func (c *Cluster) pickRecreationTarget(spec *models.CreateSandboxRequest) (nodeID, apiURL, dataPlaneHost string) {
	if spec == nil {
		return "", "", ""
	}
	if spec.ImageDistributionMode == models.ImageDistributionLocalOnly {
		return "", "", ""
	}
	req := capacityRequestFromSpec(spec)
	target, err := c.SelectPlacement(req)
	if err != nil {
		return "", "", ""
	}
	if target.IsSelf {
		return c.nodeID, c.apiURL, c.dataPlaneHost
	}
	return target.NodeID, target.APIURL, target.DataPlaneHost
}
