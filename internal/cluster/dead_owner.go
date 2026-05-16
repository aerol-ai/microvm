package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// clusterRecreateOnFailoverEnabled is the product-policy gate for automatic
// sandbox failover-recreate. When false (current policy), a dead owner's
// placements are orphaned and clients see 410 Gone — sandboxes do not survive
// node death.
//
// The reassign + recreate code paths in this file (pickRecreationTarget,
// evictDeadOwner's spec-driven branch) and in owner_watcher.go
// (recreateOwnedSandboxes, tryReassignStuckPlacement) are intentionally
// preserved rather than deleted: spec/sealed-secret replication is cheap, the
// failure-mode tests are still useful, and a future opt-in lifecycle policy
// (e.g. Lifecycle.RecreateOnFailover) is expected to flip this gate.
//
// To re-enable: change to true here. Before exposing to users, decide whether
// recreate should be opt-in per sandbox so it does not silently revive user
// work that the operator intended to leave dead.
const clusterRecreateOnFailoverEnabled = false

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

// evictDeadOwner orphans every placement owned by nodeID and removes the dead
// node from the raft configuration. Orphan = OwnerNodeID set to "", so the API
// surfaces ErrOrphaned (410 Gone) for any subsequent request against that
// sandbox. This matches the product policy that sandboxes do not survive node
// death (see clusterRecreateOnFailoverEnabled at the top of this file).
//
// When clusterRecreateOnFailoverEnabled flips to true, pickRecreationTarget
// returns a live peer scored against the replicated spec and the placement is
// reassigned (rather than orphaned) — the owner watcher on the new owner then
// re-materializes the container. That code path is preserved here for the
// future opt-in failover behavior.
//
// All steps are idempotent so a partial failure is safe to retry on the next
// tick: a placement already orphaned stays orphaned, and RemoveServer is a
// no-op once the dead node is gone.
func (c *Cluster) evictDeadOwner(ctx context.Context, nodeID string) {
	ids := c.fsm.idsOwnedBy(nodeID)
	var reassigned, orphaned int
	for _, id := range ids {
		p, ok := c.fsm.get(id)
		if !ok {
			continue
		}
		// Default to the orphan path. The reassign branch is gated off in
		// product policy; keeping pickRecreationTarget callable preserves the
		// future opt-in path and the existing tests that exercise it.
		var newOwnerID, newOwnerURL, newOwnerDataPlaneHost string
		if clusterRecreateOnFailoverEnabled {
			newOwnerID, newOwnerURL, newOwnerDataPlaneHost = c.pickRecreationTarget(p.Spec)
		}
		cmd := command{
			Op:                 opReassign,
			SandboxID:          id,
			OwnerNodeID:        newOwnerID,
			OwnerAPIURL:        newOwnerURL,
			OwnerDataPlaneHost: newOwnerDataPlaneHost,
		}
		if err := c.applyCommand(ctx, cmd); err != nil {
			c.logger.Warn("cluster: reassign placement failed; will retry next tick",
				"sandbox_id", id, "dead_node", nodeID, "new_owner", newOwnerID, "err", err)
			return
		}
		if newOwnerID == "" {
			orphaned++
		} else {
			reassigned++
		}
	}
	if reassigned > 0 || orphaned > 0 {
		c.logger.Warn("cluster: handled placements after owner death",
			"dead_node", nodeID, "reassigned", reassigned, "orphaned_no_spec", orphaned)
	}
	// RemoveServer is a no-op (returns nil) if the server isn't in the config,
	// so we don't need to pre-check.
	f := c.raft.raft.RemoveServer(raft.ServerID(nodeID), 0, c.commitTimeout)
	if err := f.Error(); err != nil {
		c.logger.Warn("cluster: RemoveServer failed; will retry next tick",
			"dead_node", nodeID, "err", err)
		return
	}
	c.deadOwners.clear(nodeID)
	c.logger.Info("cluster: evicted dead node from raft config", "dead_node", nodeID)
}

// pickRecreationTarget runs placement scoring against the replicated spec to
// pick a live node for the recreated sandbox. Returns empty strings if spec is
// nil (caller treats that as the orphan path) or if SelectPlacement errors out.
// Self is a perfectly valid choice — the leader is a normal recreation target.
func (c *Cluster) pickRecreationTarget(spec *models.CreateSandboxRequest) (nodeID, apiURL, dataPlaneHost string) {
	if spec == nil {
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
