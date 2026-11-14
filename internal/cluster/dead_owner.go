package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/raft"
)

// defaultDeadOwnerGrace is SB_DEAD_OWNER_GRACE's default. config.Load sets it;
// this covers a Config built without Load (tests, embedders).
const defaultDeadOwnerGrace = 30 * time.Second

// DeadOwnerGrace is how long the leader waits, after it first sees a node
// dead, before it moves or orphans that node's sandboxes (SB_DEAD_OWNER_GRACE).
func DeadOwnerGrace(cfg config.Config) time.Duration {
	if cfg.ClusterDeadOwnerGrace > 0 {
		return cfg.ClusterDeadOwnerGrace
	}
	return defaultDeadOwnerGrace
}

// OwnershipLease is how long a node may keep acting on placement or ownership
// information it has not confirmed with the control plane: half the dead-owner
// grace. The leader cannot move a sandbox until a node has looked dead for the
// whole grace, so a node that stops trusting what it last heard at half the
// grace stops before any move it has not heard about. The other half is the
// margin for clocks, loop ticks and the time gossip takes to call a node dead.
func OwnershipLease(cfg config.Config) time.Duration {
	return DeadOwnerGrace(cfg) / 2
}

// RestartWindow is how long the leader waits for a node that announced a
// restart before it moves that node's sandboxes (SB_CLUSTER_RESTART_WINDOW,
// C8). Zero or less turns the wait off. It runs from the leave, like the
// grace, so it changes nothing unless it is longer than the grace. It takes
// a pointer so the leave callback, which runs on gossip's goroutine, reads
// this one setting and not a copy of the whole config.
func RestartWindow(cfg *config.Config) time.Duration {
	if cfg.ClusterRestartWindow <= 0 {
		return 0
	}
	return cfg.ClusterRestartWindow
}

// deadOwnerTracker holds per-node "first observed dead at" timestamps so the
// reconciler can decide which nodes have outlasted the grace period, and the
// restart deadline of each node that left announcing a restart (C8).
type deadOwnerTracker struct {
	mu        sync.Mutex
	firstSeen map[string]time.Time
	// restartUntil is when a node that left with "rs" set stops counting as
	// restarting. Every server keeps it from its own NotifyLeave, so a new
	// leader has it too, unless it joined after the leave; then the node
	// gets only the grace, which fails over sooner and never later.
	restartUntil map[string]time.Time
}

func newDeadOwnerTracker() *deadOwnerTracker {
	return &deadOwnerTracker{firstSeen: make(map[string]time.Time), restartUntil: make(map[string]time.Time)}
}

// markRestarting records that nodeID left to restart and is not to be
// judged dead before until. A second notice keeps the first deadline, so a
// node cannot extend its own window by announcing again.
func (t *deadOwnerTracker) markRestarting(nodeID string, until time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.restartUntil[nodeID]; ok {
		return
	}
	t.restartUntil[nodeID] = until
}

// restarting reports nodeID's restart deadline, if it announced one.
func (t *deadOwnerTracker) restarting(nodeID string) (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.restartUntil[nodeID]
	return until, ok
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
	delete(t.restartUntil, nodeID)
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
// records the death timestamp, and the restart deadline when the node left
// announcing a restart (C8); the periodic reconciler does the actual
// orphaning + voter removal once the grace period, or that deadline, passes.
func (c *Cluster) handleMemberLeave(nodeID string, restarting bool) {
	if nodeID == "" || nodeID == c.nodeID || c.deadOwners == nil {
		return
	}
	now := time.Now()
	c.deadOwners.markDead(nodeID, now)
	if window := RestartWindow(&c.cfg); restarting && window > 0 {
		c.deadOwners.markRestarting(nodeID, now.Add(window))
	}
}

// cancelDeadOwnerWatch is invoked from the join callback so a flapped node
// that comes back doesn't get evicted.
func (c *Cluster) cancelDeadOwnerWatch(nodeID string) {
	if c.deadOwners == nil {
		return
	}
	c.deadOwners.clear(nodeID)
	// Back in gossip, so its machine was not gone after all (C19).
	c.gone.clearGone(nodeID)
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
	if c.raft == nil {
		return
	}
	leading := c.raft.raft.State() == raft.Leader
	c.gone.observeLeadership(leading, c.raft.raft.CurrentTerm(), time.Now())
	if !leading {
		return
	}
	grace := DeadOwnerGrace(c.cfg)

	// Refresh the dead set from gossip: any tracked node that's actually
	// alive is cleared (covers events we missed during a leadership flap).
	// Nodes that are not alive are marked below, from the raft voters and
	// from the placements' owners.
	live := make(map[string]bool)
	for _, m := range c.gossip.members() {
		if m.NodeID == "" {
			continue
		}
		if m.Alive {
			live[m.NodeID] = true
			c.deadOwners.clear(m.NodeID)
			c.gone.clearGone(m.NodeID)
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

	// Every node that owns placements and gossip does not show alive. A
	// server that was down when a worker died saw no leave event, and the
	// worker may be gone from gossip too: its placements are then the only
	// sign of it (the plan's "a restarted server may miss a dead worker").
	// A mark only starts the grace; a node gossip shows alive by then is
	// cleared above on the next tick.
	for _, id := range c.fsm.ownerNodeIDs() {
		if id != c.nodeID && !live[id] {
			c.deadOwners.markDead(id, time.Now())
		}
	}

	// A deleted node is out of the gossip view, so nothing above marks it.
	// One that still owns placements (its delete failed after the deny
	// record landed and was never retried) is evicted like a dead owner.
	for nodeID := range c.fsm.deniedNodeSet() {
		if c.fsm.ownedCount(nodeID) > 0 {
			c.deadOwners.markDead(nodeID, time.Now())
		}
	}

	now := time.Now()
	for nodeID, since := range c.deadOwners.snapshot() {
		// The operator said its machine is gone (C19): once the node's own
		// lease has run out, nothing it runs is live, so the grace is not
		// needed. A gone machine is not restarting or upgrading either.
		gone := c.gone.isGone(nodeID)
		if now.Sub(since) < grace && !c.goneFailoverDue(nodeID, now) {
			continue
		}
		// A node the rollout is upgrading is restarting, not dead: no
		// failover until its step deadline (--node-timeout) passes, so a
		// restart longer than the grace moves none of its sandboxes (§6.2,
		// Codex eng finding 2). Past the deadline it is judged as before.
		if deadline, upgrading := c.fsm.upgradingDeadline(nodeID); upgrading && now.Before(deadline) && !gone {
			continue
		}
		// A node that announced a restart on SIGTERM (C8) gets the restart
		// window, for a pod or kubelet restart outside a rollout. A deleted
		// node never waits: it is not coming back.
		if until, restarting := c.deadOwners.restarting(nodeID); restarting && now.Before(until) && !gone && !c.fsm.deniedNodeSet()[nodeID] {
			continue
		}
		if live[nodeID] {
			c.deadOwners.clear(nodeID)
			continue
		}
		c.evictDeadOwner(ctx, nodeID)
	}
	// The recreate-policy sandboxes no node had room for are retried by
	// their own loop, every second (startOrphanRetryLoop, R14).
}

// evictDeadOwner handles every placement owned by nodeID (evictOwnerPlacements)
// and removes the dead node from the raft configuration. All steps are
// idempotent so a partial failure is safe to retry on the next tick: a
// placement already orphaned stays orphaned, and RemoveServer is a no-op once
// the dead node is gone. A node that rejoins mid-loop keeps what it still
// owns and stays a voter: evictOwnerPlacements stops with errOwnerRejoined,
// and the liveness check runs once more before the removal.
func (c *Cluster) evictDeadOwner(ctx context.Context, nodeID string) {
	reassigned, orphaned, err := c.evictOwnerPlacements(ctx, nodeID)
	if err != nil {
		return
	}
	if reassigned > 0 || orphaned > 0 {
		c.logger.Warn("cluster: handled placements after owner death",
			"dead_node", nodeID, "reassigned", reassigned, "orphaned", orphaned)
	}
	// A voter that came back after its sandboxes were orphaned still must
	// not be dropped from Raft: it reclaims them through ClaimOrphan.
	if c.deadOwnerRejoined(nodeID, reassigned) {
		return
	}
	c.runEvictDeadOwnerStepHook(evictStepRemoveServer, "")
	c.removeDeadOwnerServer(nodeID)
	// Its failover is done; its C19 marks and C10 facts would only fill
	// their bounded maps.
	c.gone.forget(nodeID)
	c.capacityLeases.forgetNode(nodeID)
}

// errOwnerRejoined is evictOwnerPlacements' answer when the owner shows alive
// again partway through: the sandboxes it still owns stay with it, and the
// dead-owner loop leaves it in Raft.
var errOwnerRejoined = errors.New("cluster: owner rejoined during eviction")

// evictOwnerPlacements moves every placement nodeID owns off it. Sandboxes
// that opted into failover.policy=recreate are reassigned to a live peer
// scored against their replicated spec; the owner watcher on that peer
// re-materializes the container. All remaining placements are orphaned
// (OwnerNodeID="") so the API surfaces ErrOrphaned (410 Gone). A
// recreate-policy placement orphaned only for want of room is retried by
// the leader's orphan loop (retryOrphanedRecoveries, R14). The dead-owner
// loop and an operator's node delete (node_lifecycle.go) share it. A failure
// is logged and returned after the steps that succeeded; every step is
// idempotent, so the caller's retry finishes the job.
//
// Every write is fenced on the owner, because each step is a Raft round trip
// and the world moves while the loop runs. A reassign carries nodeID as its
// expected owner: opReassign keeps the incarnation, so without that the FSM
// cannot tell a placement still on nodeID from one that another path moved
// after this loop read it, and would move it again. opOrphanOwner needs no
// extra field: it only touches rows whose owner is still nodeID when it
// applies. And before each step the owner's liveness is re-checked
// (deadOwnerRejoined), so a node that rejoins mid-loop keeps what it still
// owns instead of having it moved or orphaned under it (errOwnerRejoined). A
// deleted node never counts as rejoined, so a delete always finishes.
func (c *Cluster) evictOwnerPlacements(ctx context.Context, nodeID string) (reassigned, orphaned int, err error) {
	ids := c.fsm.idsOwnedBy(nodeID)
	for _, id := range ids {
		if c.deadOwnerRejoined(nodeID, reassigned) {
			return reassigned, 0, errOwnerRejoined
		}
		p, ok := c.fsm.get(id)
		if !ok || strings.TrimSpace(p.OwnerNodeID) != strings.TrimSpace(nodeID) {
			// Deleted, or moved off the dead node since the listing.
			continue
		}
		if !placementWantsFailoverRecreate(p) {
			continue
		}
		target, err := c.selectFailoverTarget(p, nodeID)
		if err != nil {
			// A placement rule no live node satisfies is not a reason to
			// move the sandbox somewhere it must not run: it is orphaned
			// like any other, so the node it ran on reclaims it when it
			// returns, and the refusal is counted and audited (P1.5).
			if errors.Is(err, ErrPlacementUnsatisfiable) {
				c.reportFailoverRefused(p, nodeID, err)
			}
			c.logger.Warn("cluster: no failover recreation target; placement will be orphaned",
				"sandbox_id", id, "dead_node", nodeID, "reason", err)
			continue
		}
		cmd := command{
			Op:                     opReassign,
			SandboxID:              id,
			OwnerNodeID:            target.NodeID,
			OwnerAPIURL:            target.APIURL,
			OwnerDataPlaneHost:     target.DataPlaneHost,
			ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
			ExpectedOwnerNodeID:    nodeID,
			ExpectedOwnerNodeIDSet: true,
			ReassignCause:          reassignCauseFailover,
		}
		c.runEvictDeadOwnerStepHook(evictStepReassign, id)
		if err := c.applyCommand(ctx, cmd); err != nil {
			if errors.Is(err, ErrStuckReassignNotOwner) {
				// The placement left the dead node between the read above
				// and this write; whoever moved it owns it now. Nothing to
				// retry, so the rest of the eviction goes on.
				c.logger.Info("cluster: placement moved off the dead node during eviction; leaving it with its new owner",
					"sandbox_id", id, "dead_node", nodeID, "err", err)
				continue
			}
			c.logger.Warn("cluster: reassign placement failed; will retry next tick",
				"sandbox_id", id, "dead_node", nodeID, "new_owner", target.NodeID, "err", err)
			return reassigned, 0, err
		}
		// The leader apply wrapper increments the metric only when the FSM
		// reports a real transition. reassigned is a local log counter and
		// deliberately still counts successful acknowledgements.
		reassigned++
	}
	if c.deadOwnerRejoined(nodeID, reassigned) {
		return reassigned, 0, errOwnerRejoined
	}
	orphaned = len(c.fsm.idsOwnedBy(nodeID))
	c.runEvictDeadOwnerStepHook(evictStepOrphan, "")
	if err := c.orphanOwner(ctx, nodeID); err != nil {
		c.logger.Warn("cluster: orphan dead-owner placements failed; will retry next tick",
			"dead_node", nodeID, "err", err)
		return reassigned, 0, err
	}
	return reassigned, orphaned, nil
}

// deadOwnerRejoined reports whether gossip sees nodeID alive again, and logs
// that the eviction stops. It reads the same gossip view reconcileDeadOwners
// used to decide the node was dead. The dead-owner mark is left for that
// reconciler (or the join callback) to clear.
//
// A deleted node (one with a deny record) never counts as back, even while
// its machine still runs and gossips: it is refused at peer auth, gossip and
// placement, so its sandboxes must move as the delete intends. The member
// index drops it only on its next refresh (the node delete calls
// applyDenySet after this eviction), so until then gossip can still read it
// as alive. The check lives here, the one place that decides "alive again",
// so every caller of the fence gets it.
func (c *Cluster) deadOwnerRejoined(nodeID string, reassigned int) bool {
	if c.fsm.isNodeDenied(nodeID) {
		return false
	}
	m, ok := c.gossip.lookupMember(nodeID)
	if !ok || !m.Alive {
		return false
	}
	c.logger.Warn("cluster: dead owner rejoined during eviction; leaving the sandboxes it still owns in place",
		"dead_node", nodeID, "reassigned_before_rejoin", reassigned)
	return true
}

// evictDeadOwnerStep names the write evictDeadOwner is about to make, for
// evictDeadOwnerStepHook.
type evictDeadOwnerStep string

const (
	evictStepReassign     evictDeadOwnerStep = "reassign"
	evictStepOrphan       evictDeadOwnerStep = "orphan"
	evictStepRemoveServer evictDeadOwnerStep = "remove-server"
)

func (c *Cluster) runEvictDeadOwnerStepHook(step evictDeadOwnerStep, sandboxID string) {
	if c.evictDeadOwnerStepHook != nil {
		c.evictDeadOwnerStepHook(step, sandboxID)
	}
}

func (c *Cluster) orphanOwner(ctx context.Context, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	return c.applyCommand(ctx, command{Op: opOrphanOwner, NodeID: nodeID})
}

func (c *Cluster) removeDeadOwnerServer(nodeID string) {
	// Same lock as admission: a removal that lands between another caller's
	// replica count and its AddVoter would make that count describe a
	// configuration the mutation is not applied to.
	c.raftMembershipMu.Lock()
	defer c.raftMembershipMu.Unlock()
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
	// A node can fail after committing the distributed delete fence but before
	// its final opDelete. Expire only fences whose owner is unavailable; a live
	// owner may still be retrying external artifact cleanup, and removing its
	// fence would permit ID reuse to race that lifecycle-wide finalizer.
	for _, p := range c.fsm.expiredDeletingPlacements(now) {
		if !c.deleteFenceOwnerUnavailable(p.OwnerNodeID) {
			continue
		}
		if err := c.DeletePlacementExact(ctx, p.SandboxID, p.OwnerNodeID, p.IncarnationID); err != nil {
			c.logger.Warn("cluster: expire abandoned deleting placement failed; will retry next tick",
				"sandbox_id", p.SandboxID, "owner", p.OwnerNodeID, "err", err)
			continue
		}
		c.logger.Warn("cluster: expired abandoned deleting placement",
			"sandbox_id", p.SandboxID, "owner", p.OwnerNodeID)
	}
}

func (c *Cluster) deleteFenceOwnerUnavailable(ownerNodeID string) bool {
	ownerNodeID = strings.TrimSpace(ownerNodeID)
	if c == nil || ownerNodeID == "" {
		return true
	}
	if ownerNodeID == strings.TrimSpace(c.nodeID) || c.gossip == nil {
		return false
	}
	member, ok := c.gossip.lookupMember(ownerNodeID)
	return !ok || !member.Alive
}
