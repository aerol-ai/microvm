package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// ownerWatcherInterval is the polling cadence for the owner watcher loop. The
// loop's only job is to re-materialize sandboxes whose placement was
// reassigned to this node by the dead-owner reconciler — a coarse-grained
// recovery flow where a few seconds of latency is invisible. Faster polling
// would just churn the FSM snapshot during steady state.
const ownerWatcherInterval = 5 * time.Second

// maxRecreateFailuresBeforeReassign is the consecutive-failure threshold at
// which the watcher gives up on local recreation and asks the cluster to
// reassign the placement to a different node. The previous behavior was to
// retry forever on the same owner — a permanent local failure (image not
// pullable, runtime missing, capacity gone, etc.) would leave the placement
// stuck without ever trying an alternate target. Five attempts at 5s intervals
// = ~25s before we look for a new home.
const maxRecreateFailuresBeforeReassign = 5

// startOwnerWatcher spawns the per-node loop that bridges FSM placements into
// the service layer. It runs on every node (not just the leader): each node
// is responsible for materializing the sandboxes it owns. The loop is a no-op
// until AttachRecreator wires in the service hook. Only placements whose spec
// opts into failover.policy=recreate are materialized; all others remain
// ordinary non-HA sandboxes and are orphaned when their owner dies.
func (c *Cluster) startOwnerWatcher() {
	c.recreateFailures = &recreateFailureTracker{counts: make(map[string]int), permanent: make(map[string]struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	c.ownerWatcherStop = cancel
	go func() {
		t := time.NewTicker(ownerWatcherInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.recreateOwnedSandboxes(ctx)
			}
		}
	}()
}

// recreateFailureTracker counts consecutive recreate failures per sandbox so
// the watcher can escalate from "retry locally" to "ask for reassignment"
// instead of looping forever on a permanent failure. permanent holds ids that
// must not be reassigned (e.g. recipient-denied — walking the fleet cannot help).
type recreateFailureTracker struct {
	mu        sync.Mutex
	counts    map[string]int
	permanent map[string]struct{}
}

func (t *recreateFailureTracker) record(id string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counts[id]++
	return t.counts[id]
}

func (t *recreateFailureTracker) clear(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.counts, id)
}

func (t *recreateFailureTracker) markPermanent(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.permanent == nil {
		t.permanent = make(map[string]struct{})
	}
	t.permanent[id] = struct{}{}
	delete(t.counts, id)
}

func (t *recreateFailureTracker) isPermanent(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.permanent[id]
	return ok
}

// recreateOwnedSandboxes scans the FSM for placements where this node is the
// owner and a spec is available, and asks the service layer to recreate any
// that aren't already present locally. The recreator is responsible for
// idempotency (existing sandboxes are no-ops). One slow recreate must not
// block the others — we run sequentially today; if recreate latency becomes a
// problem we can fan out, but typical failover bursts are <100 sandboxes.
func (c *Cluster) recreateOwnedSandboxes(ctx context.Context) {
	r := c.currentRecreator()
	if r == nil {
		return
	}
	placements := c.fsm.fullPlacementsForOwner(c.nodeID)
	for id, p := range placements {
		if !placementWantsFailoverRecreate(p) {
			continue
		}
		if c.recreateFailures != nil && c.recreateFailures.isPermanent(id) {
			continue
		}
		if p.Spec == nil {
			// Pre-cluster sandbox or never-replicated spec. Without a spec we
			// can't reconstruct the container; leave it unhandled. The
			// dead-owner reconciler still won't reassign such placements
			// because there's no way to recover them.
			continue
		}
		spec := *p.Spec
		ports := exposedPortRoutesForPlacement(p)
		// Pass the secret provider handle through unchanged — only the service
		// is allowed to resolve and merge credentials.
		attempted := true
		var err error
		if reporter, ok := r.(SandboxRecreateReporter); ok {
			attempted, err = reporter.RecreateSandboxReport(ctx, id, spec, secretsFromPlacement(p), ports)
		} else {
			err = r.RecreateSandbox(ctx, id, spec, secretsFromPlacement(p), ports)
		}
		if attempted || err != nil {
			recordFailoverRecreate(err)
		}
		if err != nil {
			// Recipient-denied cannot be fixed by reassigning to another
			// arbitrary node (D5 / outside-voice #7) — stop churn permanently.
			if errors.Is(err, secrets.ErrRecipientDenied) {
				if c.recreateFailures != nil {
					c.recreateFailures.markPermanent(id)
				}
				c.logger.Error("cluster: recreate permanently failed: recipient denied; not reassigning",
					"sandbox_id", id, "err", err)
				continue
			}
			fails := c.recreateFailures.record(id)
			c.logger.Warn("cluster: recreate owned sandbox failed",
				"sandbox_id", id, "consecutive_failures", fails, "err", err)
			if fails >= maxRecreateFailuresBeforeReassign {
				c.tryReassignStuckPlacement(ctx, id, p)
			}
			continue
		}
		c.recreateFailures.clear(id)
	}
}

// tryReassignStuckPlacement asks the cluster to hand a stuck placement to a
// different node. Excludes self from the candidate set — there's no point
// re-electing the node that's been failing — and is a no-op if no other live
// node can fit the spec (we keep retrying locally rather than orphan a
// recoverable placement). The failure counter resets on a successful
// reassign so the new owner gets a fresh window.
func (c *Cluster) tryReassignStuckPlacement(ctx context.Context, id string, p Placement) {
	if !placementWantsFailoverRecreate(p) {
		return
	}
	target, ok := c.selectRecreationTarget(p, c.nodeID)
	if !ok {
		c.logger.Warn("cluster: no alternate node available for stuck placement; will keep retrying locally",
			"sandbox_id", id)
		return
	}
	cmd := command{
		Op:                    opReassign,
		SandboxID:             id,
		OwnerNodeID:           target.NodeID,
		OwnerAPIURL:           target.APIURL,
		OwnerDataPlaneHost:    target.DataPlaneHost,
		ExpectedIncarnationID: strings.TrimSpace(p.IncarnationID),
		ReassignCause:         reassignCauseFailover,
	}
	if err := c.applyCommand(ctx, cmd); err != nil {
		c.logger.Warn("cluster: reassign stuck placement failed; will retry on next tick",
			"sandbox_id", id, "target", target.NodeID, "err", err)
		return
	}
	// The leader apply wrapper increments the metric only when its FSM reports
	// a real transition. This acknowledgement is deliberately not used as the
	// metric signal because this path can forward to a remote leader.
	c.recreateFailures.clear(id)
	c.logger.Warn("cluster: reassigned stuck placement to alternate owner",
		"sandbox_id", id, "from", c.nodeID, "to", target.NodeID)
}

// selectRecreationTarget picks a placement target for a failover recreate,
// skipping any node ID listed in exclude. A placement with sealed secrets is
// restricted to its replicated recipient set: those are the only nodes that
// can both hold and decrypt the local-provider row. Placements without a
// secret handle retain ordinary fleet-wide placement behavior.
func (c *Cluster) selectRecreationTarget(p Placement, exclude ...string) (PlacementTarget, bool) {
	spec := p.Spec
	if spec == nil {
		return PlacementTarget{}, false
	}
	if spec.ImageDistributionMode == models.ImageDistributionLocalOnly {
		return PlacementTarget{}, false
	}
	excluded := make(map[string]struct{}, len(exclude))
	for _, id := range exclude {
		excluded[id] = struct{}{}
	}
	req := capacityRequestFromSpec(spec)
	// Preserve the existing O(1) power-of-two placement path for the initial
	// failover of a sandbox that has no secret row. The full deterministic scan
	// is needed only when exclusions apply or a small recipient set constrains
	// the candidates.
	if !placementHasSecretHandle(p) && len(exclude) == 0 {
		target, err := c.SelectPlacement(req)
		return target, err == nil
	}
	drained := c.fsm.drainedNodesSnapshot()
	// Score every eligible candidate that isn't excluded and pick the one with
	// the highest headroom. Secret-bearing placements normally have only the
	// owner plus two backups, so the recipient lookup remains O(recipients)
	// rather than scanning a 2,000-node fleet for every failed sandbox.
	all := c.recreationCandidates(p)
	pending := c.fsm.pendingReservationsByNode(time.Now().Unix())
	var best Member
	bestScore := -1.0
	found := false
	for _, m := range all {
		if !m.Alive {
			continue
		}
		if _, skip := excluded[m.NodeID]; skip {
			continue
		}
		if !CanOwnSandboxRole(m.Role) {
			continue
		}
		if req.RequiredNodeID != "" && m.NodeID != req.RequiredNodeID {
			continue
		}
		if drained[m.NodeID] {
			continue
		}
		if m.APIURL == "" && m.NodeID != c.nodeID {
			continue
		}
		if !nodeFits(m, req, pending[m.NodeID]) {
			continue
		}
		s := headroomScore(m, req, pending[m.NodeID])
		if !found || s > bestScore {
			best = m
			bestScore = s
			found = true
		}
	}
	if !found {
		return PlacementTarget{}, false
	}
	if best.NodeID == c.nodeID {
		return PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost, IsSelf: true}, true
	}
	return PlacementTarget{NodeID: best.NodeID, APIURL: best.APIURL, DataPlaneHost: best.DataPlaneHost, IsSelf: false}, true
}

// recreationCandidates returns the existing fleet gossip view for a stuck
// sandbox without sealed secrets. When a handle is present it resolves only
// the recorded recipient IDs through the gossip index, because a non-recipient
// cannot open (and normally does not even store) the local secret row.
func (c *Cluster) recreationCandidates(p Placement) []Member {
	if !placementHasSecretHandle(p) {
		// This path is used only for stuck-owner reassignment (initial
		// secretless failover returned through SelectPlacement above). Preserve
		// its existing gossip-view behavior.
		return c.gossip.members()
	}
	if c == nil || c.gossip == nil {
		return nil
	}
	recipientIDs := normalizeSecretRecipientIDs(p.SecretRecipients)
	members := make([]Member, 0, len(recipientIDs))
	for _, id := range recipientIDs {
		if member, ok := c.gossip.lookupMember(id); ok {
			members = append(members, member)
		}
	}
	if c.capacityLeases != nil {
		members = c.capacityLeases.apply(members, time.Now())
	}
	return members
}

func placementHasSecretHandle(p Placement) bool {
	return strings.TrimSpace(p.SecretRef) != "" || p.SecretVersion != 0 || p.SecretSealGeneration != 0
}
