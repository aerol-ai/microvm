package cluster

import (
	"context"
	"errors"
	"log/slog"
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
		recreateOwnedPlacement(ctx, ownerRecreateDeps{
			recreator: r,
			failures:  c.recreateFailures,
			logger:    c.logger,
			escalate: func(ctx context.Context, id string, p Placement) {
				// The local watcher keeps retrying on failure; the log in
				// tryReassignStuckPlacement already carries the reason.
				_ = c.tryReassignStuckPlacement(ctx, id, p)
			},
		}, id, p)
	}
}

// ownerRecreateDeps is everything one owner-recreate attempt needs. It exists
// so the dedicated-worker loop and the server-side owner watcher run the SAME
// recreation, failure-accounting and escalation logic: a worker that cannot
// recreate its reassigned sandboxes is a failover that silently did not
// happen, and a second copy of this logic is how the two would drift.
type ownerRecreateDeps struct {
	recreator SandboxRecreator
	failures  *recreateFailureTracker
	logger    *slog.Logger
	// escalate hands a repeatedly failing placement to whoever can move it.
	// The server does it through its own FSM; a worker asks the leader.
	escalate func(context.Context, string, Placement)
}

func recreateOwnedPlacement(ctx context.Context, deps ownerRecreateDeps, id string, p Placement) {
	if deps.recreator == nil {
		return
	}
	if !placementWantsFailoverRecreate(p) {
		return
	}
	if deps.failures != nil && deps.failures.isPermanent(id) {
		return
	}
	if p.Spec == nil {
		// Pre-cluster sandbox or never-replicated spec. Without a spec we
		// can't reconstruct the container; leave it unhandled. The
		// dead-owner reconciler still won't reassign such placements
		// because there's no way to recover them.
		return
	}
	spec := *p.Spec
	ports := exposedPortRoutesForPlacement(p)
	// Pass the secret provider handle through unchanged — only the service
	// is allowed to resolve and merge credentials.
	attempted := true
	var err error
	if reporter, ok := deps.recreator.(SandboxRecreateReporter); ok {
		attempted, err = reporter.RecreateSandboxReport(ctx, id, spec, secretsFromPlacement(p), ports)
	} else {
		err = deps.recreator.RecreateSandbox(ctx, id, spec, secretsFromPlacement(p), ports)
	}
	if attempted || err != nil {
		recordFailoverRecreate(err)
	}
	if err == nil {
		if deps.failures != nil {
			deps.failures.clear(id)
		}
		return
	}
	// Recipient-denied cannot be fixed by reassigning to another
	// arbitrary node (D5 / outside-voice #7) — stop churn permanently.
	if errors.Is(err, secrets.ErrRecipientDenied) {
		if deps.failures != nil {
			deps.failures.markPermanent(id)
		}
		if deps.logger != nil {
			deps.logger.Error("cluster: recreate permanently failed: recipient denied; not reassigning",
				"sandbox_id", id, "err", err)
		}
		return
	}
	fails := 0
	if deps.failures != nil {
		fails = deps.failures.record(id)
	}
	if deps.logger != nil {
		deps.logger.Warn("cluster: recreate owned sandbox failed",
			"sandbox_id", id, "consecutive_failures", fails, "err", err)
	}
	if fails >= maxRecreateFailuresBeforeReassign && deps.escalate != nil {
		deps.escalate(ctx, id, p)
	}
}

// ErrNoReassignTarget reports that no live node other than the failing owner
// can host the placement. The caller keeps retrying where it is rather than
// orphaning a recoverable sandbox — but it must not be told the placement
// moved, or it resets the failure counter that drives the escalation.
var ErrNoReassignTarget = errors.New("cluster: no alternate node available for stuck placement")

// tryReassignStuckPlacement asks the cluster to hand a stuck placement to a
// different node. It excludes the node the placement is stuck ON — which is
// the placement's current owner, NOT necessarily the node running this code.
// The local watcher is the owner, so the two coincided; the worker RPC path
// runs on a control-plane server, and excluding that server instead left the
// failing worker in the candidate set. With the most free capacity it would
// be chosen again and the RPC would report success, resetting the very
// failure counter that asked for the move.
//
// Returns nil only when the FSM accepted a fenced ownership transition, so
// the caller's "reassigned" bookkeeping reflects something that happened.
func (c *Cluster) tryReassignStuckPlacement(ctx context.Context, id string, p Placement) error {
	if !placementWantsFailoverRecreate(p) {
		return ErrNoReassignTarget
	}
	stuckOwner := strings.TrimSpace(p.OwnerNodeID)
	if stuckOwner == "" {
		// An orphaned placement has no owner to avoid; keep the old
		// self-exclusion so a server that just failed it isn't re-elected.
		stuckOwner = c.nodeID
	}
	target, ok := c.selectRecreationTarget(p, stuckOwner)
	if !ok {
		c.logger.Warn("cluster: no alternate node available for stuck placement; will keep retrying locally",
			"sandbox_id", id, "stuck_owner", stuckOwner)
		return ErrNoReassignTarget
	}
	cmd := command{
		Op:                 opReassign,
		SandboxID:          id,
		OwnerNodeID:        target.NodeID,
		OwnerAPIURL:        target.APIURL,
		OwnerDataPlaneHost: target.DataPlaneHost,
		// Fence BOTH axes through the mutation. opReassign preserves the
		// incarnation, so the incarnation CAS alone cannot tell "still stuck
		// on the owner I read" from "already moved to a new owner" — and a
		// late escalation must not bounce a sandbox off the node that has
		// just taken it over.
		ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
		ExpectedOwnerNodeID:    stuckOwner,
		ExpectedOwnerNodeIDSet: true,
		ReassignCause:          reassignCauseFailover,
	}
	if err := c.applyCommand(ctx, cmd); err != nil {
		c.logger.Warn("cluster: reassign stuck placement failed; will retry on next tick",
			"sandbox_id", id, "target", target.NodeID, "err", err)
		return err
	}
	// The leader apply wrapper increments the metric only when its FSM reports
	// a real transition. This acknowledgement is deliberately not used as the
	// metric signal because this path can forward to a remote leader.
	c.recreateFailures.clear(id)
	c.logger.Warn("cluster: reassigned stuck placement to alternate owner",
		"sandbox_id", id, "from", stuckOwner, "to", target.NodeID)
	return nil
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
