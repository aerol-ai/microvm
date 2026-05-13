package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
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
// until AttachRecreator wires in the service hook.
func (c *Cluster) startOwnerWatcher() {
	c.recreateFailures = &recreateFailureTracker{counts: make(map[string]int)}
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
// instead of looping forever on a permanent failure.
type recreateFailureTracker struct {
	mu     sync.Mutex
	counts map[string]int
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
	placements := c.fsm.snapshot()
	for id, p := range placements {
		if p.OwnerNodeID != c.nodeID {
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
		var ports map[int]string
		if len(p.ExposedPorts) > 0 {
			ports = make(map[int]string, len(p.ExposedPorts))
			for k, v := range p.ExposedPorts {
				ports[k] = v
			}
		}
		if err := r.RecreateSandbox(ctx, id, spec, ports); err != nil {
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
	target, ok := c.selectRecreationTargetExcluding(p.Spec, c.nodeID)
	if !ok {
		c.logger.Warn("cluster: no alternate node available for stuck placement; will keep retrying locally",
			"sandbox_id", id)
		return
	}
	cmd := command{Op: opReassign, SandboxID: id, OwnerNodeID: target.NodeID, OwnerAPIURL: target.APIURL}
	if err := c.applyCommand(ctx, cmd); err != nil {
		c.logger.Warn("cluster: reassign stuck placement failed; will retry on next tick",
			"sandbox_id", id, "target", target.NodeID, "err", err)
		return
	}
	c.recreateFailures.clear(id)
	c.logger.Warn("cluster: reassigned stuck placement to alternate owner",
		"sandbox_id", id, "from", c.nodeID, "to", target.NodeID)
}

// selectRecreationTargetExcluding picks a placement target for spec, skipping
// any node ID listed in exclude. Returns ok=false if no candidate fits — the
// caller should NOT clear or orphan the placement in that case; better to keep
// trying locally than abandon a sandbox the operator can fix by adding capacity.
func (c *Cluster) selectRecreationTargetExcluding(spec *models.CreateSandboxRequest, exclude ...string) (PlacementTarget, bool) {
	if spec == nil {
		return PlacementTarget{}, false
	}
	excluded := make(map[string]struct{}, len(exclude))
	for _, id := range exclude {
		excluded[id] = struct{}{}
	}
	req := capacity.Request{CPU: spec.CPU, MemoryMB: spec.MemoryMB}
	if req.CPU <= 0 {
		req.CPU = models.DefaultCPU
	}
	if req.MemoryMB <= 0 {
		req.MemoryMB = models.DefaultMemoryMB
	}
	// Score every alive candidate that isn't excluded; pick the one with the
	// highest headroom. We don't use power-of-two here because the candidate
	// set is already filtered (and likely small after excludes) — full scan
	// gives a deterministic best-fit, which matters more for recovery than
	// for steady-state placement spread.
	all := c.gossip.members()
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
		if m.APIURL == "" && m.NodeID != c.nodeID {
			continue
		}
		if !nodeFits(m, req) {
			continue
		}
		s := headroomScore(m, req)
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
		return PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, IsSelf: true}, true
	}
	return PlacementTarget{NodeID: best.NodeID, APIURL: best.APIURL, IsSelf: false}, true
}
