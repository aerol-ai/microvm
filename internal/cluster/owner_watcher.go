package cluster

import (
	"context"
	"time"
)

// ownerWatcherInterval is the polling cadence for the owner watcher loop. The
// loop's only job is to re-materialize sandboxes whose placement was
// reassigned to this node by the dead-owner reconciler — a coarse-grained
// recovery flow where a few seconds of latency is invisible. Faster polling
// would just churn the FSM snapshot during steady state.
const ownerWatcherInterval = 5 * time.Second

// startOwnerWatcher spawns the per-node loop that bridges FSM placements into
// the service layer. It runs on every node (not just the leader): each node
// is responsible for materializing the sandboxes it owns. The loop is a no-op
// until AttachRecreator wires in the service hook.
func (c *Cluster) startOwnerWatcher() {
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
			c.logger.Warn("cluster: recreate owned sandbox failed; will retry next tick",
				"sandbox_id", id, "err", err)
		}
	}
}
