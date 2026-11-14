package cluster

import (
	"context"
	"expvar"
	"time"

	"github.com/hashicorp/raft"
)

// ShutdownPreparer is what the daemon calls on SIGTERM, before it drains its
// listeners and closes the cluster client (C8, plans/kubernetes-v2-architecture.md
// §10.2). Both cluster clients implement it; the daemon asks with a type
// assertion so the Client interface and its fakes stay as they are.
//
// A stop is read as a restart: a pod's SIGTERM, a kubelet restart, a
// systemd restart. The node tells its peers so the leader waits the restart
// window (SB_CLUSTER_RESTART_WINDOW), not only the dead-owner grace, before
// it moves the node's sandboxes, and placement sends it nothing new. A node
// that is leaving for good is deleted (`aerolvm delete node`), and a deleted
// node never gets the window. A crash sends nothing and gets the grace, as
// before.
type ShutdownPreparer interface {
	PrepareShutdown(ctx context.Context)
}

// leaderHandoffTimeout bounds the leadership hand-off on shutdown. A
// hand-off that does not finish in time is given up: the node stops anyway
// and the others elect a leader the usual way, one election timeout later.
// Kubernetes' default 30 s termination grace leaves room for it.
const leaderHandoffTimeout = 10 * time.Second

// shutdownHandoffs counts leadership hand-offs on shutdown by outcome:
// "ok", or "failed" when the node stopped as leader anyway.
var shutdownHandoffs = expvar.NewMap("aerolvm_cluster_shutdown_leader_handoffs_total")

// PrepareShutdown hands Raft leadership to another voter when this server
// leads, then announces the restart. Safe to call more than once.
func (c *Cluster) PrepareShutdown(ctx context.Context) {
	c.handOffLeadership(ctx)
	if c.gossip != nil {
		if err := c.gossip.announceRestart(restartAnnounceTimeout); err != nil && c.logger != nil {
			c.logger.Warn("cluster: restart notice not confirmed sent; peers may fail over after the grace", "error", err)
		}
	}
}

// handOffLeadership moves leadership off this server before it stops, so
// the cluster does not wait out an election timeout with no leader (lesson
// L2). It does nothing on a follower or on the only voter.
func (c *Cluster) handOffLeadership(ctx context.Context) {
	if c.raft == nil || c.raft.raft == nil || c.raft.raft.State() != raft.Leader || !c.hasOtherVoter() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, leaderHandoffTimeout)
	defer cancel()
	start := time.Now()
	resp, err := c.TransferLeadership(ctx, "")
	if err != nil {
		shutdownHandoffs.Add("failed", 1)
		if c.logger != nil {
			c.logger.Warn("cluster: leadership hand-off before shutdown failed; stopping anyway",
				"error", err, "elapsed", time.Since(start))
		}
		return
	}
	shutdownHandoffs.Add("ok", 1)
	if c.logger != nil {
		c.logger.Info("cluster: handed off leadership before shutdown",
			"to", resp.Leader, "elapsed", time.Since(start))
	}
}

// hasOtherVoter reports whether the Raft configuration holds a voter other
// than this node, the only kind leadership can move to.
func (c *Cluster) hasOtherVoter() bool {
	f := c.raft.raft.GetConfiguration()
	if f.Error() != nil {
		return false
	}
	for _, srv := range f.Configuration().Servers {
		if srv.Suffrage == raft.Voter && string(srv.ID) != c.nodeID {
			return true
		}
	}
	return false
}

// PrepareShutdown announces the restart. A worker or ingress node holds no
// Raft state, so there is nothing to hand off.
func (a *Agent) PrepareShutdown(context.Context) {
	if a.gossip == nil {
		return
	}
	if err := a.gossip.announceRestart(restartAnnounceTimeout); err != nil && a.logger != nil {
		a.logger.Warn("cluster agent: restart notice not confirmed sent; peers may fail over after the grace", "error", err)
	}
}
