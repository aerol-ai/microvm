package cluster

import (
	"context"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

// voterAutoJoinDelegate bridges memberlist membership events into the cluster
// so the raft leader can react to joins and leaves automatically. Only the
// leader acts on these events; followers ignore them since raft membership
// changes go through the leader's log.
//
// Phase 2 behavior:
//   - NotifyJoin: AddVoter on the leader (this file).
//   - NotifyLeave: arms a grace timer; on expiry the leader orphans the
//     dead node's placements and RemoveServer's it from the raft config
//     (see dead_owner.go).
//   - NotifyUpdate: ignored — metadata churn doesn't change membership.
//
// Why we don't auto-evict immediately on Leave: gossip will mis-mark a node
// dead during transient network blips and long GC pauses. Consul shipped
// without a grace period and operators got burned; we don't repeat it.
type voterAutoJoinDelegate struct {
	c *Cluster
}

func (d *voterAutoJoinDelegate) NotifyJoin(n *memberlist.Node) {
	if d.c == nil || n == nil {
		return
	}
	go d.c.handleMemberJoin(n.Name)
	// A join event also clears any in-flight dead-owner timer for this node:
	// a flapped peer that comes back is not actually dead.
	go d.c.cancelDeadOwnerWatch(n.Name)
}

func (d *voterAutoJoinDelegate) NotifyLeave(n *memberlist.Node) {
	if d.c == nil || n == nil {
		return
	}
	go d.c.handleMemberLeave(n.Name)
}

func (d *voterAutoJoinDelegate) NotifyUpdate(*memberlist.Node) {}

// handleMemberJoin tries to add nodeID as a raft voter. Idempotent and
// leader-gated. Failures are logged at warn — the periodic reconcile loop
// will retry.
func (c *Cluster) handleMemberJoin(nodeID string) {
	if nodeID == "" || nodeID == c.nodeID {
		return
	}
	if c.raft == nil || c.raft.raft.State() != raft.Leader {
		return
	}
	raftAddr := c.peerRaftAddr(nodeID)
	if raftAddr == "" {
		// Metadata hasn't propagated yet. The reconcile loop will catch this.
		return
	}
	if c.alreadyVoter(nodeID, raftAddr) {
		return
	}
	f := c.raft.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(raftAddr), 0, c.commitTimeout)
	if err := f.Error(); err != nil {
		c.logger.Warn("cluster: auto-AddVoter failed; will retry on next reconcile",
			"node_id", nodeID, "raft_addr", raftAddr, "err", err)
		return
	}
	c.logger.Info("cluster: auto-promoted member to raft voter",
		"node_id", nodeID, "raft_addr", raftAddr)
}

// alreadyVoter returns true if nodeID is in the current raft configuration at
// raftAddr. We compare both ID and address so a re-bound peer with a new port
// is re-added rather than silently skipped.
func (c *Cluster) alreadyVoter(nodeID, raftAddr string) bool {
	cfg := c.raft.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		return false
	}
	for _, srv := range cfg.Configuration().Servers {
		if string(srv.ID) == nodeID && string(srv.Address) == raftAddr {
			return true
		}
	}
	return false
}

// peerRaftAddr looks up the raft transport address advertised by nodeID via
// gossip. Returns "" if unknown.
func (c *Cluster) peerRaftAddr(nodeID string) string {
	if c.gossip == nil {
		return ""
	}
	for _, m := range c.gossip.members() {
		if m.NodeID == nodeID {
			return m.RaftAddr
		}
	}
	return ""
}

// startVoterReconcileLoop spawns a goroutine that periodically reconciles the
// raft configuration against gossip-known members. This is the safety net for
// the join-event race (gossip metadata propagates after the join notification)
// and for transient leadership changes during a join.
func (c *Cluster) startVoterReconcileLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	c.voterReconcileStop = cancel
	go func() {
		// Slow tick — auto-promotion is best-effort and the join event handles
		// the fast path. 5s is fast enough that operators don't notice it on
		// fresh-cluster boot but slow enough to be invisible at steady state.
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.reconcileVoters()
			}
		}
	}()
}

// reconcileVoters scans gossip members and ensures every alive node with a
// known RaftAddr is a raft voter. No-op when self is not the leader.
func (c *Cluster) reconcileVoters() {
	if c.raft == nil || c.raft.raft.State() != raft.Leader {
		return
	}
	for _, m := range c.gossip.members() {
		if m.NodeID == "" || m.NodeID == c.nodeID || !m.Alive || m.RaftAddr == "" {
			continue
		}
		c.handleMemberJoin(m.NodeID)
	}
}
