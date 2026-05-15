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
//   - NotifyJoin: AddVoter on the leader until the configured voter cap is
//     reached, then AddNonvoter for additional nodes (this file).
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

// handleMemberJoin tries to add nodeID to the raft configuration. It promotes
// members to voters until ClusterMaxAutoVoters is reached, then adds later
// members as non-voters so they keep a replicated FSM without increasing
// quorum size. Idempotent and leader-gated. Failures are logged at warn — the
// periodic reconcile loop will retry.
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

	if srv, ok := c.configuredServer(nodeID); ok {
		if srv.Suffrage == raft.Voter {
			if string(srv.Address) == raftAddr {
				return
			}
			c.addMemberAsVoter(nodeID, raftAddr)
			return
		}
		if c.voterCapReached() {
			if string(srv.Address) == raftAddr {
				return
			}
			c.addMemberAsNonvoter(nodeID, raftAddr)
			return
		}
		c.addMemberAsVoter(nodeID, raftAddr)
		return
	}

	if c.voterCapReached() {
		c.addMemberAsNonvoter(nodeID, raftAddr)
		return
	}
	c.addMemberAsVoter(nodeID, raftAddr)
}

func (c *Cluster) addMemberAsVoter(nodeID, raftAddr string) {
	f := c.raft.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(raftAddr), 0, c.commitTimeout)
	if err := f.Error(); err != nil {
		c.logger.Warn("cluster: auto-AddVoter failed; will retry on next reconcile",
			"node_id", nodeID, "raft_addr", raftAddr, "err", err)
		return
	}
	c.logger.Info("cluster: auto-promoted member to raft voter",
		"node_id", nodeID, "raft_addr", raftAddr)
}

func (c *Cluster) addMemberAsNonvoter(nodeID, raftAddr string) {
	f := c.raft.raft.AddNonvoter(raft.ServerID(nodeID), raft.ServerAddress(raftAddr), 0, c.commitTimeout)
	if err := f.Error(); err != nil {
		c.logger.Warn("cluster: auto-AddNonvoter failed; will retry on next reconcile",
			"node_id", nodeID, "raft_addr", raftAddr, "err", err)
		return
	}
	c.logger.Info("cluster: added member as raft non-voter because voter cap is reached",
		"node_id", nodeID, "raft_addr", raftAddr, "max_auto_voters", c.cfg.ClusterMaxAutoVoters)
}

func (c *Cluster) voterCapReached() bool {
	max := c.cfg.ClusterMaxAutoVoters
	if max <= 0 {
		return false
	}
	count, ok := c.currentVoterCount()
	if !ok {
		// If we cannot read the configuration, avoid promoting another voter.
		return true
	}
	return count >= max
}

func (c *Cluster) currentVoterCount() (int, bool) {
	cfg := c.raft.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		return 0, false
	}
	count := 0
	for _, srv := range cfg.Configuration().Servers {
		if srv.Suffrage == raft.Voter {
			count++
		}
	}
	return count, true
}

func (c *Cluster) configuredServer(nodeID string) (raft.Server, bool) {
	cfg := c.raft.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		return raft.Server{}, false
	}
	for _, srv := range cfg.Configuration().Servers {
		if string(srv.ID) == nodeID {
			return srv, true
		}
	}
	return raft.Server{}, false
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
// known RaftAddr is present in the raft configuration. No-op when self is not
// the leader.
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
