package cluster

import (
	"context"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
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
//
// Role-aware policy: a peer that gossiped SB_NODE_ROLE=worker or =ingress is
// always added as a non-voter, regardless of the voter cap. Without this gate
// a 200-worker cluster grows 200 raft voters even with the cap set high, and
// stage-2 §02 (B4) treats that as a release blocker. Empty role (older builds
// without the field) is treated as "mixed" so rolling upgrades don't strand
// pre-existing voters.
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
	// Fast path, deliberately outside the membership lock: reconcileVoters
	// re-offers every gossip member every 5s, so a 2000-node fleet's steady
	// state must not queue behind a mutex that a raft round can hold for
	// commitTimeout.
	if c.memberJoinSettled(nodeID, raftAddr) {
		return
	}
	c.raftMembershipMu.Lock()
	defer c.raftMembershipMu.Unlock()
	c.applyMemberJoinLocked(nodeID, raftAddr)
}

// memberJoinSettled reports whether nodeID is already configured the way
// applyMemberJoinLocked would leave it, so the caller can skip the lock. It
// mirrors the no-op branches of applyMemberJoinLocked exactly; anything it
// gets wrong costs one extra locked re-check, never a wrong membership.
func (c *Cluster) memberJoinSettled(nodeID, raftAddr string) bool {
	srv, ok := c.configuredServer(nodeID)
	if !ok {
		return false
	}
	if string(srv.Address) != raftAddr {
		return false
	}
	if srv.Suffrage == raft.Voter {
		return !c.peerForcedNonVoter(nodeID)
	}
	return c.peerForcedNonVoter(nodeID) || c.voterCapReached()
}

// applyMemberJoinLocked decides and performs the membership mutation for
// nodeID. It must run under raftMembershipMu, which every membership mutation
// on this node takes: the replica budget is counted from the same
// configuration read the mutation is then applied to, and the AddVoter/
// AddNonvoter future only returns once the configuration entry is committed,
// so the next caller counts it. Serializing the check with the mutation is
// what makes the budget a bound rather than a suggestion — with a per-join
// goroutine, an unsynchronized count admits every concurrent joiner.
//
// raft's own compare-and-set (the prevIndex argument) cannot carry this:
// hashicorp/raft v1.7.3 builds the GetConfiguration future without
// latestIndex, so Index() is always 0 and passing it would mean "match any
// configuration". The lock is the whole guarantee, which is why RemoveServer
// takes it too.
func (c *Cluster) applyMemberJoinLocked(nodeID, raftAddr string) {
	cfgFuture := c.raft.raft.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		// Refuse rather than admit blind — the 5s reconcile loop retries, and
		// an unadmitted server is recoverable while an over-replicated log is
		// not.
		c.logger.Warn("cluster: could not read raft configuration for member join; will retry on next reconcile",
			"node_id", nodeID, "raft_addr", raftAddr, "err", err)
		return
	}
	servers := cfgFuture.Configuration().Servers
	nonVoterByRole := c.peerForcedNonVoter(nodeID)

	if srv, ok := findConfiguredServer(servers, nodeID); ok {
		// Already a replica. Address and suffrage corrections are not new
		// state carriers, so the replica budget does not apply to them.
		if srv.Suffrage == raft.Voter {
			if string(srv.Address) == raftAddr {
				return
			}
			if nonVoterByRole {
				c.addMemberAsNonvoter(nodeID, raftAddr)
				return
			}
			c.addMemberAsVoter(nodeID, raftAddr)
			return
		}
		if nonVoterByRole || voterCountFrom(servers) >= c.maxAutoVoters() {
			if string(srv.Address) == raftAddr {
				return
			}
			c.addMemberAsNonvoter(nodeID, raftAddr)
			return
		}
		c.addMemberAsVoter(nodeID, raftAddr)
		return
	}

	// This is a NEW raft replica. The membership mutator is the only place
	// that can actually bound replication: topology/placement validation
	// rejects an oversized server tier after the fact, and rejecting new
	// sandbox placement does not un-replicate a log and FSM that a surplus
	// node is already receiving. The daemon also starts the cluster before it
	// checks topology, and an open-source topology violation logs and
	// continues — so admission is the only enforcement point that holds.
	if budget := c.raftReplicaBudget(); budget > 0 && c.replicaCountFrom(servers, nodeID) >= budget {
		c.logReplicaBudgetRefusal(nodeID, raftAddr)
		return
	}

	if nonVoterByRole || voterCountFrom(servers) >= c.maxAutoVoters() {
		c.addMemberAsNonvoter(nodeID, raftAddr)
		return
	}
	c.addMemberAsVoter(nodeID, raftAddr)
}

func findConfiguredServer(servers []raft.Server, nodeID string) (raft.Server, bool) {
	for _, srv := range servers {
		if string(srv.ID) == nodeID {
			return srv, true
		}
	}
	return raft.Server{}, false
}

func voterCountFrom(servers []raft.Server) int {
	count := 0
	for _, srv := range servers {
		if srv.Suffrage == raft.Voter {
			count++
		}
	}
	return count
}

// maxAutoVoters returns the voter cap, normalized so "no cap configured"
// compares as unreachable instead of as zero.
func (c *Cluster) maxAutoVoters() int {
	if c.cfg.ClusterMaxAutoVoters <= 0 {
		return int(^uint(0) >> 1)
	}
	return c.cfg.ClusterMaxAutoVoters
}

// raftReplicaBudget is how many state-carrying raft replicas this cluster may
// hold. Every replica — voter or non-voter — receives the full log and FSM,
// which at 100k sandboxes is tens of MB of placement state plus a leader
// replication stream each.
//
// The regime matches LargeClusterTopologyError exactly, on purpose. A cluster
// at or below MaxMixedClusterNodes is the explicitly supported small/local
// topology where every node may be mixed, and every mixed node is
// server-role; capping those at the dedicated-tier budget would break a
// deployment shape the product supports. Above that line the fleet must run
// dedicated tiers, and the server tier is what MaxServerTierNodes bounds.
func (c *Cluster) raftReplicaBudget() int {
	if c == nil {
		return 0
	}
	if c.gossip == nil {
		// No membership view to classify the regime with. Use the permissive
		// small-cluster budget rather than refusing every join.
		return MaxMixedClusterNodes
	}
	if LiveMemberCount(c.gossip.members()) <= MaxMixedClusterNodes {
		return MaxMixedClusterNodes
	}
	return MaxServerTierNodes
}

// raftReplicaAdmissionBlocked reports whether admitting nodeID would push the
// configuration past the replica budget.
func (c *Cluster) raftReplicaAdmissionBlocked(nodeID string) bool {
	budget := c.raftReplicaBudget()
	if budget <= 0 {
		return false
	}
	replicas, ok := c.currentReplicaCount(nodeID)
	if !ok {
		// The configuration could not be read. Refuse rather than admit
		// blind — the 5s reconcile loop retries, and an unadmitted server is
		// recoverable while an over-replicated log is not.
		return true
	}
	return replicas >= budget
}

// currentReplicaCount counts configured raft servers other than exclude that
// still carry a replica.
//
// A member gossip reports as dead is not counted: the dead-owner reconciler
// RemoveServer's it, and counting it would block the rolling replacement the
// spare slots in MaxServerTierNodes exist for. A configured server absent
// from gossip entirely IS counted — an unknown entry is assumed to still be
// replicating.
func (c *Cluster) currentReplicaCount(exclude string) (int, bool) {
	cfg := c.raft.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		return 0, false
	}
	return c.replicaCountFrom(cfg.Configuration().Servers, exclude), true
}

// replicaCountFrom counts state-carrying replicas in an already-read
// configuration. applyMemberJoinLocked needs the count and the mutation to
// share one read, so the counting rule lives here rather than behind another
// GetConfiguration call.
//
// EVERY configured server counts, including one gossip currently reports as
// dead. It is still in the configuration, so the leader still replicates the
// log and the FSM to it, and gossip and raft partition independently — a
// member that SWIM has given up on may still be receiving entries. Handing
// its slot to a replacement is how a 7-node tier becomes a 9-node one: the
// flapped member comes back before the dead-owner reconciler removes it, and
// an already-configured server takes the existing-member path, which does not
// consult the budget at all.
//
// A slot frees when the removal is COMMITTED (dead_owner.go's RemoveServer,
// or an operator's), which is also what stops replication to it. Replacement
// therefore trails eviction rather than racing it.
func (c *Cluster) replicaCountFrom(servers []raft.Server, exclude string) int {
	count := 0
	for _, srv := range servers {
		if string(srv.ID) == exclude {
			continue
		}
		count++
	}
	return count
}

// replicaBudgetLogInterval throttles the refusal log. reconcileVoters retries
// every 5s for every gossip member, so an un-re-roled surplus server would
// otherwise fill the log forever.
const replicaBudgetLogInterval = time.Minute

func (c *Cluster) logReplicaBudgetRefusal(nodeID, raftAddr string) {
	raftReplicaAdmissionRefused.Add(1)
	now := time.Now().Unix()
	last := c.replicaBudgetLogUnix.Load()
	if now-last < int64(replicaBudgetLogInterval/time.Second) {
		return
	}
	if !c.replicaBudgetLogUnix.CompareAndSwap(last, now) {
		return
	}
	if c.logger == nil {
		return
	}
	budget := c.raftReplicaBudget()
	c.logger.Error("cluster: refusing raft replica admission; the server tier is at its budget",
		"node_id", nodeID,
		"raft_addr", raftAddr,
		"replica_budget", budget,
		"hint", "every server-role node replicates the whole placement FSM; re-role the surplus nodes to worker or ingress",
	)
}

// peerForcedNonVoter returns true when the joining peer gossiped a role that
// must never become a raft voter (worker or ingress). Empty / unknown roles
// are treated as voter-eligible so older builds (and the default "mixed"
// role) keep their pre-role-split behavior.
func (c *Cluster) peerForcedNonVoter(nodeID string) bool {
	if c.gossip == nil {
		return false
	}
	for _, m := range c.gossip.members() {
		if m.NodeID == nodeID {
			return isForcedNonVoterRole(m.Role)
		}
	}
	return false
}

// isForcedNonVoterRole reports whether a gossiped SB_NODE_ROLE must never be
// promoted to raft voter. The gossip field can carry a single role
// ("worker"), the legacy "mixed" shorthand, or a comma-separated hybrid
// combination ("worker,ingress", "server,worker"). A peer is forced non-voter
// iff its role set is non-empty, does not include "server", and is not
// "mixed". Empty role (older builds that pre-date the field) and unknown
// tokens (future roles we don't recognise yet) stay voter-eligible so a
// rolling upgrade can't accidentally demote a legitimate server peer.
func isForcedNonVoterRole(role string) bool {
	trimmed := strings.TrimSpace(role)
	if trimmed == "" {
		return false
	}
	hasKnown := false
	for raw := range strings.SplitSeq(trimmed, ",") {
		tok := strings.ToLower(strings.TrimSpace(raw))
		switch tok {
		case config.NodeRoleServer, config.NodeRoleMixed:
			return false
		case config.NodeRoleWorker, config.NodeRoleIngress:
			hasKnown = true
		}
	}
	return hasKnown
}

// addMemberAsVoter appends the voter configuration entry. Callers hold
// raftMembershipMu so the budget decision and this mutation cannot interleave
// with another membership change.
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

// addMemberAsNonvoter appends the non-voter configuration entry under the
// same lock discipline as addMemberAsVoter.
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
