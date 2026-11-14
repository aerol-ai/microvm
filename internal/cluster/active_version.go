package cluster

import (
	"context"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/hashicorp/raft"
)

// One active cluster version, in Raft (plans/kubectl-style-cluster-ops.md
// §6.5, CEO D10).
//
// Before this, each cross-node write checked "every Raft server's fv >= the
// feature's version" (raftServersRunAtLeast). Now it checks the active
// version: the newest op set every member has agreed to use. The active
// version moves only forward, and only at three points:
//
//  1. The first write. Once every Raft server runs a build that knows
//     opSetActiveVersion, the leader writes the LOWEST fv among the
//     servers. That is exactly what today's check allows, so nothing that is
//     on today turns off; and old servers never meet an op they don't know,
//     because the write waits for all of them.
//  2. Finalize. A rollout's finalize commits the target's fv (fsm_rollout.go).
//     With --hold, nothing else moves it, so rollback stays safe.
//  3. No rollout. With no rollout in flight (none, or the last one finalized
//     or rolled back), the leader moves it up to the lowest fv every live
//     member reports, servers, workers and ingress nodes alike. This keeps
//     `sandboxd upgrade node` and install.sh upgrades, which make no rollout,
//     turning features on once the whole fleet runs the new build.
//
// Until the first write the old check stands, so a cluster mid-way through
// its first upgrade into this release behaves as it always did.
//
// A member whose fv is below the active version (it was down while the
// version moved) is obsolete: it gets no placements (placement.go), and a
// server is kept out of Raft until it is upgraded (voter_autojoin.go), so it
// never replays an op it cannot apply.

// activeVersionReconcileEvery is how often the leader checks the first
// write and the no-rollout advance. Moving the version is never urgent.
const activeVersionReconcileEvery = 10 * time.Second

// ActiveFSMOpsVersion returns the active version's fv, 0 when it was never
// written.
func (c *Cluster) ActiveFSMOpsVersion() int {
	if c == nil || c.fsm == nil {
		return 0
	}
	return c.fsm.activeFVValue()
}

// raftServersSupport is the cross-node write gate: the active version when
// it exists, else today's per-server check.
func (c *Cluster) raftServersSupport(min int, feature string) error {
	if active := c.fsm.activeFVValue(); active > 0 {
		if active >= min {
			return nil
		}
		return fmt.Errorf("%w: the active cluster version is %d and %s need %d; finalize the rollout that brings it (aerolvm upgrade finalize)", ErrClusterVersion, active, feature, min)
	}
	return c.raftServersRunAtLeast(min, feature)
}

// raftServersRunAtLeast reports whether every Raft server runs a build that
// applies ops of version min. It gates the ops that must never reach a
// replica that would fail them: the rollout ops and the active version's own
// write. Every server in the Raft configuration counts, failed ones
// included: a failed server counts at its last-known gossip meta because it
// replays the log when it returns, and one with no gossip entry at all
// counts as an old build. A half-upgraded cluster answers ErrClusterVersion
// instead of committing an op some replica would skip.
func (c *Cluster) raftServersRunAtLeast(min int, feature string) error {
	future := c.raft.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return fmt.Errorf("cluster: read raft configuration: %w", err)
	}
	for _, srv := range future.Configuration().Servers {
		id := string(srv.ID)
		v := 0
		if id == c.nodeID {
			v = fsmOpsVersion
		} else if c.gossip != nil {
			if m, ok := c.gossip.lookupMember(id); ok {
				v = m.FSMOpsVersion
			}
		}
		if v < min {
			return fmt.Errorf("%w: server %s reports FSM ops version %d, %s need %d", ErrClusterVersion, id, v, feature, min)
		}
	}
	return nil
}

// reconcileActiveVersion is the leader's step for points 1 and 3 above.
func (c *Cluster) reconcileActiveVersion(ctx context.Context) {
	if c == nil || c.raft == nil || c.raft.raft == nil || c.raft.raft.State() != raft.Leader {
		return
	}
	if c.raftServersRunAtLeast(rolloutFSMOpsVersion, "the active cluster version") != nil {
		return
	}
	cur := c.fsm.activeFVValue()
	var (
		target  int
		release string
	)
	if cur == 0 {
		target, release = c.lowestServerFV()
	} else {
		r, _ := c.fsm.rolloutView()
		if !rolloutTerminal(r) {
			return
		}
		target, release = c.lowestLiveMemberFV()
		if target <= cur {
			return
		}
	}
	if target < rolloutFSMOpsVersion {
		return
	}
	res, err := c.writeActiveVersion(ctx, ActiveVersionCommand{FV: target, ExpectFV: cur, Release: release})
	if err != nil {
		c.logger.Warn("cluster: could not write the active cluster version; will retry", "fv", target, "err", err)
		return
	}
	if res.Changed {
		c.logger.Info("cluster: active cluster version moved", "from_fv", cur, "to_fv", res.Active.FV, "release", res.Active.Release)
	}
}

// writeActiveVersion proposes opSetActiveVersion on this leader.
func (c *Cluster) writeActiveVersion(ctx context.Context, cmd ActiveVersionCommand) (activeVersionApplyResult, error) {
	payload, err := encodeCommand(command{Op: opSetActiveVersion, StampUnixNano: time.Now().UnixNano(), ActiveVersion: &cmd})
	if err != nil {
		return activeVersionApplyResult{}, err
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return activeVersionApplyResult{}, err
	}
	res, _ := result.(activeVersionApplyResult)
	return res, nil
}

// lowestServerFV is the lowest fv among the Raft servers and the build of
// a server that reports it.
func (c *Cluster) lowestServerFV() (int, string) {
	future := c.raft.raft.GetConfiguration()
	if future.Error() != nil {
		return 0, ""
	}
	low, release := fsmOpsVersion, version.Version
	for _, srv := range future.Configuration().Servers {
		id := string(srv.ID)
		if id == c.nodeID {
			continue
		}
		m, ok := c.gossip.lookupMember(id)
		if !ok {
			return 0, ""
		}
		if m.FSMOpsVersion < low {
			low, release = m.FSMOpsVersion, m.Version
		}
	}
	return low, release
}

// lowestLiveMemberFV is the lowest fv any live member reports (self
// included) and that member's build.
func (c *Cluster) lowestLiveMemberFV() (int, string) {
	low, release := fsmOpsVersion, version.Version
	if c.gossip == nil {
		return low, release
	}
	for _, m := range c.gossip.members() {
		if !m.Alive || m.NodeID == c.nodeID {
			continue
		}
		if m.FSMOpsVersion < low {
			low, release = m.FSMOpsVersion, m.Version
		}
	}
	return low, release
}

// memberObsolete reports whether a member's fv is below the active
// version. A cluster whose active version was never written has none.
func (c *Cluster) memberObsolete(fv int) bool {
	active := c.fsm.activeFVValue()
	return active > 0 && fv < active
}

// peerObsolete reports whether nodeID gossips an fv below the active
// cluster version. An fv of 0 is unknown (meta not yet seen, or cut to its
// last fallback tier), never obsolete: refusing on it would push a healthy
// server out of Raft.
func (c *Cluster) peerObsolete(nodeID string) bool {
	if c.gossip == nil {
		return false
	}
	m, ok := c.gossip.lookupMember(nodeID)
	return ok && m.FSMOpsVersion > 0 && c.memberObsolete(m.FSMOpsVersion)
}

// removeObsoleteServers takes every live Raft server below the active
// version out of the configuration (§6.5, Codex outside review finding 7):
// it would fail the ops it does not know when it replays them. It comes
// back through handleMemberJoin once it runs a build at the active version.
// Dead servers are left to the dead-owner loop; self is never removed.
func (c *Cluster) removeObsoleteServers() {
	if c.fsm.activeFVValue() == 0 || c.gossip == nil {
		return
	}
	cfg := c.raft.raft.GetConfiguration()
	if cfg.Error() != nil {
		return
	}
	for _, srv := range cfg.Configuration().Servers {
		id := string(srv.ID)
		if id == c.nodeID {
			continue
		}
		m, ok := c.gossip.lookupMember(id)
		if !ok || !m.Alive || m.FSMOpsVersion == 0 || !c.memberObsolete(m.FSMOpsVersion) {
			continue
		}
		c.raftMembershipMu.Lock()
		err := c.raft.raft.RemoveServer(srv.ID, 0, c.commitTimeout).Error()
		c.raftMembershipMu.Unlock()
		if err != nil {
			c.logger.Warn("cluster: could not remove a server below the active cluster version; will retry",
				"node_id", id, "fv", m.FSMOpsVersion, "active_fv", c.fsm.activeFVValue(), "err", err)
			continue
		}
		obsoleteServersRemoved.Add(1)
		c.logger.Warn("cluster: removed a server below the active cluster version from Raft until it is upgraded",
			"node_id", id, "fv", m.FSMOpsVersion, "build", m.Version, "active_fv", c.fsm.activeFVValue())
	}
}

// membersBelowActive counts live members below the active version, for
// the alert (§10.1).
func (c *Cluster) membersBelowActive() int {
	if c == nil || c.gossip == nil || c.fsm.activeFVValue() == 0 {
		return 0
	}
	n := 0
	for _, m := range c.gossip.members() {
		if m.Alive && m.FSMOpsVersion > 0 && c.memberObsolete(m.FSMOpsVersion) {
			n++
		}
	}
	return n
}

// ActiveVersion returns the active cluster version and whether it was ever
// written.
func (c *Cluster) ActiveVersion() (ActiveVersion, bool) {
	if c == nil || c.fsm == nil {
		return ActiveVersion{}, false
	}
	return c.fsm.activeVersionView()
}
