package cluster

import (
	"errors"
	"log/slog"

	"github.com/hashicorp/raft"
)

// No resurrection of a deleted lifecycle (C2 in
// plans/cluster-correctness-and-create-latency.md, invariant I3).
//
// A node that was cut off can come back with a local row for a sandbox the
// cluster deleted while it was away. Its ownership replay finds no placement
// for that row. Before C2 it wrote one back with the old incarnation, and the
// deleted sandbox was routable again. Two things now stop that:
//
//  1. The service decides what happens to a local row with no placement
//     before it reaches AssertOwnership (service.settleUnplacedRow): it
//     destroys the row unless the row is provably not a deleted sandbox. One
//     of the two proofs is that this node is the only Raft server
//     (SoleRaftServer).
//  2. opPlace refuses a missing row whose (sandbox, incarnation) still has a
//     post-delete record (ErrPlacementDeleted). This covers a delete that
//     commits between the service's check and the replay.
//
// Rolling upgrade: an older server ignores RefuseDeletedLifecycle and would
// apply an entry a newer one refuses. A proposer sets it only when every Raft
// server (Cluster) or every live member (Agent) runs
// deletedLifecycleFenceFSMOpsVersion, the same rule as volume reclaims. Until
// then step 1 is the guard.

// deletedLifecycleFenceFSMOpsVersion: opPlace honours RefuseDeletedLifecycle.
const deletedLifecycleFenceFSMOpsVersion = 11

func (c *Cluster) deletedLifecycleFenceReplicated() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	return c.raftServersSupport(deletedLifecycleFenceFSMOpsVersion, "deleted-lifecycle fence") == nil
}

func (a *Agent) deletedLifecycleFenceReplicated() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(deletedLifecycleFenceFSMOpsVersion)
}

// placeUnplacedRow is AssertOwnership's step for a local row with no
// placement, shared by Cluster and Agent. record writes the placement. It
// reports whether the caller should go on to replay the row's ports and
// hostnames.
//
// A refusal by the deleted-lifecycle fence goes into firstErr, so the replay
// runs again; by then the service sees the post-delete record and destroys
// the row. Any other record error keeps the old behaviour (ports and
// hostnames are still replayed, as the write may have committed anyway).
func placeUnplacedRow(logger *slog.Logger, self string, st LocalSandboxState, record func() error, firstErr *error) bool {
	err := record()
	if err == nil {
		return true
	}
	if *firstErr == nil {
		*firstErr = err
	}
	if errors.Is(err, ErrPlacementDeleted) {
		recordOwnershipReplayRefused()
		logger.Warn("cluster: local sandbox was deleted by the cluster; not placing it",
			"sandbox_id", st.ID, "incarnation_id", st.Secrets.IncarnationID, "self", self)
		return false
	}
	return true
}

// SoleServerReporter is implemented by the clients that run Raft themselves
// (*Cluster). A worker Agent and the single-node Noop do not.
type SoleServerReporter interface {
	SoleRaftServer() bool
}

// SoleRaftServer reports whether c's node is the only server in its Raft
// configuration. Nothing commits without such a node, so no delete can have
// happened while it was away. Clients without a local Raft report false.
func SoleRaftServer(c Client) bool {
	r, ok := c.(SoleServerReporter)
	return ok && r.SoleRaftServer()
}

// SoleRaftServer reports whether this node is the only server, voter or not,
// in its Raft configuration. Any other server counts, so the answer errs on
// the side of "not sole".
func (c *Cluster) SoleRaftServer() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	future := c.raft.raft.GetConfiguration()
	if future.Error() != nil {
		return false
	}
	servers := future.Configuration().Servers
	return len(servers) == 1 && servers[0].ID == raft.ServerID(c.nodeID)
}
