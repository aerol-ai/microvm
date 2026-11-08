package cluster

import (
	"errors"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"
)

// No resurrection of a deleted lifecycle (C2 in
// plans/cluster-correctness-and-create-latency.md, invariant I3).
//
// A node that was cut off can come back with a local row for a sandbox the
// cluster deleted while it was away. Its ownership replay finds no placement
// for that row. Before C2 it wrote one back with the old incarnation, and the
// deleted sandbox was routable again. Three things now stop that:
//
//  1. The service asks for the row's post-delete record before replaying it,
//     and destroys the row when one exists (service.assertClusterOwnership).
//  2. opPlace refuses a missing row whose (sandbox, incarnation) still has a
//     post-delete record (ErrPlacementDeleted). This covers a delete that
//     commits between that check and the replay.
//  3. A row with no placement and no record is placed only when that cannot
//     resurrect anything (adoptUnplacedRow). Records last
//     SB_AUDIT_DELETED_GRACE, so after a longer outage their absence proves
//     nothing.
//
// Rolling upgrade: an older server ignores RefuseDeletedLifecycle and would
// apply an entry a newer one refuses. A proposer sets it only when every Raft
// server (Cluster) or every live member (Agent) runs
// deletedLifecycleFenceFSMOpsVersion, the same rule as volume reclaims. Until
// then step 1 is the guard.

// deletedLifecycleFenceFSMOpsVersion: opPlace honours RefuseDeletedLifecycle.
const deletedLifecycleFenceFSMOpsVersion = 11

// unplacedReplayClockSkew is the clock difference adoptUnplacedRow allows
// between the node that stamped a record's expiry (the deleter), the leader
// that prunes it, and this node, which stamped the row's CreatedAt.
const unplacedReplayClockSkew = time.Minute

// Reasons the ownership replay left a local row without a placement. They
// label aerolvm_cluster_ownership_replay_skipped_total.
const (
	unplacedReplayDeleted  = "deleted"
	unplacedReplayUnproven = "unproven"
)

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

// adoptUnplacedRow decides whether the ownership replay may write a placement
// for a local row that has no placement and no post-delete record.
//
// Such a row is either one the cluster never placed (a single node turned
// into a cluster, a create whose placement write failed) or one deleted so
// long ago that its record is gone. Placing the second kind resurrects it;
// destroying the first kind loses a live sandbox. The rule keeps both safe:
//
//   - soleServer: this node is the only server in its Raft configuration.
//     Nothing commits without it, so no delete happened while it was away.
//     This is how setup/cluster.md's "convert a single node into the seed of
//     a cluster" keeps its sandboxes.
//   - createdAt is younger than grace (less clock skew). A delete after the
//     row was created would still have its record, so its absence proves the
//     row was never deleted.
//
// Anything else is quarantined: not placed, not destroyed, logged and
// counted. With grace 0 no record is kept, so only a sole server places.
func adoptUnplacedRow(createdAt, now time.Time, grace time.Duration, soleServer bool) bool {
	if soleServer {
		return true
	}
	window := grace - unplacedReplayClockSkew
	if window <= 0 || createdAt.IsZero() {
		return false
	}
	return now.Sub(createdAt) < window
}

// placeUnplacedRow is AssertOwnership's step for a local row with no
// placement, shared by Cluster and Agent. It reports whether the caller should
// go on to replay the row's ports and hostnames. record writes the placement.
//
// A refusal by the deleted-lifecycle fence goes into firstErr, so the replay
// runs again; by then the service sees the post-delete record and destroys
// the row. Any other record error keeps the old behaviour (ports and
// hostnames are still replayed, as the write may have committed anyway).
func placeUnplacedRow(logger *slog.Logger, self string, st LocalSandboxState, now time.Time, grace time.Duration, soleServer bool, record func() error, firstErr *error) bool {
	if !adoptUnplacedRow(st.CreatedAt, now, grace, soleServer) {
		recordOwnershipReplaySkipped(unplacedReplayUnproven)
		logger.Warn("cluster: local sandbox has no placement and may have been deleted while this node was away; not placing it",
			"sandbox_id", st.ID, "created_at", st.CreatedAt, "audit_deleted_grace", grace, "self", self)
		return false
	}
	err := record()
	if err == nil {
		return true
	}
	if *firstErr == nil {
		*firstErr = err
	}
	if errors.Is(err, ErrPlacementDeleted) {
		recordOwnershipReplaySkipped(unplacedReplayDeleted)
		logger.Warn("cluster: local sandbox was deleted by the cluster; not placing it",
			"sandbox_id", st.ID, "incarnation_id", st.Secrets.IncarnationID, "self", self)
		return false
	}
	return true
}

// soleRaftServer reports whether this node is the only server, voter or not,
// in its Raft configuration. Any other server counts, so the answer errs on
// the side of quarantine.
func (c *Cluster) soleRaftServer() bool {
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
