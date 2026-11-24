package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Sandboxes left on a deleted node.
//
// `aerolvm delete node` writes the node's deny record first, then hands what
// the node held to the rest of the cluster (node_lifecycle.go,
// evictOwnerPlacements). From the deny commit the node can finish nothing:
// every member refuses it as a peer, so its Raft writes and its secret
// deletes fail, and gossip drops it, so no member has an InternalURL to
// forward a call to it either (and the mTLS rule never forwards without
// one). Whatever it held must therefore be finished by the server tier:
//
//   - a reservation: cancelled by opOrphanOwner;
//   - a placed sandbox (running or stopped): reassigned when it has the
//     recreate policy, otherwise orphaned;
//   - a deleting placement (a delete the node had started): the leader
//     finishes the delete while it evicts the node. opOrphanOwner leaves a
//     deleting placement with its owner, so the owner can finish its own
//     delete; a deleted node never will. Before this the placement stayed on
//     the deleted node until the fence's TTL ran out, and every DELETE in the
//     meantime was routed to a node that was gone and answered 503.
//
// A DELETE of a sandbox whose placement is still on the deleted node (the
// moment between the deny and the hand-off) or was orphaned from it is run
// by a server, never forwarded to the node: the router sends it to one
// (pkg/api/clusterroute), and the service deletes the placement there
// (DeleteAbandonedPlacement). An orphan of a node that only died keeps its
// 410: that node may still come back and claim it.
//
// Every write here is the existing opDelete with its exact owner and
// incarnation compare, the one the leader's fence expiry and the operator's
// orphan delete already send. No new op, so no version gate, and replay is
// as safe as it is for those: a delete that lost a race to another write
// changes nothing, and the caller reads again.

// ErrPlacementNotAbandoned is a delete for a sandbox whose placement is no
// longer left on a deleted node: it moved to a live node after it was read
// (a failover reassign won the race). The caller sends the delete again, and
// the router takes it to that node.
var ErrPlacementNotAbandoned = errors.New("cluster: the sandbox's placement moved to a live node; send the delete again")

// abandonedDeleteAttempts bounds DeleteAbandonedPlacement's read-and-delete
// rounds. The leader can change the placement under it at most twice for
// one node delete (orphan it, then a recreate retry moves it), so three
// rounds settle every race that is not a live owner.
const abandonedDeleteAttempts = 3

// NodeDeleted reports whether nodeID was deleted (aerolvm delete node), from
// c's deny set: the FSM on a server, the polled mirror on a worker or
// gateway. Unlike IsDeniedPeer it counts nothing; the router asks it about a
// placement's owner, not about a peer that called in.
func NodeDeleted(c Client, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	checker, ok := c.(DeniedNodeChecker)
	return ok && nodeID != "" && checker.IsNodeDenied(nodeID)
}

// PlacementAbandoned reports whether p is left on a deleted node: p still
// names it as owner, or p was orphaned from it. A reservation never is: the
// create that made it owns its rollback, and opOrphanOwner cancels it.
func PlacementAbandoned(c Client, p Placement) bool {
	if p.IsReserved() || strings.TrimSpace(p.IncarnationID) == "" {
		return false
	}
	node := p.OwnerNodeID
	if p.IsOrphaned() {
		node = p.OrphanedOwnerNodeID
	}
	return NodeDeleted(c, node)
}

// AbandonedPlacementDeleter is implemented by Cluster. Only a server may
// delete a placement another node owns (peer_proposals.go binds a worker's
// delete to the worker itself), so a worker or gateway sends such a DELETE
// on to a server instead of running it.
type AbandonedPlacementDeleter interface {
	DeleteAbandonedPlacement(ctx context.Context, p Placement) error
}

// DeleteAbandonedPlacement deletes p's lifetime while p is left on a deleted
// node. opDelete compares owner and incarnation and ACKs a write that lost
// a race without deleting anything, so each round reads the placement again:
// gone, or a new lifetime under the same ID, means this lifetime is deleted;
// still left on the deleted node under another owner value (the leader
// orphaned it between the read and the write) means one more round; on a
// live node it is ErrPlacementNotAbandoned.
func (c *Cluster) DeleteAbandonedPlacement(ctx context.Context, p Placement) error {
	id := strings.TrimSpace(p.SandboxID)
	inc := strings.TrimSpace(p.IncarnationID)
	if id == "" || inc == "" {
		return fmt.Errorf("%w: deleting a placement left on a deleted node needs the sandbox and its lifetime", ErrIncarnationConflict)
	}
	for range abandonedDeleteAttempts {
		if !PlacementAbandoned(c, p) {
			return fmt.Errorf("%w: %s", ErrPlacementNotAbandoned, id)
		}
		if err := c.DeletePlacementExact(ctx, id, p.OwnerNodeID, inc); err != nil {
			return err
		}
		read, err := c.AuthoritativePlacementsByIDs(ctx, []string{id})
		if err != nil {
			return err
		}
		next, ok := read[id]
		if !ok || strings.TrimSpace(next.IncarnationID) != inc {
			return nil
		}
		p = next
	}
	return fmt.Errorf("%w: %s kept changing", ErrPlacementNotAbandoned, id)
}

// finishDeletedNodeDelete is evictOwnerPlacements' step for a deleting
// placement on a deleted node: the same exact delete the fence expiry sends
// (reconcileReservations), without waiting out the fence's TTL. The TTL is
// there for an owner that may be cut off but still finishing; a deleted
// node is refused as a peer from its deny commit, so it can finish nothing.
func (c *Cluster) finishDeletedNodeDelete(ctx context.Context, nodeID string, p Placement) error {
	c.runEvictDeadOwnerStepHook(evictStepFinishDelete, p.SandboxID)
	if err := c.DeletePlacementExact(ctx, p.SandboxID, nodeID, p.IncarnationID); err != nil {
		c.logger.Warn("cluster: finishing a deleted node's delete failed; will retry",
			"sandbox_id", p.SandboxID, "node_id", nodeID, "err", err)
		return err
	}
	return nil
}

// orphanableCount is how many placements opOrphanOwner would orphan for
// nodeID now. The owner index holds no reservation and no orphan, and
// opOrphanOwner leaves a deleting placement with its owner, so those are not
// counted: the eviction used to report them as orphaned while they stayed on
// the node.
func (f *placementFSM) orphanableCount(nodeID string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ids := f.ownerIndex[nodeID]
	if ids == nil {
		return 0
	}
	n := 0
	ids.Ascend(func(id string) bool {
		if _, deleting := f.deletingIndex[id]; !deleting {
			n++
		}
		return true
	})
	return n
}
