package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A delete during the failover window (plan item C3, invariant I3).
//
// When a node dies, the leader reassigns its failover.policy=recreate
// sandboxes to another worker (opReassign). Until that worker's owner watcher
// recreates a sandbox, a few seconds at least, the worker owns the placement
// but has no local row. A DELETE routed to it used to find no row and answer
// 404, which every SDK reads as "deleted"; the watcher then recreated the
// sandbox the client had just deleted.
//
// So a DELETE that finds no local row asks the control plane whether this node
// owns the placement. When it does, the delete is committed for the placement
// alone: the same begin-delete fence and exact delete a normal destroy uses
// (destroySandboxLocked), with the sealed secrets of that lifetime removed in
// between, the same order as there. It runs under the id's create lease, the
// one every create of the id holds, and the failover recreate checks the
// placement again under that lease (failoverRecreateStillOwned), so either the
// delete commits first and the recreate finds nothing to do, or the recreate
// finishes first and the delete finds the row and runs the full destroy.
//
// Rollback rule: the fence is written before anything is removed. If the
// secret cleanup or the final delete fails, the placement stays "deleting":
// the owner watcher never recreates a deleting placement, a retried DELETE
// finishes the job (begin-delete is a no-op on a deleting placement), and so
// does reconcileMissingSelfOwnedPlacements, which deletes a self-owned
// deleting placement whose local row is gone.
//
// The same no-row path finishes a DELETE of a sandbox whose node an operator
// deleted (deleteAbandonedPlacement). No node holds its row any more, and
// the router never forwards to a deleted node, so it sends the call to a
// server, which lands here and deletes the placement.

// unmaterializedDeleteTimeout bounds each control-plane call on this path,
// matching the destroy path's 5s per commit.
const unmaterializedDeleteTimeout = 5 * time.Second

// destroyUnmaterializedPlacement finishes a DestroySandbox that found no
// local row. notFound is what the local destroy answered; it is returned
// unchanged whenever this node does not own a placement it may delete, so
// single-node mode and every unknown id behave exactly as before.
func (s *Service) destroyUnmaterializedPlacement(ctx context.Context, id string, notFound error) error {
	if s == nil || !s.cfg.EnableCluster {
		return notFound
	}
	c := s.Cluster()
	if c == nil {
		return notFound
	}
	// Read before taking the lease: a create of the id that is running here
	// holds it, and a delete of an id with no self-owned placement (unknown,
	// already deleted, or a reservation still being created) must keep
	// answering 404 at once rather than 503.
	placement, found, err := s.authoritativePlacementWithoutRow(ctx, c, id)
	if err != nil {
		return err
	}
	if !found {
		return notFound
	}
	if !selfDeletableWithoutRow(c, placement) {
		if cluster.PlacementAbandoned(c, placement) {
			return s.deleteAbandonedPlacement(ctx, c, placement, notFound)
		}
		return notFound
	}
	// The placement carries the tenant. Another tenant's sandbox answers
	// 404, as it does when it has a local row (enforceOwner).
	if err := enforceOwner(ctx, &models.Sandbox{ID: id, OwnerRef: placement.OwnerRef}); err != nil {
		return err
	}
	leaseCtx, release, err := s.tryCreateLease(ctx, id)
	if err != nil {
		// A create of the id is running here, most likely the failover
		// recreate itself: 503, and the retry finds its row.
		return err
	}
	defer release()
	// The recreate may have finished between the read and the lease.
	if _, err := s.store.Get(leaseCtx, id); err == nil {
		return s.destroySandboxUnderLifecycleLock(leaseCtx, id)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.deletePlacementWithoutLocalRow(leaseCtx, c, placement)
}

// authoritativePlacementWithoutRow reads id's authoritative placement for a
// delete that found no local row. An unreadable placement is an error: "not
// found" would be a guess.
func (s *Service) authoritativePlacementWithoutRow(ctx context.Context, c cluster.Client, id string) (cluster.Placement, bool, error) {
	readCtx, cancel := context.WithTimeout(ctx, unmaterializedDeleteTimeout)
	placements, err := c.AuthoritativePlacementsByIDs(readCtx, []string{id})
	cancel()
	if err != nil {
		return cluster.Placement{}, false, fmt.Errorf("%w: resolve authoritative placement for a sandbox with no local row: %v", ErrClusterFinalizationUnavailable, err)
	}
	p, ok := placements[id]
	return p, ok, nil
}

// selfDeletableWithoutRow reports whether this node may delete p without a
// local row: it owns it actively, it is a placement and not a reservation (a
// reservation belongs to a create on its way here, whose own rollback
// cancels it), and it names its lifetime. A deleting placement qualifies, so
// a retry finishes an interrupted delete.
func selfDeletableWithoutRow(c cluster.Client, p cluster.Placement) bool {
	if p.IsReserved() || p.IsOrphaned() || strings.TrimSpace(p.IncarnationID) == "" {
		return false
	}
	return strings.TrimSpace(p.OwnerNodeID) == strings.TrimSpace(c.SelfNodeID())
}

// deleteAbandonedPlacement finishes a DELETE of a sandbox whose placement is
// left on a node an operator deleted (cluster.PlacementAbandoned: still
// named as its owner, or orphaned from it). Nothing runs it any more, so no
// node holds a row or a runtime to tear down: the delete is the placement's
// alone, and the forward the router would make has no node to reach. Only a
// server can write it (cluster.AbandonedPlacementDeleter); a worker or
// gateway router sends the call to one, so any other caller here answers as
// before.
//
// The lifetime's sealed secrets are not deleted from here: this node is not
// a recipient, and a holder takes a delete only from the owner or another
// recipient. The holders retire their copies once the placement is gone, as
// they do when the leader expires an abandoned delete fence.
//
// Idempotent: a second DELETE finds no placement and answers 404, and one
// that races this one either deletes first or finds it gone.
func (s *Service) deleteAbandonedPlacement(ctx context.Context, c cluster.Client, placement cluster.Placement, notFound error) error {
	deleter, ok := c.(cluster.AbandonedPlacementDeleter)
	if !ok {
		return notFound
	}
	// The placement carries the tenant: another tenant's sandbox answers
	// 404, as everywhere else.
	if err := enforceOwner(ctx, &models.Sandbox{ID: placement.SandboxID, OwnerRef: placement.OwnerRef}); err != nil {
		return err
	}
	deleteCtx, cancel := context.WithTimeout(ctx, unmaterializedDeleteTimeout)
	defer cancel()
	if err := deleter.DeleteAbandonedPlacement(deleteCtx, placement); err != nil {
		return fmt.Errorf("%w: delete the placement of a sandbox whose node was deleted: %v", ErrClusterFinalizationUnavailable, err)
	}
	if s.logger != nil {
		s.logger.Info("audit sandbox destroyed after its node was deleted",
			"sandbox_id", placement.SandboxID, "incarnation_id", placement.IncarnationID,
			"node_id", abandonedNode(placement))
	}
	return nil
}

// abandonedNode is the deleted node p is left on.
func abandonedNode(p cluster.Placement) string {
	if p.IsOrphaned() {
		return p.OrphanedOwnerNodeID
	}
	return p.OwnerNodeID
}

// deletePlacementWithoutLocalRow commits the delete of a placement this node
// owns but never materialized. The caller holds the id's create lease.
func (s *Service) deletePlacementWithoutLocalRow(ctx context.Context, c cluster.Client, placement cluster.Placement) error {
	id := strings.TrimSpace(placement.SandboxID)
	self := strings.TrimSpace(c.SelfNodeID())
	incarnationID := strings.TrimSpace(placement.IncarnationID)
	// Owner and incarnation are compared inside the apply, so a placement
	// that moved or was replaced since the read is refused, not deleted.
	fenceCtx, cancel := context.WithTimeout(ctx, unmaterializedDeleteTimeout)
	err := c.BeginDeletePlacementExact(fenceCtx, id, self, incarnationID)
	cancel()
	if errors.Is(err, cluster.ErrUnknownSandbox) {
		// Deleted since the read, by a concurrent delete of the same id.
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: begin authoritative placement delete: %v", ErrClusterFinalizationUnavailable, err)
	}
	// The sealed secrets of this lifetime go before the placement, as in
	// destroySandboxLocked: once the placement is gone nothing names the
	// recipients that hold copies.
	if err := s.DeleteClusterSecrets(ctx, id, incarnationID); err != nil {
		return err
	}
	deleteCtx, cancel := context.WithTimeout(ctx, unmaterializedDeleteTimeout)
	defer cancel()
	if err := c.DeletePlacementExact(deleteCtx, id, self, incarnationID); err != nil {
		return fmt.Errorf("%w: delete authoritative placement: %v", ErrClusterFinalizationUnavailable, err)
	}
	if s.logger != nil {
		s.logger.Info("audit sandbox destroyed before failover recreate",
			"sandbox_id", id, "incarnation_id", incarnationID)
	}
	return nil
}

// failoverRecreateStillOwned is the recreate side of the same rule. The owner
// watcher reads its placements once per tick and recreates them one after
// another, so the placement it passes may have been deleted (or moved) since.
// The caller holds the id's create lease and has found no local row; this
// reads the placement again and answers whether this node should still
// create it. Outside a cluster there is nothing to check.
//
// When it should, firstCreated is when the cluster first placed the sandbox
// (Placement.CreatedUnix), zero if unknown: the recreate keeps it as the
// row's created_at (persistSandboxCreate).
func (s *Service) failoverRecreateStillOwned(ctx context.Context, id string, secrets cluster.PlacementSecrets) (owned bool, firstCreated time.Time, err error) {
	if s == nil || !s.cfg.EnableCluster {
		return true, time.Time{}, nil
	}
	c := s.Cluster()
	if c == nil {
		return true, time.Time{}, nil
	}
	readCtx, cancel := context.WithTimeout(ctx, unmaterializedDeleteTimeout)
	placements, err := c.AuthoritativePlacementsByIDs(readCtx, []string{id})
	cancel()
	if err != nil {
		return false, time.Time{}, fmt.Errorf("recreate %s: confirm placement before recreate: %w", id, err)
	}
	p, ok := placements[id]
	reason := ""
	switch {
	case !ok:
		reason = "placement deleted"
	case p.IsDeleting():
		reason = "placement is being deleted"
	case p.IsOrphaned() || strings.TrimSpace(p.OwnerNodeID) != strings.TrimSpace(c.SelfNodeID()):
		reason = "placement moved to another node"
	case strings.TrimSpace(secrets.IncarnationID) != "" && strings.TrimSpace(p.IncarnationID) != strings.TrimSpace(secrets.IncarnationID):
		reason = "placement belongs to a newer lifetime"
	default:
		if p.CreatedUnix > 0 {
			firstCreated = time.Unix(p.CreatedUnix, 0).UTC()
		}
		return true, firstCreated, nil
	}
	if s.logger != nil {
		s.logger.Info("cluster: failover recreate skipped", "sandbox_id", id, "reason", reason)
	}
	return false, time.Time{}, nil
}
