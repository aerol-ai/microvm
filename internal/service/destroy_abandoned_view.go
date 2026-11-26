package service

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A facade delete of a sandbox left on a node an operator deleted.
//
// v1's DELETE and E2B's kill answer with no body, so DestroySandbox's no-row
// path is all they need (deleteAbandonedPlacement). Daytona's DELETE and
// Runloop's shutdown answer with the sandbox they deleted, which the SDKs
// parse, and they read the sandbox first: Daytona by its id or by the
// caller's name for it. On the server that takes such a delete (the router
// sends it there, pkg/api/clusterroute abandoned.go) there is no row to read
// or to build the answer from: it went with the deleted node. What the
// cluster still holds is the placement: the id, the tenant, the name, the
// creation time and the replicated create spec (without its secrets), plus
// a facade's own state when the sandbox is failover=recreate. So the facade
// asks for the delete here and builds its answer from what this returns.

// DestroyAbandonedSandbox deletes the sandbox ref names when it is left on a
// node an operator deleted, for a facade delete that found no local row. It
// returns the sandbox as its placement describes it (status destroyed), and
// facade's state from the replicated spec, or nil when the spec has none.
// ref is a sandbox id; with byName it may also be the caller's name for
// one, in the caller's namespace (the one the router resolved it in).
//
// store.ErrNotFound means no such sandbox for this caller, and the facade
// answers 404 as before: no cluster, a node that is not a server (only a
// server may delete another node's placement, and the router sends these
// deletes to one, so a worker never gets here with one), no placement, a
// placement on a live node, or another tenant's sandbox (enforceOwner: the
// same answer as for an id that does not exist, before any leader read).
//
// Idempotent: a duplicate in flight that finds the lifetime already deleted
// answers as the call that deleted it did, since the sandbox it asked to
// delete is gone; a later retry finds no placement on this node and answers
// 404, as a second DELETE does anywhere. A placement handed to a live node
// since this node read it is left there, and the 503 makes the client retry:
// the router sends the retry to the new owner.
func (s *Service) DestroyAbandonedSandbox(ctx context.Context, ref string, byName bool, facade string) (*models.Sandbox, *models.SandboxCompatState, error) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, nil, store.ErrNotFound
	}
	c := s.Cluster()
	if _, server := c.(cluster.AbandonedPlacementDeleter); c == nil || !server {
		return nil, nil, store.ErrNotFound
	}
	p, ok := abandonedPlacementFor(ctx, c, strings.TrimSpace(ref), byName)
	if !ok {
		return nil, nil, store.ErrNotFound
	}
	if err := enforceOwner(ctx, &models.Sandbox{ID: p.SandboxID, OwnerRef: p.OwnerRef}); err != nil {
		return nil, nil, err
	}
	// Built from this node's copy, which has the spec; the leader's answer
	// below is the hot row only, and decides what to delete.
	sandbox, state := abandonedSandboxView(p, facade)
	current, found, err := s.authoritativePlacementWithoutRow(ctx, c, p.SandboxID)
	switch {
	case err != nil:
		return nil, nil, err
	case !found || strings.TrimSpace(current.IncarnationID) != strings.TrimSpace(p.IncarnationID):
		// Another delete of this lifetime committed after this node read
		// it (a new lifetime under the same id is not this one).
		return sandbox, state, nil
	}
	// One handed to a live node since is refused there, as
	// ErrClusterFinalizationUnavailable (cluster.ErrPlacementNotAbandoned).
	if err := s.deleteAbandonedPlacement(ctx, c, current, store.ErrNotFound); err != nil {
		return nil, nil, err
	}
	return sandbox, state, nil
}

// abandonedPlacementFor reads ref's placement on this server: by id or,
// with byName, by the caller's name for it. Only a placement left on a
// deleted node answers.
func abandonedPlacementFor(ctx context.Context, c cluster.Client, ref string, byName bool) (cluster.Placement, bool) {
	if ref == "" {
		return cluster.Placement{}, false
	}
	p, ok := c.PlacementOf(ref)
	if !ok && byName {
		// A name names a sandbox only in its owner's namespace; another
		// tenant's name is unknown here, as it is to the router.
		if id, _, _ := c.OwnerOfName(ownerRefForCreate(ctx), ref); strings.TrimSpace(id) != "" {
			p, ok = c.PlacementOf(id)
		}
	}
	if !ok || !cluster.PlacementAbandoned(c, p) {
		return cluster.Placement{}, false
	}
	return p, true
}

// abandonedSandboxView is the sandbox p describes, for a facade's answer:
// what the placement and its replicated spec hold. The spec carries no
// environment (RedactClusterSecrets), and runtime state such as addresses
// and ports went with the node, so those stay empty.
func abandonedSandboxView(p cluster.Placement, facade string) (*models.Sandbox, *models.SandboxCompatState) {
	sb := &models.Sandbox{
		ID:       strings.TrimSpace(p.SandboxID),
		OwnerRef: p.OwnerRef,
		Name:     p.Name,
		Status:   models.SandboxStatusDestroyed,
	}
	if p.CreatedUnix > 0 {
		sb.CreatedAt = time.Unix(p.CreatedUnix, 0).UTC()
	}
	if p.UpdatedUnix > 0 {
		sb.UpdatedAt = time.Unix(p.UpdatedUnix, 0).UTC()
	}
	spec := p.Spec
	if spec == nil {
		return sb, nil
	}
	if sb.Name == "" {
		sb.Name = spec.Name
	}
	sb.Image = spec.Image
	sb.CPU, sb.MemoryMB, sb.DiskGB = spec.CPU, spec.MemoryMB, spec.DiskGB
	sb.OSUser = spec.OSUser
	sb.NetworkBlockAll = spec.NetworkBlockAll
	sb.AllowPublicTraffic = spec.AllowPublicTraffic
	sb.GPUs = spec.GPUs
	sb.Runtime = spec.Runtime
	sb.Tags = maps.Clone(spec.Tags)
	if spec.Lifecycle != nil {
		sb.Lifecycle = *spec.Lifecycle
	}
	raw := strings.TrimSpace(spec.CompatState[facade])
	if facade == "" || raw == "" {
		return sb, nil
	}
	return sb, &models.SandboxCompatState{SandboxID: sb.ID, Facade: facade, StateJSON: raw}
}
