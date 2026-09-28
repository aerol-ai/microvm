package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ownerScope reports the account a request is fenced to. scoped=false means the
// caller is unscoped — either the operator/PAT path, or an internal/background
// call that never went through the auth edge (no Access in context). Such
// callers see and act on the whole fleet, exactly as before owner scoping
// existed. scoped=true means a validated user token: only sandboxes whose
// OwnerRef equals owner are visible.
//
// This is the one place the controlplane.Access convention is interpreted, so
// the "no Access ⇒ unscoped" default lives in a single audited spot.
func ownerScope(ctx context.Context) (owner string, scoped bool) {
	access, ok := controlplane.AccessFromContext(ctx)
	if !ok || access.Operator {
		return "", false
	}
	return access.Identity.OwnerRef, true
}

// enforceOwner returns store.ErrNotFound when a user-scoped caller references a
// sandbox it does not own. A 404 (not 403) is deliberate: it denies the
// existence of another tenant's sandbox so a user token cannot probe IDs to map
// the fleet. Operator and internal callers always pass.
func enforceOwner(ctx context.Context, sandbox *models.Sandbox) error {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return nil
	}
	if sandbox == nil || sandbox.OwnerRef != owner {
		return store.ErrNotFound
	}
	return nil
}

// scopedGet loads a sandbox and applies owner scoping in one step. It is the
// owner-aware replacement for store.Get at caller-facing, per-id entry points;
// background loops keep calling store.Get directly so they stay fleet-wide.
func (s *Service) scopedGet(ctx context.Context, id string) (*models.Sandbox, error) {
	sandbox, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := enforceOwner(ctx, sandbox); err != nil {
		return nil, err
	}
	return sandbox, nil
}

// ownerRefForCreate returns the owner_ref to stamp on a sandbox created by the
// current request: the caller's account for a validated user token, or "" for
// operator/PAT and internal creates (which carry no owner). It never errors —
// an unscoped create is legitimately owner-less.
func ownerRefForCreate(ctx context.Context) string {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return ""
	}
	return owner
}

// OwnerRefForCreate is the exported form of ownerRefForCreate for API layers
// that need to stamp PlacementSecrets.OwnerRef at reserve time.
func OwnerRefForCreate(ctx context.Context) string {
	return ownerRefForCreate(ctx)
}

// tenantOwnerRefForRecreate prefers the replicated Placement.OwnerRef so
// owner-watcher recreates (unscoped context) keep the original tenant.
func (s *Service) tenantOwnerRefForRecreate(ctx context.Context, sandboxID string) string {
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok {
			if ref := strings.TrimSpace(p.OwnerRef); ref != "" {
				return ref
			}
		}
	}
	return ownerRefForCreate(ctx)
}

// ownerRefForCreateOrRecreate uses the request Access when present; on failover
// recreate (empty Access + known id) falls back to Placement.OwnerRef.
func (s *Service) ownerRefForCreateOrRecreate(ctx context.Context, idOverride string) string {
	ownerRef := ownerRefForCreate(ctx)
	if ownerRef == "" && strings.TrimSpace(idOverride) != "" {
		return s.tenantOwnerRefForRecreate(ctx, idOverride)
	}
	return ownerRef
}

// filterByOwnerScope narrows a sandbox slice to the caller's account when the
// request is user-scoped, and returns it untouched for operator/internal
// callers. Used by list paths (including the cluster fan-out aggregation) where
// a missing entry must read as "you have none" rather than a 404.
func filterByOwnerScope(ctx context.Context, sandboxes []*models.Sandbox) []*models.Sandbox {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return sandboxes
	}
	filtered := make([]*models.Sandbox, 0, len(sandboxes))
	for _, sb := range sandboxes {
		if sb != nil && sb.OwnerRef == owner {
			filtered = append(filtered, sb)
		}
	}
	return filtered
}
