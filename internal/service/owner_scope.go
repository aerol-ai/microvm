package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
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
	if !ok || access.Fleet {
		return "", false
	}
	return access.Identity.OwnerRef, true
}

// hostCapable reports whether the caller may use host-side powers: raw host
// mounts (validateCreateMounts), file:// bundle refs read off the host
// (createIsolateSandbox), and the operator's trusted path for custom domains
// (no DNS proof on create, the owner-less TXT on attach). True for the PAT,
// a cluster node, an internal call with no Access and the admin role; false
// for viewer, runner (on a team or on every team), auditor and managed
// callers (plans/identity-and-access.md §5.1, eng review D3/D7).
//
// Scope is not power: ownerScope answers which owners a caller sees, and a
// runner bound to every team is unscoped there but still not host-capable.
// A new check that gates a host or trust power must ask this, never
// !scoped; TestOwnerScopeCallSitesAreReviewed fails on an unreviewed use.
func hostCapable(ctx context.Context) bool {
	return controlplane.HostCapable(ctx)
}

// wasmResolveContext annotates ctx for the WASM module resolver so that a caller
// which is not host-capable (a scoped tenant) cannot resolve a module from a raw
// host path (absolute, file://, or a bare operator-staged filename under
// ModulesDir — resolver step 4). Operator, node and internal callers are
// host-capable and pass through unmarked, keeping host-path resolution.
//
// It is the WASM counterpart of the hostCapable gate the raw-mount and file://
// jsbundle paths already use (eng review D3/D7): scope is not power, so a runner
// bound to every team is unscoped but still refused a host path. Reserved
// keywords and oci:// / owned-catalogue refs resolve for everyone, so a tenant
// loses only the host-path escape (plans/identity-and-access.md §5.1).
func wasmResolveContext(ctx context.Context) context.Context {
	if hostCapable(ctx) {
		return ctx
	}
	return wasmmod.WithHostPathsDenied(ctx)
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

// snapshotVisible applies the sandbox owner rule to a snapshot row: operator
// and internal callers see every snapshot, a user token only its own
// account's. Snapshots carry their own owner because they outlive the
// sandbox they were taken from, so the source row cannot be consulted.
func snapshotVisible(ctx context.Context, snapshot *models.SandboxSnapshot) bool {
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return true
	}
	return snapshot != nil && snapshot.OwnerRef == owner
}

// snapshotResolvableForCreate reports whether a snapshot may be silently
// resolved by NAME when a create request names it (the implicit create path),
// as opposed to snapshotVisible which governs explicit reads.
//
// It is STRICTER than snapshotVisible for an unscoped caller: an operator may
// READ every snapshot, but a create must NOT implicitly resolve a TENANT's
// snapshot by name — that is how a tenant who registers a snapshot named after
// a common/default image ("ubuntu:22.04") hijacks an operator/no-Access create
// onto their own image (#7). So an unscoped create resolves only
// operator-published ("") snapshots; a tenant resolves only its own (matching
// snapshotVisible, which does not expose "" snapshots to a tenant).
func snapshotResolvableForCreate(ctx context.Context, snapshot *models.SandboxSnapshot) bool {
	if snapshot == nil {
		return false
	}
	owner, scoped := ownerScope(ctx)
	if !scoped {
		return snapshot.OwnerRef == ""
	}
	return snapshot.OwnerRef == owner
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
