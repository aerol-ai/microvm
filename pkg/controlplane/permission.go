package controlplane

import "context"

// Permission is one verb a route requires (plans/identity-and-access.md
// §5.3). Every API route is registered with exactly one (or, for a route
// whose verb depends on the request, a classifier that returns one), and a
// caller's Role decides whether it holds it. The values are the names audit
// records, 403 bodies and `whoami` print, so they are a wire contract.
type Permission string

const (
	// PermSandboxRead: get and list sandboxes (no env), mounts, network
	// usage, custom domains, snapshots, egress profiles, WASM modules and JS
	// bundles, capacity.
	PermSandboxRead Permission = "sandbox.read"
	// PermSandboxSecrets: include_env reads (the audited secret_open path).
	PermSandboxSecrets Permission = "sandbox.secrets"
	// PermSandboxWrite: create, start, stop, delete, resize, lifecycle,
	// ports, custom domains, network limits and policy, snapshots, image
	// build, egress profiles, JS bundles and WASM modules.
	PermSandboxWrite Permission = "sandbox.write"
	// PermSandboxExec: the whole toolbox proxy (exec, files, sessions,
	// terminals). Files can hold secrets, so a viewer gets none of it.
	PermSandboxExec Permission = "sandbox.exec"
	// PermAuditRead: GET /v1/sandboxes/{id}/audit.
	PermAuditRead Permission = "audit.read"
	// PermAuditVerify: POST /v1/audit/verify.
	PermAuditVerify Permission = "audit.verify"
	// PermTokenRead and PermTokenWrite: list, and create or revoke, API
	// tokens (task T3).
	PermTokenRead  Permission = "token.read"
	PermTokenWrite Permission = "token.write"
	// PermMetricsRead: GET /v1/metrics. The counters describe the whole
	// fleet, so only a role bound to every team holds it (CEO review D6).
	PermMetricsRead Permission = "metrics.read"
	// PermFleetAdmin: templates, /v1/cluster/*, admin reconcile, ingress
	// DNS, /debug/vars.
	PermFleetAdmin Permission = "fleet.admin"
	// PermClusterInternal: /v1/cluster/internal/*. Held only by the node:
	// principal (a peer's PAT over mTLS, on its own behalf), never by a role.
	PermClusterInternal Permission = "cluster.internal"
	// PermAuthenticated is the pseudo-permission of the two routes that need
	// only a valid principal: GET /v1/whoami (it describes the caller) and
	// /mcp (each tool's inner API call is authorized by its own route).
	PermAuthenticated Permission = "authenticated"
)

// rolePermissions is the §5.3 role table. Whether a grant reaches one team
// or every team is the binding's business (Access.Fleet), not the role's:
// the table only says which verbs a role carries at all.
var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {
		PermSandboxRead: true, PermAuditRead: true, PermMetricsRead: true,
	},
	RoleRunner: {
		PermSandboxRead: true, PermSandboxSecrets: true, PermSandboxWrite: true, PermSandboxExec: true,
		PermAuditRead: true, PermMetricsRead: true,
	},
	RoleAuditor: {
		PermSandboxRead: true, PermAuditRead: true, PermAuditVerify: true, PermTokenRead: true,
		PermMetricsRead: true,
	},
	RoleAdmin: {
		PermSandboxRead: true, PermSandboxSecrets: true, PermSandboxWrite: true, PermSandboxExec: true,
		PermAuditRead: true, PermAuditVerify: true, PermTokenRead: true, PermTokenWrite: true,
		PermMetricsRead: true, PermFleetAdmin: true,
	},
}

// roleOrder is least to most powerful: the D9 hint names the first role in
// it that would allow a refused call.
var roleOrder = []Role{RoleViewer, RoleRunner, RoleAuditor, RoleAdmin}

// Grants reports whether the role table gives r the permission p at all.
// It ignores the binding: use Access.Can for a caller.
func (r Role) Grants(p Permission) bool { return rolePermissions[r][p] }

// RequiresFleet reports whether r may only be bound to every team (FleetTeam).
// auditor and admin see the whole fleet by definition (§5.3); a token or an
// identity-file binding that names one team for them is invalid (T3, T6).
func (r Role) RequiresFleet() bool { return r == RoleAuditor || r == RoleAdmin }

// RequiresFleet reports whether p is granted only through a binding to every
// team, whatever the role. metrics.read is: the counters are fleet-wide.
func (p Permission) RequiresFleet() bool { return p == PermMetricsRead }

// preRoles reports whether a is an Access literal from before roles: no Role
// and no Principal. Every authenticator sets both (the T1 constructors do),
// so only in-process literals and older test fixtures look like this.
func (a Access) preRoles() bool { return a.Role == "" && a.Principal.Kind == "" }

// EffectiveRole is the role a caller's permissions come from.
//
// A pre-roles Access literal keeps the meaning it had then: Fleet was the
// PAT (admin; on an internal route, the peer node), anything else an
// owner-scoped caller (runner, the verb set every managed caller has always
// had). A caller that names a principal but carries no role holds nothing:
// a broken authenticator fails closed, never open.
func (a Access) EffectiveRole() Role {
	switch {
	case a.Role != "":
		return a.Role
	case a.Principal.Kind != "":
		return ""
	case a.Fleet:
		return RoleAdmin
	default:
		return RoleRunner
	}
}

// Can reports whether the caller holds p. It answers "may this caller use
// this verb", never "on which owner": that is Fleet's job (ownerScope), so a
// runner bound to team payments Can(sandbox.exec) and is still fenced to
// payments' sandboxes by the service layer.
func (a Access) Can(p Permission) bool {
	switch p {
	case PermAuthenticated:
		return true
	case PermClusterInternal:
		// Only the node: principal. A pre-roles Fleet literal meant "the
		// PAT", which on an internal route was always the peer (the route
		// still demands a live mTLS peer on top).
		return a.Principal.Kind == PrincipalNode || (a.preRoles() && a.Fleet)
	}
	role := a.EffectiveRole()
	if !role.Grants(p) {
		return false
	}
	if (role.RequiresFleet() || p.RequiresFleet()) && !a.Fleet {
		// An auditor or admin fenced to one team is a misbinding, and
		// metrics.read is never a team grant: refuse rather than guess.
		return false
	}
	return true
}

// HostCapable reports whether the caller may use host-side powers: raw host
// mounts, file:// bundle refs read off the host, and custom domains on the
// operator's trusted DNS path (eng review D3, D7). True for the PAT
// (operator), a cluster peer (node:), a system loop, and the admin role.
// False for viewer, runner (team or fleet), auditor and managed identities:
// fleet scope is which owners a caller sees, never host power.
func (a Access) HostCapable() bool {
	switch a.Principal.Kind {
	case PrincipalOperator, PrincipalNode, PrincipalSystem:
		return true
	}
	return a.EffectiveRole() == RoleAdmin && a.Fleet
}

// HostCapable is Access.HostCapable for a request context. A context with no
// Access is an internal call that never crossed the API edge (failover
// recreate, background loops), so it keeps the host powers it always had.
func HostCapable(ctx context.Context) bool {
	access, ok := AccessFromContext(ctx)
	if !ok {
		return true
	}
	return access.HostCapable()
}

// LeastRoleFor returns the least powerful role that would let a caller hold
// p, and whether that role (or p itself) must be bound to every team. ok is
// false when no role grants p (cluster.internal, authenticated).
func LeastRoleFor(p Permission) (role Role, fleetOnly bool, ok bool) {
	for _, r := range roleOrder {
		if r.Grants(p) {
			return r, r.RequiresFleet() || p.RequiresFleet(), true
		}
	}
	return "", false, false
}

// HintPrincipal reports whether a refusal for this principal kind carries the
// D9 hint. Only the new identity kinds (avm_ tokens, OIDC) get one; the PAT,
// a cluster node and a managed caller keep today's 403 bodies byte for byte
// (L8).
func HintPrincipal(kind PrincipalKind) bool {
	return kind == PrincipalToken || kind == PrincipalOIDC
}

// DenyHint is the D9 hint for a refused permission: the caller's own role and
// team, and the role that would allow the call. It names only what `whoami`
// already shows the caller, never another principal, team or binding. It is
// "" for principals that get no hint (HintPrincipal).
//
//	role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments
func DenyHint(a Access, p Permission) string {
	if !HintPrincipal(a.Principal.Kind) {
		return ""
	}
	have := "role " + string(a.EffectiveRole()) + " on " + teamPhrase(a.Team())
	if p == PermClusterInternal {
		return have + " cannot " + string(p) + "; it is reserved for cluster nodes and no role grants it"
	}
	role, fleetOnly, ok := LeastRoleFor(p)
	if !ok {
		return have + " cannot " + string(p)
	}
	team := a.Team()
	if fleetOnly {
		team = FleetTeam
	}
	return have + " cannot " + string(p) + "; ask an admin for role " + string(role) + " on " + teamPhrase(team)
}

func teamPhrase(team string) string {
	if team == FleetTeam {
		return "all teams"
	}
	return "team " + team
}

type routePermissionKey struct{}

// ContextWithRoutePermission records the permission the request's route
// needs, before authentication runs (apihttp.Router stamps it). Only one
// authenticator reads it: a token mirror that cannot sync still accepts a
// request whose route needs nothing but metrics.read (CEO review D16), so
// it has to know the route's permission at authentication time.
func ContextWithRoutePermission(ctx context.Context, p Permission) context.Context {
	return context.WithValue(ctx, routePermissionKey{}, p)
}

// RoutePermissionFromContext returns the permission the request's route
// needs. ok is false for a request that did not come through a Router (an
// unknown route must be treated as needing more than metrics.read).
func RoutePermissionFromContext(ctx context.Context) (Permission, bool) {
	p, ok := ctx.Value(routePermissionKey{}).(Permission)
	return p, ok
}
