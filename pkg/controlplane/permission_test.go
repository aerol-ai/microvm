package controlplane

import (
	"context"
	"testing"
)

// boundAccess is a token caller with role bound to team ("*" = every team).
func boundAccess(kind PrincipalKind, role Role, team string) Access {
	a := Access{Role: role, Principal: Principal{Kind: kind, ID: string(kind) + ":x", Name: "x"}}
	if team == FleetTeam {
		a.Fleet = true
	} else {
		a.Identity.OwnerRef = TeamOwnerRef(team)
	}
	return a
}

var allPermissions = []Permission{
	PermSandboxRead, PermSandboxSecrets, PermSandboxWrite, PermSandboxExec,
	PermAuditRead, PermAuditVerify, PermTokenRead, PermTokenWrite,
	PermMetricsRead, PermFleetAdmin, PermClusterInternal, PermAuthenticated,
}

// TestRolePermissionMatrix is the §5.3 role table, written out cell by cell
// so a change to rolePermissions has to change this too. Rows are the
// bindings a principal can hold; a cell is the set of permissions it has.
func TestRolePermissionMatrix(t *testing.T) {
	const (
		r  = PermSandboxRead
		s  = PermSandboxSecrets
		w  = PermSandboxWrite
		x  = PermSandboxExec
		ar = PermAuditRead
		av = PermAuditVerify
		tr = PermTokenRead
		tw = PermTokenWrite
		m  = PermMetricsRead
		fa = PermFleetAdmin
		ci = PermClusterInternal
		au = PermAuthenticated
	)
	set := func(ps ...Permission) map[Permission]bool {
		out := map[Permission]bool{}
		for _, p := range ps {
			out[p] = true
		}
		return out
	}
	cases := []struct {
		name   string
		access Access
		want   map[Permission]bool
	}{
		{"viewer on a team", boundAccess(PrincipalToken, RoleViewer, "payments"), set(r, ar, au)},
		{"viewer on every team", boundAccess(PrincipalToken, RoleViewer, FleetTeam), set(r, ar, m, au)},
		{"runner on a team", boundAccess(PrincipalToken, RoleRunner, "payments"), set(r, s, w, x, ar, au)},
		{"runner on every team", boundAccess(PrincipalOIDC, RoleRunner, FleetTeam), set(r, s, w, x, ar, m, au)},
		{"auditor", boundAccess(PrincipalToken, RoleAuditor, FleetTeam), set(r, ar, av, tr, m, au)},
		{"admin", boundAccess(PrincipalOIDC, RoleAdmin, FleetTeam), set(r, s, w, x, ar, av, tr, tw, m, fa, au)},
		// auditor and admin must be bound to every team; a team binding
		// for them is a misconfiguration and grants nothing.
		{"auditor misbound to a team", boundAccess(PrincipalToken, RoleAuditor, "payments"), set(au)},
		{"admin misbound to a team", boundAccess(PrincipalToken, RoleAdmin, "payments"), set(au)},
		// The PAT and a peer node are admins on every team; only the node
		// holds cluster.internal (§5.3: "only the node: principal").
		{"operator (PAT)", OperatorAccess(), set(r, s, w, x, ar, av, tr, tw, m, fa, au)},
		{"node", NodeAccess("n3"), set(r, s, w, x, ar, av, tr, tw, m, fa, ci, au)},
		// A managed caller is a runner (or viewer) on its account: today's
		// owner-scoped verb set, never metrics or fleet routes (L8).
		{"managed runner", mustControlPlane(t, Identity{OwnerRef: "acct", ExternalID: "u1"}), set(r, s, w, x, ar, au)},
		{"managed viewer", mustControlPlane(t, Identity{OwnerRef: "acct", ExternalID: "u1", Role: RoleViewer}), set(r, ar, au)},
		// Pre-roles literals keep their old meaning: Fleet was the PAT,
		// anything else an owner-scoped caller.
		{"pre-roles fleet literal", Access{Fleet: true}, set(r, s, w, x, ar, av, tr, tw, m, fa, ci, au)},
		{"pre-roles scoped literal", Access{Identity: Identity{OwnerRef: "acct"}}, set(r, s, w, x, ar, au)},
		// A principal with no role holds nothing: fail closed.
		{"principal without a role", Access{Fleet: true, Principal: Principal{Kind: PrincipalToken, ID: "tok"}}, set(au)},
	}
	for _, tc := range cases {
		for _, p := range allPermissions {
			if got := tc.access.Can(p); got != tc.want[p] {
				t.Errorf("%s: Can(%s) = %v, want %v", tc.name, p, got, tc.want[p])
			}
		}
	}
}

func mustControlPlane(t *testing.T, id Identity) Access {
	t.Helper()
	a, err := ControlPlaneAccess(id)
	if err != nil {
		t.Fatalf("ControlPlaneAccess(%+v): %v", id, err)
	}
	return a
}

func TestRoleAndPermissionFleetRules(t *testing.T) {
	for role, want := range map[Role]bool{RoleViewer: false, RoleRunner: false, RoleAuditor: true, RoleAdmin: true, "": false} {
		if role.RequiresFleet() != want {
			t.Errorf("%q.RequiresFleet() = %v, want %v", role, !want, want)
		}
	}
	for _, p := range allPermissions {
		if got := p.RequiresFleet(); got != (p == PermMetricsRead) {
			t.Errorf("%s.RequiresFleet() = %v", p, got)
		}
	}
	if Role("owner").Grants(PermSandboxRead) {
		t.Fatal("an unknown role grants nothing")
	}
}

func TestEffectiveRole(t *testing.T) {
	for name, tc := range map[string]struct {
		access Access
		want   Role
	}{
		"set role wins":             {Access{Role: RoleViewer, Fleet: true}, RoleViewer},
		"pre-roles fleet is admin":  {Access{Fleet: true}, RoleAdmin},
		"pre-roles scoped runner":   {Access{Identity: Identity{OwnerRef: "a"}}, RoleRunner},
		"principal without a role":  {Access{Principal: Principal{Kind: PrincipalOIDC}}, ""},
		"operator constructor role": {OperatorAccess(), RoleAdmin},
	} {
		if got := tc.access.EffectiveRole(); got != tc.want {
			t.Errorf("%s: EffectiveRole = %q, want %q", name, got, tc.want)
		}
	}
}

// TestHostCapable: host powers (raw mounts, file:// refs, the trusted DNS
// path) belong to the operator, nodes, system loops, internal calls and
// admins; fleet scope alone never grants them (eng review D3).
func TestHostCapable(t *testing.T) {
	cases := []struct {
		name   string
		access Access
		want   bool
	}{
		{"operator", OperatorAccess(), true},
		{"node", NodeAccess("n1"), true},
		{"system loop", Access{Fleet: true, Principal: Principal{Kind: PrincipalSystem, ID: "system:lifecycle"}}, true},
		{"admin (oidc)", boundAccess(PrincipalOIDC, RoleAdmin, FleetTeam), true},
		{"admin (token)", boundAccess(PrincipalToken, RoleAdmin, FleetTeam), true},
		{"admin misbound to a team", boundAccess(PrincipalToken, RoleAdmin, "payments"), false},
		{"runner on every team", boundAccess(PrincipalToken, RoleRunner, FleetTeam), false},
		{"runner on a team", boundAccess(PrincipalToken, RoleRunner, "payments"), false},
		{"viewer on every team", boundAccess(PrincipalOIDC, RoleViewer, FleetTeam), false},
		{"auditor", boundAccess(PrincipalToken, RoleAuditor, FleetTeam), false},
		{"managed runner", mustControlPlane(t, Identity{OwnerRef: "acct"}), false},
		{"sandbox key", Access{Principal: Principal{Kind: PrincipalSandboxKey, ID: "sb-1"}}, false},
		{"pre-roles fleet literal", Access{Fleet: true}, true},
		{"pre-roles scoped literal", Access{Identity: Identity{OwnerRef: "acct"}}, false},
	}
	for _, tc := range cases {
		if got := tc.access.HostCapable(); got != tc.want {
			t.Errorf("%s: HostCapable = %v, want %v", tc.name, got, tc.want)
		}
		ctx := ContextWithAccess(context.Background(), tc.access)
		if got := HostCapable(ctx); got != tc.want {
			t.Errorf("%s: HostCapable(ctx) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !HostCapable(context.Background()) {
		t.Fatal("an internal call with no Access keeps its host powers")
	}
}

func TestLeastRoleFor(t *testing.T) {
	cases := []struct {
		perm      Permission
		role      Role
		fleetOnly bool
		ok        bool
	}{
		{PermSandboxRead, RoleViewer, false, true},
		{PermAuditRead, RoleViewer, false, true},
		{PermSandboxSecrets, RoleRunner, false, true},
		{PermSandboxWrite, RoleRunner, false, true},
		{PermSandboxExec, RoleRunner, false, true},
		{PermMetricsRead, RoleViewer, true, true},
		{PermAuditVerify, RoleAuditor, true, true},
		{PermTokenRead, RoleAuditor, true, true},
		{PermTokenWrite, RoleAdmin, true, true},
		{PermFleetAdmin, RoleAdmin, true, true},
		{PermClusterInternal, "", false, false},
		{PermAuthenticated, "", false, false},
	}
	for _, tc := range cases {
		role, fleetOnly, ok := LeastRoleFor(tc.perm)
		if role != tc.role || fleetOnly != tc.fleetOnly || ok != tc.ok {
			t.Errorf("LeastRoleFor(%s) = %q %v %v, want %q %v %v", tc.perm, role, fleetOnly, ok, tc.role, tc.fleetOnly, tc.ok)
		}
	}
}

// TestDenyHint is the D9 wording. It names only the caller's own role and
// team and the role to ask for, and only token and OIDC callers get one.
func TestDenyHint(t *testing.T) {
	cases := []struct {
		name   string
		access Access
		perm   Permission
		want   string
	}{
		{"team viewer, team verb", boundAccess(PrincipalToken, RoleViewer, "payments"), PermSandboxExec,
			"role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments"},
		{"team viewer, fleet-only permission", boundAccess(PrincipalOIDC, RoleViewer, "payments"), PermMetricsRead,
			"role viewer on team payments cannot metrics.read; ask an admin for role viewer on all teams"},
		{"team runner, fleet-only role", boundAccess(PrincipalToken, RoleRunner, "payments"), PermAuditVerify,
			"role runner on team payments cannot audit.verify; ask an admin for role auditor on all teams"},
		{"fleet viewer, team verb", boundAccess(PrincipalToken, RoleViewer, FleetTeam), PermSandboxWrite,
			"role viewer on all teams cannot sandbox.write; ask an admin for role runner on all teams"},
		{"auditor, fleet admin", boundAccess(PrincipalOIDC, RoleAuditor, FleetTeam), PermFleetAdmin,
			"role auditor on all teams cannot fleet.admin; ask an admin for role admin on all teams"},
		{"admin, cluster internal", boundAccess(PrincipalOIDC, RoleAdmin, FleetTeam), PermClusterInternal,
			"role admin on all teams cannot cluster.internal; it is reserved for cluster nodes and no role grants it"},
		{"no role grants it", boundAccess(PrincipalToken, RoleViewer, "payments"), Permission("made.up"),
			"role viewer on team payments cannot made.up"},
		{"operator gets no hint", OperatorAccess(), PermClusterInternal, ""},
		{"node gets no hint", NodeAccess("n1"), PermFleetAdmin, ""},
		{"managed caller gets no hint", mustControlPlane(t, Identity{OwnerRef: "acct", Role: RoleViewer}), PermSandboxExec, ""},
		{"pre-roles literal gets no hint", Access{Identity: Identity{OwnerRef: "acct"}}, PermFleetAdmin, ""},
	}
	for _, tc := range cases {
		if got := DenyHint(tc.access, tc.perm); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
	for kind, want := range map[PrincipalKind]bool{
		PrincipalToken: true, PrincipalOIDC: true, PrincipalOperator: false, PrincipalNode: false,
		PrincipalControlPlane: false, PrincipalSystem: false, PrincipalSandboxKey: false, "": false,
	} {
		if HintPrincipal(kind) != want {
			t.Errorf("HintPrincipal(%q) = %v, want %v", kind, !want, want)
		}
	}
}
