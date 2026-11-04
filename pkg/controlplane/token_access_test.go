package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestTokenAccess pins the API-token row of the §5.1 invariant table: a
// team-bound token is fenced to team:<team>, a fleet token is unscoped, the
// principal is the token's public id, and the name is sanitized.
func TestTokenAccess(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	team := TokenAccess("tok_7Hq2aBcDeFgH", "ci\ndeploy", RoleRunner, "payments", exp)
	if team.Fleet || team.Identity.OwnerRef != "team:payments" || team.Team() != "payments" || team.Role != RoleRunner ||
		team.Principal != (Principal{Kind: PrincipalToken, ID: "tok_7Hq2aBcDeFgH", Name: "cideploy"}) || !team.ExpiresAt.Equal(exp) {
		t.Fatalf("team token = %+v", team)
	}
	if !team.Can(PermSandboxExec) || team.Can(PermMetricsRead) || team.HostCapable() {
		t.Fatal("a team runner token: exec yes, fleet metrics no, host powers no")
	}
	fleet := TokenAccess("tok_7Hq2aBcDeFgH", "prom", RoleViewer, FleetTeam, exp)
	if !fleet.Fleet || fleet.Identity.OwnerRef != "" || fleet.Team() != FleetTeam || !fleet.Can(PermMetricsRead) || fleet.Can(PermSandboxWrite) {
		t.Fatalf("fleet viewer token = %+v", fleet)
	}
	admin := TokenAccess("tok_7Hq2aBcDeFgH", "root", RoleAdmin, FleetTeam, exp)
	if !admin.Can(PermTokenWrite) || !admin.HostCapable() {
		t.Fatal("a fleet admin token holds token.write and host powers")
	}
	if HintPrincipal(team.Principal.Kind) != true {
		t.Fatal("a token caller gets the D9 hint")
	}
	if !errors.Is(ErrIdentityStale, ErrIdentityStale) || ErrIdentityStale.Error() == "" {
		t.Fatal("ErrIdentityStale")
	}
}

func TestRoutePermissionContext(t *testing.T) {
	if _, ok := RoutePermissionFromContext(context.Background()); ok {
		t.Fatal("no route permission on a bare context")
	}
	ctx := ContextWithRoutePermission(context.Background(), PermMetricsRead)
	if p, ok := RoutePermissionFromContext(ctx); !ok || p != PermMetricsRead {
		t.Fatalf("got %q %v", p, ok)
	}
}
