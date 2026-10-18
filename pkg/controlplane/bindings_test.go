package controlplane

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestTeamBindingApplyAndOIDCAccess(t *testing.T) {
	p := Principal{Kind: PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com"}
	exp := time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC)
	bindings := []TeamBinding{{Role: RoleRunner, Team: "payments"}, {Role: RoleAdmin, Team: FleetTeam}}

	a := OIDCAccess(p, bindings, exp)
	if a.Fleet || a.Role != RoleRunner || a.Identity.OwnerRef != "team:payments" || a.Team() != "payments" ||
		a.Principal != p || !a.ExpiresAt.Equal(exp) || !reflect.DeepEqual(a.Bindings, bindings) {
		t.Fatalf("OIDCAccess scoped to the first binding = %+v", a)
	}
	fleet := bindings[1].Apply(a)
	if !fleet.Fleet || fleet.Role != RoleAdmin || fleet.Identity.OwnerRef != "" || fleet.Team() != FleetTeam ||
		fleet.Principal != p || !reflect.DeepEqual(fleet.Bindings, bindings) {
		t.Fatalf("applying the fleet binding = %+v", fleet)
	}
	back := bindings[0].Apply(fleet)
	if back.Fleet || back.Team() != "payments" {
		t.Fatalf("narrowing again = %+v", back)
	}
	// A token that matched nothing is never given an Access, but the
	// constructor must not invent a scope for one.
	none := OIDCAccess(p, nil, exp)
	if none.Role != "" || none.Fleet || none.Identity.OwnerRef != "" || none.Can(PermSandboxRead) {
		t.Fatalf("OIDCAccess with no bindings = %+v", none)
	}
}

func TestNoBindingError(t *testing.T) {
	nb := &NoBindingError{Issuer: "okta", Name: "ana@acme.com", Groups: []string{"g"}}
	if nb.Reason() != NoBindingReason || nb.Error() == "" {
		t.Fatalf("no binding = %q %q", nb.Reason(), nb.Error())
	}
	over := &NoBindingError{Issuer: "entra", Overage: true}
	if over.Reason() != GroupOverageReason {
		t.Fatalf("overage reason = %q", over.Reason())
	}
	wrapped := fmt.Errorf("authenticate: %w", nb)
	if got, ok := AsNoBindingError(wrapped); !ok || got != nb {
		t.Fatal("AsNoBindingError must find a wrapped error")
	}
	if _, ok := AsNoBindingError(errors.New("other")); ok {
		t.Fatal("AsNoBindingError matched an unrelated error")
	}
	if errors.Is(nb, ErrTokenRejected) {
		t.Fatal("a verified token with no binding is a 403, not a rejected credential")
	}
}
