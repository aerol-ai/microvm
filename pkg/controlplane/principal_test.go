package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The §5.1 invariant rows that live in this package: the constructors every
// authenticator uses to build an Access. The end-to-end table through the
// API's authenticate() is TestPrincipalInvariants in pkg/api.
func TestAccessConstructors(t *testing.T) {
	op := OperatorAccess()
	if !op.Fleet || op.Role != RoleAdmin || op.Principal != (Principal{Kind: PrincipalOperator, ID: "operator", Name: "operator"}) || op.Via != "" {
		t.Fatalf("OperatorAccess = %+v", op)
	}
	node := NodeAccess("n3")
	if !node.Fleet || node.Role != RoleAdmin || node.Principal != (Principal{Kind: PrincipalNode, ID: "node:n3", Name: "node:n3"}) {
		t.Fatalf("NodeAccess = %+v", node)
	}
	if op.Team() != FleetTeam || node.Team() != FleetTeam {
		t.Fatalf("fleet callers act on every team: %q %q", op.Team(), node.Team())
	}
}

func TestControlPlaneAccess(t *testing.T) {
	cases := []struct {
		name     string
		identity Identity
		wantErr  error
		wantRole Role
		wantID   string
		wantName string
	}{
		{name: "no role means runner (L8)", identity: Identity{ExternalID: "u1", OwnerRef: "acme"}, wantRole: RoleRunner, wantID: "controlplane:u1", wantName: "u1"},
		{name: "viewer narrows", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Role: RoleViewer}, wantRole: RoleViewer, wantID: "controlplane:u1", wantName: "u1"},
		{name: "runner explicit", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Role: RoleRunner, Name: "Ana"}, wantRole: RoleRunner, wantID: "controlplane:u1", wantName: "Ana"},
		{name: "admin is refused, never clamped", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Role: RoleAdmin}, wantErr: ErrIdentityRole},
		{name: "auditor is refused", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Role: RoleAuditor}, wantErr: ErrIdentityRole},
		{name: "unknown role is refused", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Role: "root"}, wantErr: ErrIdentityRole},
		{name: "empty owner is refused", identity: Identity{ExternalID: "u1"}, wantErr: ErrIdentityNoOwner},
		{name: "blank owner is refused", identity: Identity{ExternalID: "u1", OwnerRef: "  "}, wantErr: ErrIdentityNoOwner},
		{name: "no external id falls back to the owner", identity: Identity{OwnerRef: "acme"}, wantRole: RoleRunner, wantID: "controlplane:acme", wantName: "acme"},
		{name: "display name is sanitised", identity: Identity{ExternalID: "u1", OwnerRef: "acme", Name: "Ana\n\x1b[31m"}, wantRole: RoleRunner, wantID: "controlplane:u1", wantName: "Ana[31m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ControlPlaneAccess(tc.identity)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrTokenRejected) {
					t.Fatalf("err = %v, want %v wrapping ErrTokenRejected", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got.Fleet || got.Role != tc.wantRole || got.Principal.Kind != PrincipalControlPlane ||
				got.Principal.ID != tc.wantID || got.Principal.Name != tc.wantName {
				t.Fatalf("access = %+v", got)
			}
			if got.Identity != tc.identity {
				t.Fatalf("identity not carried: %+v", got.Identity)
			}
			if got.Team() != "" {
				t.Fatalf("a managed account is not a team: %q", got.Team())
			}
		})
	}
}

func TestTeamOfAccess(t *testing.T) {
	cases := map[string]struct {
		access Access
		want   string
	}{
		"fleet":           {Access{Fleet: true}, FleetTeam},
		"team owner":      {Access{Identity: Identity{OwnerRef: TeamOwnerRef("payments")}}, "payments"},
		"managed account": {Access{Identity: Identity{OwnerRef: "acct-1"}}, ""},
		"fleet wins":      {Access{Fleet: true, Identity: Identity{OwnerRef: TeamOwnerRef("payments")}}, FleetTeam},
	}
	for name, tc := range cases {
		if got := tc.access.Team(); got != tc.want {
			t.Errorf("%s: Team() = %q, want %q", name, got, tc.want)
		}
	}
	if TeamOwnerRef("payments") != "team:payments" {
		t.Fatal("team owner prefix changed: it is part of every stored owner ref")
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleViewer, RoleRunner, RoleAuditor, RoleAdmin} {
		if !r.Valid() {
			t.Errorf("%q not valid", r)
		}
	}
	for _, r := range []Role{"", "root", "Admin"} {
		if r.Valid() {
			t.Errorf("%q valid", r)
		}
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"  ana@acme.com  ":       "ana@acme.com",
		"ci\tdeploy\r\n":         "cideploy",
		"\x00evil\x07":           "evil",
		"zoë 漢字":                 "zoë 漢字",
		strings.Repeat("é", 300): strings.Repeat("é", 256),
	}
	for in, want := range cases {
		if got := SanitizeDisplayName(in); got != want {
			t.Errorf("SanitizeDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCredentialError(t *testing.T) {
	var err error = &CredentialError{Kind: PrincipalToken, Reason: RejectExpired}
	if !errors.Is(err, ErrTokenRejected) {
		t.Fatal("a credential refusal must read as ErrTokenRejected")
	}
	if !strings.Contains(err.Error(), "token") || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Error() = %q", err.Error())
	}
	wrapped := errors.Join(errors.New("context"), err)
	ce, ok := AsCredentialError(wrapped)
	if !ok || ce.Reason != RejectExpired {
		t.Fatalf("AsCredentialError(wrapped) = %v, %v", ce, ok)
	}
	if _, ok := AsCredentialError(ErrTokenRejected); ok {
		t.Fatal("a bare rejection is not a credential error")
	}
}

func TestRejectReasonValid(t *testing.T) {
	// The D17 list is a wire contract: callers and SDKs switch on it.
	want := []RejectReason{"expired", "not_yet_valid", "unknown_issuer", "wrong_audience", "too_long_lived", "invalid_signature", "malformed", "unknown_or_revoked"}
	for _, r := range want {
		if !r.Valid() {
			t.Errorf("%q not valid", r)
		}
	}
	for _, r := range []RejectReason{"", "kid_unknown", "Expired"} {
		if r.Valid() {
			t.Errorf("%q must not be sendable", r)
		}
	}
}

type acceptAll struct{}

func (acceptAll) Validate(context.Context, string) (Identity, error) {
	return Identity{OwnerRef: "x"}, nil
}

func TestHasExternalValidator(t *testing.T) {
	if Noop().HasExternalValidator() {
		t.Fatal("noop provider has no validator of its own")
	}
	if (Provider{}).HasExternalValidator() {
		t.Fatal("nil validator is no validator")
	}
	if !(Provider{Validator: acceptAll{}}).HasExternalValidator() {
		t.Fatal("a real validator must be reported")
	}
	if !IsNoopValidator(nil) || !IsNoopValidator(Noop().Validator) || IsNoopValidator(acceptAll{}) {
		t.Fatal("IsNoopValidator disagrees with the provider")
	}
}
