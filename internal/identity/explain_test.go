package identity

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// rawJWT is a compact JWT with claims and a junk signature: ExplainClaims
// runs only on a bearer this node already verified, so it reads claims and
// never the signature.
func rawJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc(body) + ".c2ln"
}

func TestExplainClaims(t *testing.T) {
	names := &controlplane.ClaimNames{Issuer: "okta", Username: "email", Groups: "groups", Roles: "roles"}
	base := func(extra map[string]any) map[string]any {
		c := map[string]any{"iss": "https://idp", "sub": "00u1", "aud": "cli", "exp": 1_900_000_000}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	cases := []struct {
		name   string
		names  *controlplane.ClaimNames
		bearer string
		want   *identitywire.ExplainClaims
	}{
		{name: "no claim names (not an OIDC caller)", names: nil, bearer: rawJWT(t, base(nil)), want: nil},
		{name: "groups and roles", names: names,
			bearer: rawJWT(t, base(map[string]any{"email": "ana@acme.com", "groups": []string{"payments-eng", "everyone"}, "roles": "AerolVM.Runner"})),
			want:   &identitywire.ExplainClaims{Issuer: "okta", Username: "ana@acme.com", Groups: []string{"payments-eng", "everyone"}, Roles: []string{"AerolVM.Runner"}}},
		{name: "no username claim: the subject", names: names, bearer: rawJWT(t, base(nil)),
			want: &identitywire.ExplainClaims{Issuer: "okta", Username: "00u1"}},
		{name: "the issuer's own claim names", names: &controlplane.ClaimNames{Issuer: "kc", Username: "preferred_username", Groups: "grp", Roles: "app_roles"},
			bearer: rawJWT(t, base(map[string]any{"preferred_username": "ana", "grp": []string{"a"}, "groups": []string{"ignored"}, "app_roles": []string{"r"}})),
			want:   &identitywire.ExplainClaims{Issuer: "kc", Username: "ana", Groups: []string{"a"}, Roles: []string{"r"}}},
		{name: "Entra overage: no groups listed", names: names,
			bearer: rawJWT(t, base(map[string]any{"email": "ana@acme.com", "groups": []string{"partial"}, "_claim_names": map[string]string{"groups": "src1"}})),
			want:   &identitywire.ExplainClaims{Issuer: "okta", Username: "ana@acme.com", GroupOverage: true}},
		{name: "control characters stripped", names: names,
			bearer: rawJWT(t, base(map[string]any{"email": "ana\u001b[2J@acme.com", "groups": []string{"ok", "\u0007"}})),
			want:   &identitywire.ExplainClaims{Issuer: "okta", Username: "ana[2J@acme.com", Groups: []string{"ok"}}},
		{name: "not a JWT", names: names, bearer: "avm_x", want: &identitywire.ExplainClaims{Issuer: "okta"}},
		{name: "over the size cap", names: names, bearer: "a." + strings.Repeat("b", MaxJWTBytes) + ".c", want: &identitywire.ExplainClaims{Issuer: "okta"}},
		{name: "a payload that is not claims", names: names, bearer: "eyJhbGciOiJSUzI1NiJ9.bm9wZQ.c2ln", want: &identitywire.ExplainClaims{Issuer: "okta"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExplainClaims(tc.bearer, tc.names); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExplainClaims = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestExplainEndToEndFromTheVerifier: the Access the verifier builds for a
// token carries what explain needs, and explain reads only that token.
func TestExplainEndToEndFromTheVerifier(t *testing.T) {
	env := newVerifierEnv(t, "")
	c := env.claims("00u1", "payments-eng", "billing-eng")
	c["roles"] = []string{"AerolVM.Runner"}
	bearer := env.iss.Mint(t, c)
	a, _, err := env.auth(bearer)
	if err != nil {
		t.Fatal(err)
	}
	got := ExplainClaims(bearer, a.ClaimNames)
	want := &identitywire.ExplainClaims{Issuer: "test", Username: "00u1@acme.com", Groups: []string{"payments-eng", "billing-eng"}, Roles: []string{"AerolVM.Runner"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explain = %+v, want %+v", got, want)
	}
	// A cache hit hands out the same claim names and binding lines.
	again, _, _ := env.auth(bearer)
	if again.ClaimNames != a.ClaimNames || len(again.Bindings) != 3 || again.Bindings[2].Rule != a.Bindings[2].Rule {
		t.Fatalf("cached access = %+v", again)
	}
}
