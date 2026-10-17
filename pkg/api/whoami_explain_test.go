package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWhoAmIExplainThroughTheEdge is D22 end to end: the real auth edge
// with the OIDC verifier and the API-token authenticator, then GET
// /v1/whoami?explain=1. An SSO caller sees the bindings its own claims
// matched (1-based index and canonical line, the selected one in effect)
// and its own claims; X-AerolVM-Team moves "in effect" without changing
// what matched; the PAT and an avm_ token get a block saying bindings
// don't apply; and without the parameter the body is byte for byte the
// plain whoami.
func TestWhoAmIExplainThroughTheEdge(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	set := &switchableTokens{}
	apiToken := mintToken(t, set, "ci-deploy", "payments", controlplane.RoleRunner, time.Now().Add(time.Hour))
	h := NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, identity.NewTokenAuthenticator(set, discardLogger())),
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, env.v)).Handler()
	sso := env.token(t, "billing-eng", "payments-eng", "everyone")
	payments := identitywire.ExplainBinding{Index: 2, Text: `okta group="payments-eng" -> runner/payments`}
	billing := identitywire.ExplainBinding{Index: 3, Text: `okta group="billing-eng" -> viewer/billing`}
	inEffect := func(b identitywire.ExplainBinding) identitywire.ExplainBinding { b.InEffect = true; return b }
	ssoClaims := &identitywire.ExplainClaims{Issuer: "okta", Username: "ana@acme.com", Groups: []string{"billing-eng", "payments-eng", "everyone"}}

	cases := []struct {
		name     string
		bearer   string
		team     string
		wantRole string
		wantTeam string
		want     identitywire.WhoAmIExplain
	}{
		{name: "SSO: the first match is in effect", bearer: sso, wantRole: "runner", wantTeam: "payments",
			want: identitywire.WhoAmIExplain{BindingsApply: true, Matched: []identitywire.ExplainBinding{inEffect(payments), billing}, Claims: ssoClaims}},
		{name: "SSO with X-AerolVM-Team: billing", bearer: sso, team: "billing", wantRole: "viewer", wantTeam: "billing",
			want: identitywire.WhoAmIExplain{BindingsApply: true, Matched: []identitywire.ExplainBinding{payments, inEffect(billing)}, Claims: ssoClaims}},
		{name: "the operator token", bearer: "pat-token", wantRole: "admin", wantTeam: "*",
			want: identitywire.WhoAmIExplain{Note: "the operator token (SB_PAT_TOKEN) acts as admin on every team; identity-file bindings don't apply", Matched: []identitywire.ExplainBinding{}}},
		{name: "an API token", bearer: apiToken, wantRole: "runner", wantTeam: "payments",
			want: identitywire.WhoAmIExplain{Note: "an API token carries its own role and team; identity-file bindings don't apply", Matched: []identitywire.ExplainBinding{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := map[string]string{}
			if tc.team != "" {
				header[HeaderTeam] = tc.team
			}
			rec := serve(h, http.MethodGet, "/v1/whoami?explain=1", tc.bearer, header)
			var got struct {
				models.WhoAmI
				Explain *identitywire.WhoAmIExplain `json:"explain"`
			}
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Explain == nil {
				t.Fatalf("whoami?explain=1 = %d %s", rec.Code, rec.Body.String())
			}
			if got.Role != tc.wantRole || got.Team != tc.wantTeam || !reflect.DeepEqual(*got.Explain, tc.want) {
				t.Fatalf("role %s team %s explain %+v\nwant role %s team %s explain %+v", got.Role, got.Team, *got.Explain, tc.wantRole, tc.wantTeam, tc.want)
			}
			// The identity file as a whole never leaks: the admin binding
			// the caller did not match is not in the answer.
			if strings.Contains(rec.Body.String(), "platform-admins") {
				t.Fatalf("explain named a binding the caller did not match: %s", rec.Body.String())
			}

			// Without the parameter (or with explain=0) the body is exactly
			// the plain whoami: no explain key at all.
			plain := serve(h, http.MethodGet, "/v1/whoami", tc.bearer, header)
			off := serve(h, http.MethodGet, "/v1/whoami?explain=0", tc.bearer, header)
			if plain.Code != http.StatusOK || strings.Contains(plain.Body.String(), "explain") || off.Body.String() != plain.Body.String() {
				t.Fatalf("plain whoami = %d %s; explain=0 = %s", plain.Code, plain.Body.String(), off.Body.String())
			}
			var who models.WhoAmI
			if err := json.Unmarshal(plain.Body.Bytes(), &who); err != nil || !reflect.DeepEqual(who, got.WhoAmI) {
				t.Fatalf("the explained whoami's identity part differs from the plain one: %+v vs %+v", got.WhoAmI, who)
			}
		})
	}
}
