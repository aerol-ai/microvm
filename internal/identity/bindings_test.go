package identity

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func claimsFrom(t *testing.T, doc string) *tokenClaims {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatal(err)
	}
	return &tokenClaims{raw: raw}
}

// TestBindingMatch covers every matcher: group, app role, claim (string,
// list, bool and number values), the email_verified rule, overage, and
// deduplication by role and team in file order.
func TestBindingMatch(t *testing.T) {
	c, err := Parse([]byte(minimalIssuer + `    claims: {groups: grp, roles: app}
bindings:
  - {issuer: okta, group: admins, role: admin}
  - {issuer: okta, app_role: AerolVM.Viewer, role: viewer, team: payments}
  - {issuer: okta, claim: {email: ana@acme.com}, role: runner, team: payments}
  - {issuer: okta, claim: {repository: acme/payments, ref: refs/heads/main}, role: runner, team: ci}
  - {issuer: okta, claim: {amr: mfa}, role: viewer, team: mfa}
  - {issuer: okta, claim: {staff: "true"}, role: viewer, team: staff}
  - {issuer: okta, claim: {level: "3"}, role: viewer, team: level3}
  - {issuer: okta, group: payments, role: runner, team: payments}
`))
	if err != nil {
		t.Fatal(err)
	}
	iss := c.Issuers[0]
	cases := []struct {
		name        string
		claims      string
		want        []string
		wantGroups  []string
		wantOverage bool
	}{
		{name: "nothing", claims: `{}`},
		{name: "group claim under its configured name", claims: `{"grp":["admins"],"groups":["payments"]}`, want: []string{"admin/*"}, wantGroups: []string{"admins"}},
		{name: "single-string group", claims: `{"grp":"payments"}`, want: []string{"runner/payments"}, wantGroups: []string{"payments"}},
		{name: "app role", claims: `{"app":["AerolVM.Viewer"]}`, want: []string{"viewer/payments"}},
		{name: "verified email", claims: `{"email":"ana@acme.com","email_verified":true}`, want: []string{"runner/payments"}},
		{name: "verified email as a string", claims: `{"email":"ana@acme.com","email_verified":"true"}`, want: []string{"runner/payments"}},
		{name: "unverified email never matches", claims: `{"email":"ana@acme.com","email_verified":false}`},
		{name: "email with no email_verified", claims: `{"email":"ana@acme.com"}`},
		{name: "every claim must match", claims: `{"repository":"acme/payments","ref":"refs/heads/dev"}`},
		{name: "all claims match", claims: `{"repository":"acme/payments","ref":"refs/heads/main"}`, want: []string{"runner/ci"}},
		{name: "list claim contains", claims: `{"amr":["pwd","mfa"]}`, want: []string{"viewer/mfa"}},
		{name: "list claim lacks", claims: `{"amr":["pwd",3]}`},
		{name: "bool claim", claims: `{"staff":true}`, want: []string{"viewer/staff"}},
		{name: "number claim", claims: `{"level":3}`, want: []string{"viewer/level3"}},
		{name: "object claim never matches", claims: `{"level":{"v":3}}`},
		{name: "null claim never matches", claims: `{"level":null}`},
		{name: "dedup: verified email and group grant the same role", claims: `{"email":"ana@acme.com","email_verified":true,"grp":["payments"]}`,
			want: []string{"runner/payments"}, wantGroups: []string{"payments"}},
		{name: "overage hides the groups claim", claims: `{"grp":["admins"],"_claim_names":{"grp":"src1"},"_claim_sources":{"src1":{}}}`, wantOverage: true},
		{name: "overage pointer for another claim is not overage", claims: `{"grp":["admins"],"_claim_names":{"other":"src1"}}`, want: []string{"admin/*"}, wantGroups: []string{"admins"}},
		{name: "hasgroups overage", claims: `{"hasgroups":true}`, wantOverage: true},
		{name: "bad _claim_names is ignored", claims: `{"_claim_names":"x","grp":["admins"]}`, want: []string{"admin/*"}, wantGroups: []string{"admins"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := iss.match(claimsFrom(t, tc.claims))
			got := []string{}
			for _, b := range m.bindings {
				got = append(got, string(b.Role)+"/"+b.Team)
			}
			if tc.want == nil {
				tc.want = []string{}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("bindings = %v, want %v", got, tc.want)
			}
			if !reflect.DeepEqual(m.groups, tc.wantGroups) || m.overage != tc.wantOverage {
				t.Fatalf("groups %v overage %v, want %v %v", m.groups, m.overage, tc.wantGroups, tc.wantOverage)
			}
		})
	}
}

func TestTeamBindingApply(t *testing.T) {
	base := controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:x:1"}}
	team := controlplane.TeamBinding{Role: controlplane.RoleRunner, Team: "payments"}.Apply(base)
	if team.Fleet || team.Identity.OwnerRef != "team:payments" || team.Role != controlplane.RoleRunner {
		t.Fatalf("team binding = %+v", team)
	}
	fleet := controlplane.TeamBinding{Role: controlplane.RoleAdmin, Team: "*"}.Apply(team)
	if !fleet.Fleet || fleet.Identity.OwnerRef != "" || fleet.Role != controlplane.RoleAdmin || fleet.Principal != base.Principal {
		t.Fatalf("fleet binding = %+v", fleet)
	}
}
