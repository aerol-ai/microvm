package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// planExample is the §5.5 example identity file, verbatim apart from the
// EKS issuer's placeholder host.
const planExample = `version: 1
issuers:
  - name: okta                         # stable; part of the principal id
    display_name: Acme Okta            # dashboard button label (design review DR3)
    url: https://acme.okta.com/oauth2/default
    audiences: [0oa1cli, 0oa1dash]     # client ids of the CLI and dashboard apps
    clients: { cli: 0oa1cli, dashboard: 0oa1dash }   # published in discovery
    claims: { username: email, groups: groups }
    max_token_lifetime: 12h
    mcp: true                          # listed in RFC 9728 metadata (§5.14)
    mcp_audiences: [api://aerolvm-mcp] # access-token audiences accepted only on /mcp
  - name: google
    display_name: Google
    kind: google                       # dashboard uses Google Identity Services (§5.7)
    url: https://accounts.google.com
    audiences: [123-cli.apps.googleusercontent.com, 123-dash.apps.googleusercontent.com]
    clients: { cli: 123-cli.apps.googleusercontent.com, dashboard: 123-dash.apps.googleusercontent.com }
    claims: { username: email }
  - name: github-actions               # workload identity: CI with no stored token
    url: https://token.actions.githubusercontent.com
    audiences: [aerolvm]
    claims: { username: sub }
  - name: eks-prod                     # workload identity: Kubernetes service-account tokens
    url: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE
    audiences: [aerolvm]
    claims: { username: sub }
bindings:                              # first match wins, top to bottom
  - { issuer: okta, group: platform-admins, role: admin }
  - { issuer: okta, group: secops,          role: auditor }
  - { issuer: okta, group: payments-eng,    role: runner, team: payments }
  - { issuer: github-actions, claim: { repository: acme/payments, ref: refs/heads/main }, role: runner, team: payments }
  - { issuer: eks-prod, claim: { sub: "system:serviceaccount:payments:ci" }, role: runner, team: payments }
deny_subjects: []                      # emergency block, "<issuer>:<sub>", applied on reload
mcp:
  resource: https://api.acme.dev/mcp   # one resource URL, as RFC 9728 requires (§5.14)
`

func TestParsePlanExample(t *testing.T) {
	c, err := Parse([]byte(planExample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sum := sha256.Sum256([]byte(planExample))
	if c.Hash() != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash = %s, want the file's sha256", c.Hash())
	}
	if len(c.Issuers) != 4 || len(c.Bindings) != 5 || c.MCPResource != "https://api.acme.dev/mcp" {
		t.Fatalf("issuers %d, bindings %d, mcp %q", len(c.Issuers), len(c.Bindings), c.MCPResource)
	}
	okta, ok := c.IssuerByName("okta")
	if !ok || okta.DisplayName != "Acme Okta" || okta.Kind != identitywire.IssuerKindOIDC || okta.MaxTokenLifetime != 12*time.Hour ||
		okta.UsernameClaim != "email" || okta.GroupsClaim != "groups" || okta.RolesClaim != "roles" || !okta.MCP ||
		!reflect.DeepEqual(okta.MCPAudiences, []string{"api://aerolvm-mcp"}) {
		t.Fatalf("okta = %+v", okta)
	}
	gh, _ := c.IssuerByName("github-actions")
	if gh.DisplayName != "github-actions" || gh.MaxTokenLifetime != DefaultMaxTokenLifetime {
		t.Fatalf("display name falls back to the name and the lifetime to 24h: %+v", gh)
	}
	admin := c.Bindings[0]
	if admin.Role != controlplane.RoleAdmin || admin.Team != controlplane.FleetTeam {
		t.Fatalf("an admin binding without a team is fleet-wide: %+v", admin)
	}
	if got := c.Bindings[3].claimKeys; !reflect.DeepEqual(got, []string{"ref", "repository"}) {
		t.Fatalf("claim keys sorted = %v", got)
	}
	if _, ok := c.issuerForIss("accounts.google.com"); !ok {
		t.Fatal("Google's scheme-less iss must find the google issuer")
	}
	if _, ok := c.issuerForIss("https://evil.example"); ok {
		t.Fatal("an unknown iss matched an issuer")
	}
}

// TestDiscoveryIssuers is DR3: only issuers with a CLI or dashboard client
// id are published (the two workload issuers are not), in file order, with
// the display name.
func TestDiscoveryIssuers(t *testing.T) {
	c, err := Parse([]byte(planExample))
	if err != nil {
		t.Fatal(err)
	}
	got := c.DiscoveryIssuers()
	want := []identitywire.DiscoveryIssuer{
		{Name: "okta", DisplayName: "Acme Okta", Kind: "oidc", URL: "https://acme.okta.com/oauth2/default",
			Clients: identitywire.DiscoveryClients{CLI: "0oa1cli", Dashboard: "0oa1dash"}},
		{Name: "google", DisplayName: "Google", Kind: "google", URL: "https://accounts.google.com",
			Clients: identitywire.DiscoveryClients{CLI: "123-cli.apps.googleusercontent.com", Dashboard: "123-dash.apps.googleusercontent.com"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discovery issuers =\n %+v\nwant\n %+v", got, want)
	}
}

const minimalIssuer = `version: 1
issuers:
  - name: okta
    url: https://acme.okta.com
    audiences: [cli]
`

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"empty file (4.3)", "", "identity file is empty"},
		{"whitespace and comments only", "  \n# nothing here\n", "identity file is empty"},
		{"unknown top-level key", minimalIssuer + "groups: []\n", "field groups not found"},
		{"unknown issuer key", strings.Replace(minimalIssuer, "audiences: [cli]", "audiences: [cli]\n    secret: x", 1), "field secret not found"},
		{"two documents", minimalIssuer + "---\nversion: 1\n", "more than one YAML document"},
		{"wrong version", strings.Replace(minimalIssuer, "version: 1", "version: 2", 1), "version 2, want 1"},
		{"no version", strings.Replace(minimalIssuer, "version: 1\n", "", 1), "version 0, want 1"},
		{"no issuers", "version: 1\n", "no issuers"},
		{"bad issuer name", strings.Replace(minimalIssuer, "name: okta", "name: Okta_1", 1), "want 1 to 63 characters"},
		{"http issuer", strings.Replace(minimalIssuer, "https://acme.okta.com", "http://acme.okta.com", 1), "want an https URL"},
		{"issuer with a query", strings.Replace(minimalIssuer, "https://acme.okta.com", "https://acme.okta.com?x=1", 1), "want an https URL"},
		{"issuer with a user", strings.Replace(minimalIssuer, "https://acme.okta.com", "https://u@acme.okta.com", 1), "want an https URL"},
		{"not a url", strings.Replace(minimalIssuer, "https://acme.okta.com", "\"https://%zz\"", 1), "is not a URL"},
		{"no audiences", strings.Replace(minimalIssuer, "    audiences: [cli]\n", "", 1), "at least one is required"},
		{"empty audience", strings.Replace(minimalIssuer, "[cli]", "[cli, \"\"]", 1), "an audience is empty"},
		{"duplicate audience", strings.Replace(minimalIssuer, "[cli]", "[cli, cli]", 1), "listed twice"},
		{"mcp audiences overlap (§5.14)", minimalIssuer + "    mcp_audiences: [cli]\n", "must not overlap"},
		{"empty mcp audience", minimalIssuer + "    mcp_audiences: [\"\"]\n", "an audience is empty"},
		{"duplicate mcp audience", minimalIssuer + "    mcp_audiences: [m, m]\n", "listed twice"},
		{"mcp without audiences", minimalIssuer + "    mcp: true\n", "needs mcp_audiences"},
		{"mcp without resource", minimalIssuer + "    mcp: true\n    mcp_audiences: [m]\n", "needs the top-level mcp.resource"},
		{"mcp on google", "version: 1\nissuers:\n  - {name: g, kind: google, url: https://accounts.google.com, audiences: [a], mcp: true, mcp_audiences: [m]}\nmcp: {resource: https://x/mcp}\n", "opaque"},
		{"http mcp resource", minimalIssuer + "mcp: {resource: http://api/mcp}\n", "mcp.resource"},
		{"bad kind", minimalIssuer + "    kind: saml\n", "want oidc or google"},
		{"cli client not an audience", minimalIssuer + "    clients: {cli: other}\n", "clients.cli \"other\" is not in audiences"},
		{"dashboard client not an audience", minimalIssuer + "    clients: {dashboard: other}\n", "clients.dashboard"},
		{"bad lifetime", minimalIssuer + "    max_token_lifetime: forever\n", "max_token_lifetime"},
		{"negative lifetime", minimalIssuer + "    max_token_lifetime: -1h\n", "max_token_lifetime"},
		{"lifetime over a year", minimalIssuer + "    max_token_lifetime: 9000h\n", "max_token_lifetime"},
		{"duplicate issuer name", minimalIssuer + "  - {name: okta, url: https://other.okta.com, audiences: [x]}\n", "used twice"},
		{"duplicate issuer url", minimalIssuer + "  - {name: okta2, url: https://acme.okta.com, audiences: [x]}\n", "is already issuer"},
		{"binding unknown issuer", minimalIssuer + "bindings:\n  - {issuer: nope, group: g, role: viewer, team: t}\n", "unknown issuer"},
		{"binding without matcher", minimalIssuer + "bindings:\n  - {issuer: okta, role: viewer, team: t}\n", "exactly one of group, app_role or claim"},
		{"binding with two matchers", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, app_role: r, role: viewer, team: t}\n", "exactly one"},
		{"binding with empty claim value", minimalIssuer + "bindings:\n  - {issuer: okta, claim: {sub: \"\"}, role: viewer, team: t}\n", "needs a name and a value"},
		{"binding bad role", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, role: root, team: t}\n", "want viewer, runner, auditor or admin"},
		{"runner without team", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, role: runner}\n", "needs a team"},
		{"bad team", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, role: runner, team: Pay_ments}\n", "want 1 to 63"},
		{"admin on one team", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, role: admin, team: payments}\n", "bound to every team"},
		{"auditor on one team", minimalIssuer + "bindings:\n  - {issuer: okta, group: g, role: auditor, team: payments}\n", "bound to every team"},
		{"deny without colon", minimalIssuer + "deny_subjects: [okta]\n", "is not <issuer>:<sub>"},
		{"deny without sub", minimalIssuer + "deny_subjects: [\"okta:\"]\n", "is not <issuer>:<sub>"},
		{"deny unknown issuer", minimalIssuer + "deny_subjects: [\"oktaa:00u1\"]\n", "unknown issuer"},
		{"yaml syntax", "version: [1\n", "identity file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseEmptyIsErrEmptyFile(t *testing.T) {
	if _, err := Parse(nil); !errors.Is(err, ErrEmptyFile) {
		t.Fatalf("err = %v, want ErrEmptyFile", err)
	}
}

// TestDisplayName is DR3: control characters are stripped, the label is
// trimmed, and one over 40 characters or with nothing printable is refused
// at load. Whatever loads is what discovery publishes.
func TestDisplayName(t *testing.T) {
	cases := []struct {
		name, raw, want, wantErr string
	}{
		{name: "plain", raw: "Acme Okta", want: "Acme Okta"},
		{name: "control characters stripped", raw: "Acme\x1b[31m Okta\n", want: "Acme[31m Okta"},
		{name: "exactly 40", raw: strings.Repeat("a", 40), want: strings.Repeat("a", 40)},
		{name: "40 runes of multibyte", raw: strings.Repeat("é", 40), want: strings.Repeat("é", 40)},
		{name: "41 refused", raw: strings.Repeat("a", 41), wantErr: "41 characters, at most 40"},
		{name: "only control characters", raw: "\x01\x02", wantErr: "no printable characters"},
		{name: "unset falls back to name", raw: "", want: "okta"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := minimalIssuer + "    clients: {cli: cli}\n"
			if tc.raw != "" {
				doc += "    display_name: " + yamlQuote(tc.raw) + "\n"
			}
			c, err := Parse([]byte(doc))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := c.Issuers[0].DisplayName; got != tc.want {
				t.Fatalf("display name = %q, want %q", got, tc.want)
			}
			if got := c.DiscoveryIssuers()[0].DisplayName; got != tc.want {
				t.Fatalf("published display name = %q, want %q", got, tc.want)
			}
		})
	}
}

// yamlQuote double-quotes s with YAML escapes for control characters.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\x`)
			b.WriteString(hex.EncodeToString([]byte{byte(r)}))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// TestFileSizeCap is finding 5.5: a file over 1 MiB is refused, by Parse
// and by Load, which stops reading at the cap.
func TestFileSizeCap(t *testing.T) {
	// A count, not the *expvar.Int: the map hands back the same variable on
	// every call, so holding it would compare the live value with itself
	// and fail every run after the first under -count.
	before := oversizeCount(oversizeIdentityFile)
	big := []byte(minimalIssuer + "# " + strings.Repeat("x", MaxFileBytes) + "\n")
	if _, err := Parse(big); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("Parse err = %v, want ErrFileTooLarge", err)
	}
	path := filepath.Join(t.TempDir(), "identity.yaml")
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("Load err = %v, want ErrFileTooLarge", err)
	}
	if after := oversizeCount(oversizeIdentityFile); after <= before {
		t.Fatalf("oversize metric did not move: before %d after %d", before, after)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load of a missing file must fail")
	}
}

func TestDenied(t *testing.T) {
	c, err := Parse([]byte(minimalIssuer + "deny_subjects: [\"okta:00u1\", \" okta:system:serviceaccount:ns:sa \"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Denied("okta", "00u1") || !c.Denied("okta", "system:serviceaccount:ns:sa") {
		t.Fatal("listed subjects must be denied (sub may hold colons)")
	}
	if c.Denied("okta", "00u2") || c.Denied("google", "00u1") {
		t.Fatal("unlisted subjects must not be denied")
	}
}

func TestBindingTeamRules(t *testing.T) {
	c, err := Parse([]byte(minimalIssuer + `bindings:
  - {issuer: okta, group: a, role: viewer, team: "*"}
  - {issuer: okta, app_role: AerolVM.Runner, role: runner, team: payments}
  - {issuer: okta, group: s, role: auditor, team: "*"}
`))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, b := range c.Bindings {
		got = append(got, string(b.Role)+"/"+b.Team)
	}
	if want := []string{"viewer/*", "runner/payments", "auditor/*"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bindings = %v, want %v", got, want)
	}
}

// FuzzIdentityFile (D21): whatever bytes arrive, Parse never panics, and a
// file it accepts is internally consistent: every binding names a declared
// issuer and a valid role, and its summary diffs cleanly against itself.
func FuzzIdentityFile(f *testing.F) {
	f.Add([]byte(planExample))
	f.Add([]byte(minimalIssuer))
	f.Add([]byte(""))
	f.Add([]byte("version: 1\nissuers: [{name: a, url: 'https://a', audiences: [x]}]\nbindings: [{issuer: a, claim: {k: v}, role: runner, team: t}]\ndeny_subjects: ['a:b']\n"))
	f.Add([]byte("a: &a [*a, *a, *a]\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := Parse(raw)
		if err != nil {
			if c != nil {
				t.Fatal("a refused file returned a config")
			}
			return
		}
		for _, b := range c.Bindings {
			if _, ok := c.IssuerByName(b.Issuer); !ok || !b.Role.Valid() || b.Team == "" {
				t.Fatalf("accepted an inconsistent binding: %+v", b)
			}
		}
		for _, iss := range c.Issuers {
			if iss.DisplayName == "" || len([]rune(iss.DisplayName)) > maxDisplayNameRunes || len(iss.Audiences) == 0 {
				t.Fatalf("accepted an inconsistent issuer: %+v", iss)
			}
		}
		d := Diff(c.Summary(), c.Summary())
		if len(d.BindingsAdded)+len(d.BindingsRemoved)+len(d.DenyAdded)+len(d.DenyRemoved)+len(d.IssuersAdded)+len(d.IssuersRemoved) != 0 || d.Reordered {
			t.Fatalf("a file diffed against itself shows changes: %+v", d)
		}
	})
}
