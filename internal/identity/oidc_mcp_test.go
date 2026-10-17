package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/identity/identitytest"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// entraTenant is a made-up Entra tenant id the MCP tests trust through its
// v2 issuer URL.
const entraTenant = "8f1a2b3c-0000-4000-8000-00000000abcd"

// mcpIdentityFile trusts the httptest issuer for ID tokens (cli) and for
// MCP access tokens (api://aerolvm-mcp), a second issuer that lists
// mcp_audiences without mcp: true, and an Entra tenant whose keys come from
// a file, so no test reaches the network.
func mcpIdentityFile(t *testing.T, url string) string {
	t.Helper()
	jwks := filepath.Join(t.TempDir(), "entra-jwks.json")
	if err := os.WriteFile(jwks, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`version: 1
issuers:
  - name: test
    url: %s
    audiences: [cli]
    claims: {username: email}
    max_token_lifetime: 2h
    mcp: true
    mcp_audiences: [api://aerolvm-mcp, 0a1b-api-app]
  - name: other
    url: https://other.example
    jwks_file: %s
    audiences: [other-cli]
    mcp_audiences: [api://other-mcp]
  - name: entra
    url: https://login.microsoftonline.com/%s/v2.0
    jwks_file: %s
    audiences: [entra-cli]
bindings:
  - {issuer: test, group: payments-eng, role: runner, team: payments}
mcp:
  resource: https://api.acme.dev/mcp
  scopes: [api://aerolvm-mcp/mcp]
`, url, jwks, entraTenant, jwks)
}

func newMCPVerifierEnv(t *testing.T) *verifierEnv {
	t.Helper()
	env := &verifierEnv{iss: identitytest.New(t), clock: newFakeClock()}
	env.load(t, mcpIdentityFile(t, env.iss.URL))
	env.v = NewVerifier(env.cfg.Load, VerifierOptions{HTTPClient: env.iss.Client(), Now: env.clock.Now})
	return env
}

// TestVerifierMCPAccessTokens is the access-token verify table (§5.14): an
// access token for an mcp_audiences audience is accepted and marked
// MCPOnly, with the issuer's bindings applied unchanged; an ID-token
// audience never is MCP-only; a wrong audience, another issuer's MCP
// audience and an opaque token are refused or not claimed.
func TestVerifierMCPAccessTokens(t *testing.T) {
	env := newMCPVerifierEnv(t)
	mint := func(aud any) string {
		c := env.iss.Claims(env.clock.Now(), "cli", "00u1", "payments-eng")
		c["aud"] = aud
		return env.iss.Mint(t, c)
	}
	cases := []struct {
		name        string
		bearer      string
		wantMatched bool
		wantReason  controlplane.RejectReason
		wantMCPOnly bool
	}{
		{name: "MCP access token (Okta-style audience)", bearer: mint("api://aerolvm-mcp"), wantMatched: true, wantMCPOnly: true},
		{name: "MCP access token (Entra v2: the API app's client id)", bearer: mint([]string{"0a1b-api-app"}), wantMatched: true, wantMCPOnly: true},
		{name: "ID token", bearer: mint("cli"), wantMatched: true},
		{name: "an ID audience next to an MCP audience is an ordinary token", bearer: mint([]string{"api://aerolvm-mcp", "cli"}), wantMatched: true},
		{name: "wrong audience", bearer: mint("https://api.acme.dev/mcp"), wantMatched: true, wantReason: controlplane.RejectWrongAudience},
		{name: "another issuer's MCP audience", bearer: mint("api://other-mcp"), wantMatched: true, wantReason: controlplane.RejectWrongAudience},
		{name: "opaque access token is not a JWT: not this authenticator's", bearer: "ya29.a0AfH6SMBopaque-token", wantMatched: false},
		{name: "opaque Okta-style reference token", bearer: "00Tq9opaqueReferenceToken", wantMatched: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, matched, err := env.auth(tc.bearer)
			if matched != tc.wantMatched {
				t.Fatalf("matched = %v, want %v", matched, tc.wantMatched)
			}
			if !matched {
				return
			}
			if tc.wantReason != "" {
				if got := reasonOf(err); got != tc.wantReason {
					t.Fatalf("err = %v, want %s", err, tc.wantReason)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if a.MCPOnly != tc.wantMCPOnly {
				t.Fatalf("MCPOnly = %v, want %v", a.MCPOnly, tc.wantMCPOnly)
			}
			if a.Role != controlplane.RoleRunner || a.Team() != "payments" || a.Principal.ID != "oidc:test:00u1" {
				t.Fatalf("bindings must apply to an access token exactly as to an ID token: %+v", a)
			}
		})
	}
}

// TestVerifierMCPOnlyFromCache: a cached MCP-only token stays MCP-only on
// every hit, and the cache is shared with no surface in its key (the
// surface rule runs per request, at the API edge).
func TestVerifierMCPOnlyFromCache(t *testing.T) {
	env := newMCPVerifierEnv(t)
	c := env.iss.Claims(env.clock.Now(), "api://aerolvm-mcp", "00u1", "payments-eng")
	bearer := env.iss.Mint(t, c)
	for i := 0; i < 3; i++ {
		a, _, err := env.auth(bearer)
		if err != nil || !a.MCPOnly {
			t.Fatalf("call %d: MCPOnly = %v, err %v", i, a.MCPOnly, err)
		}
	}
	if env.iss.JWKSHits.Load() != 1 {
		t.Fatalf("JWKS fetched %d times; repeats must be cache hits", env.iss.JWKSHits.Load())
	}
	id, _, err := env.auth(env.iss.Mint(t, env.iss.Claims(env.clock.Now(), "cli", "00u1", "payments-eng")))
	if err != nil || id.MCPOnly {
		t.Fatalf("the same person's ID token is not MCP-only: %+v %v", id, err)
	}
}

// TestVerifierEntraV1Hint: Entra signs custom-API access tokens in its v1
// format (iss https://sts.windows.net/<tenant>/) unless the API app's
// manifest sets accessTokenAcceptedVersion: 2. For a tenant the file trusts
// through its v2 URL, the unknown_issuer refusal carries the hint; for any
// other issuer it is a plain unknown_issuer.
func TestVerifierEntraV1Hint(t *testing.T) {
	env := newMCPVerifierEnv(t)
	mint := func(iss string) string {
		c := env.iss.Claims(env.clock.Now(), "0a1b-api-app", "00u1", "payments-eng")
		c["iss"] = iss
		c["ver"] = "1.0"
		return env.iss.Mint(t, c)
	}
	cases := []struct {
		name     string
		iss      string
		wantHint string
	}{
		{"v1 token from the trusted tenant", "https://sts.windows.net/" + entraTenant + "/", EntraV1Hint},
		{"v1 token without the trailing slash", "https://sts.windows.net/" + entraTenant, EntraV1Hint},
		{"v1 token from another tenant", "https://sts.windows.net/00000000-1111-4222-8333-444444444444/", ""},
		{"v1 issuer with no tenant", "https://sts.windows.net/", ""},
		{"v1 issuer with a path after the tenant", "https://sts.windows.net/" + entraTenant + "/x/", ""},
		{"some other unknown issuer", "https://evil.example", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched, err := env.auth(mint(tc.iss))
			ce, ok := controlplane.AsCredentialError(err)
			if !matched || !ok || ce.Reason != controlplane.RejectUnknownIssuer {
				t.Fatalf("err = %v, want unknown_issuer", err)
			}
			if ce.Hint != tc.wantHint {
				t.Fatalf("hint = %q, want %q", ce.Hint, tc.wantHint)
			}
		})
	}
	if strings.Contains(EntraV1Hint, entraTenant) {
		t.Fatal("the hint must never echo a claim value")
	}
}

// TestMCPAuthorizationServers: RFC 9728's authorization_servers are the
// issuers that set mcp: true, in file order; mcp_audiences alone does not
// publish an issuer, and a nil Config publishes none.
func TestMCPAuthorizationServers(t *testing.T) {
	env := newMCPVerifierEnv(t)
	c := env.cfg.Load()
	if got := c.MCPAuthorizationServers(); !reflect.DeepEqual(got, []string{env.iss.URL}) {
		t.Fatalf("authorization servers = %v", got)
	}
	if c.MCPResource != "https://api.acme.dev/mcp" || !reflect.DeepEqual(c.MCPScopes, []string{"api://aerolvm-mcp/mcp"}) {
		t.Fatalf("resource %q scopes %v", c.MCPResource, c.MCPScopes)
	}
	if (*Config)(nil).MCPAuthorizationServers() != nil {
		t.Fatal("a nil Config publishes no authorization server")
	}
	none, err := Parse([]byte(minimalIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if none.MCPAuthorizationServers() != nil || none.MCPResource != "" || none.MCPScopes != nil {
		t.Fatalf("a file without MCP publishes nothing: %v %q %v", none.MCPAuthorizationServers(), none.MCPResource, none.MCPScopes)
	}
}

// TestSummaryMCPScopes: a scope change is evidence (D20), on the same line
// as the resource it belongs to.
func TestSummaryMCPScopes(t *testing.T) {
	c, err := Parse([]byte(minimalIssuer + "mcp: {resource: https://api.acme.dev/mcp, scopes: [api://a/mcp, openid]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Summary()
	if want := `mcp.resource="https://api.acme.dev/mcp" mcp.scopes=["api://a/mcp" "openid"]`; s.Issuers[len(s.Issuers)-1] != want {
		t.Fatalf("mcp line = %q, want %q", s.Issuers[len(s.Issuers)-1], want)
	}
	other, err := Parse([]byte(minimalIssuer + "mcp: {resource: https://api.acme.dev/mcp, scopes: [api://b/mcp]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(s, other.Summary()); len(d.IssuersAdded) != 1 || len(d.IssuersRemoved) != 1 {
		t.Fatalf("a scope change must show in the diff: %+v", d)
	}
}

// TestParseMCPSection pins the mcp: section's checks: the resource must be
// https and name /mcp (where sandboxd serves it, and the only path whose
// RFC 9728 metadata it serves), and scopes must be RFC 6749 scope-tokens.
func TestParseMCPSection(t *testing.T) {
	cases := []struct {
		name    string
		section string
		want    string // "" means valid
	}{
		{"resource only", "mcp: {resource: https://api.acme.dev/mcp}\n", ""},
		{"resource and scopes", "mcp: {resource: https://api.acme.dev/mcp, scopes: [\"api://a/mcp\", openid]}\n", ""},
		{"empty section", "mcp: {}\n", ""},
		{"resource on another path", "mcp: {resource: https://api.acme.dev/v1/mcp}\n", "the path must be /mcp"},
		{"resource with a trailing slash", "mcp: {resource: https://api.acme.dev/mcp/}\n", "the path must be /mcp"},
		{"resource with no path", "mcp: {resource: https://api.acme.dev}\n", "the path must be /mcp"},
		{"resource over http", "mcp: {resource: http://api.acme.dev/mcp}\n", "mcp.resource"},
		{"scopes without a resource", "mcp: {scopes: [a]}\n", "needs mcp.resource"},
		{"empty scope", "mcp: {resource: https://api.acme.dev/mcp, scopes: [\"\"]}\n", "printable characters"},
		{"scope with a space", "mcp: {resource: https://api.acme.dev/mcp, scopes: [\"a b\"]}\n", "printable characters"},
		{"scope with a quote", "mcp: {resource: https://api.acme.dev/mcp, scopes: ['a\"b']}\n", "printable characters"},
		{"scope with a backslash", "mcp: {resource: https://api.acme.dev/mcp, scopes: ['a\\b']}\n", "printable characters"},
		{"scope with a non-ASCII rune", "mcp: {resource: https://api.acme.dev/mcp, scopes: [\"é\"]}\n", "printable characters"},
		{"scope too long", "mcp: {resource: https://api.acme.dev/mcp, scopes: [" + strings.Repeat("s", maxMCPScopeBytes+1) + "]}\n", "printable characters"},
		{"duplicate scope", "mcp: {resource: https://api.acme.dev/mcp, scopes: [a, a]}\n", "listed twice"},
		{"too many scopes", "mcp: {resource: https://api.acme.dev/mcp, scopes: [" + strings.TrimSuffix(strings.Repeat("s,", maxMCPScopes+1), ",") + "]}\n", "at most"},
		{"unknown key", "mcp: {resource: https://api.acme.dev/mcp, audience: x}\n", "field audience not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse([]byte(minimalIssuer + tc.section))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if strings.Contains(tc.section, "scopes") && len(c.MCPScopes) != 2 {
					t.Fatalf("scopes = %v", c.MCPScopes)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
