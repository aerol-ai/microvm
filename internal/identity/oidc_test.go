package identity

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aerol-ai/microvm/internal/identity/identitytest"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// fakeClock is the verifier's clock in tests, so expiry and the refetch gap
// are exact.
type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

// testIdentityFile is the identity file the verifier tests use against an
// httptest issuer.
func testIdentityFile(url, extra string) string {
	return fmt.Sprintf(`version: 1
issuers:
  - name: test
    display_name: Test IdP
    url: %s
    audiences: [cli, dash]
    clients: {cli: cli, dashboard: dash}
    claims: {username: email}
    max_token_lifetime: 2h
bindings:
  - {issuer: test, group: admins, role: admin}
  - {issuer: test, group: payments-eng, role: runner, team: payments}
  - {issuer: test, group: billing-eng, role: viewer, team: billing}
  - {issuer: test, app_role: AerolVM.Runner, role: runner, team: checkout}
  - {issuer: test, claim: {repository: acme/payments}, role: runner, team: payments}
%s`, url, extra)
}

type verifierEnv struct {
	iss   *identitytest.Issuer
	clock *fakeClock
	cfg   atomic.Pointer[Config]
	v     *Verifier
}

func newVerifierEnv(t *testing.T, extra string) *verifierEnv {
	t.Helper()
	env := &verifierEnv{iss: identitytest.New(t), clock: newFakeClock()}
	env.load(t, testIdentityFile(env.iss.URL, extra))
	env.v = NewVerifier(env.cfg.Load, VerifierOptions{
		HTTPClient: env.iss.Client(),
		Now:        env.clock.Now,
	})
	return env
}

func (e *verifierEnv) load(t *testing.T, doc string) *Config {
	t.Helper()
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e.cfg.Store(c)
	return c
}

func (e *verifierEnv) claims(sub string, groups ...string) map[string]any {
	return e.iss.Claims(e.clock.Now(), "cli", sub, groups...)
}

func (e *verifierEnv) auth(bearer string) (controlplane.Access, bool, error) {
	return e.v.Authenticate(httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil), bearer)
}

func reasonOf(err error) controlplane.RejectReason {
	if ce, ok := controlplane.AsCredentialError(err); ok {
		return ce.Reason
	}
	return ""
}

// TestVerifierClaimChecks is the httptest-issuer table (§5.5, finding 3.5):
// algorithm, signature, issuer, audience, time and lifetime checks, each
// refused with its D17 reason.
func TestVerifierClaimChecks(t *testing.T) {
	env := newVerifierEnv(t, "deny_subjects: [\"test:blocked\"]\n")
	now := env.clock.Now()
	pub, err := x509.MarshalPKIXPublicKey(env.iss.SigningKey().Private.Public())
	if err != nil {
		t.Fatal(err)
	}
	attacker := env.iss.NewKey(t, jose.RS256)
	es := env.iss.NewKey(t, jose.ES256)
	ed := env.iss.NewKey(t, jose.EdDSA)
	env.iss.Publish(env.iss.SigningKey(), es, ed)

	with := func(mut func(c map[string]any)) map[string]any {
		c := env.claims("00u1", "payments-eng")
		mut(c)
		return c
	}
	mint := func(c map[string]any) string { return env.iss.Mint(t, c) }
	valid := mint(env.claims("00u1", "payments-eng"))
	segments := strings.Split(valid, ".")
	otherPayload, _ := json.Marshal(env.claims("00u2", "admins"))
	tampered := segments[0] + "." + base64.RawURLEncoding.EncodeToString(otherPayload) + "." + segments[2]

	cases := []struct {
		name   string
		bearer string
		want   controlplane.RejectReason // "" means accepted
	}{
		{"valid RS256", valid, ""},
		{"valid ES256", env.iss.MintWith(t, env.claims("00u1", "payments-eng"), identitytest.MintOptions{Key: &es}), ""},
		{"valid EdDSA", env.iss.MintWith(t, env.claims("00u1", "payments-eng"), identitytest.MintOptions{Key: &ed}), ""},
		{"no kid, a published key verifies", env.iss.MintWith(t, env.claims("00u1", "payments-eng"), identitytest.MintOptions{NoKeyID: true}), ""},
		{"alg none", identitytest.Unsigned(map[string]any{"alg": "none", "typ": "JWT"}, env.claims("00u1", "admins")), controlplane.RejectInvalidSignature},
		{"HS256 keyed with the public key", identitytest.MintHMAC(t, env.claims("00u1", "admins"), pub, env.iss.SigningKey().ID), controlplane.RejectInvalidSignature},
		{"tampered payload under a known kid", tampered, controlplane.RejectInvalidSignature},
		{"signed by a key the issuer never published", env.iss.MintWith(t, env.claims("00u1", "admins"), identitytest.MintOptions{Key: &attacker}), controlplane.RejectInvalidSignature},
		{"wrong audience", mint(with(func(c map[string]any) { c["aud"] = "someone-else" })), controlplane.RejectWrongAudience},
		{"audience list with one of ours", mint(with(func(c map[string]any) { c["aud"] = []string{"x", "dash"} })), ""},
		{"empty audience list", mint(with(func(c map[string]any) { c["aud"] = []string{} })), controlplane.RejectWrongAudience},
		{"unknown issuer", mint(with(func(c map[string]any) { c["iss"] = "https://evil.example" })), controlplane.RejectUnknownIssuer},
		{"issuer must match exactly", mint(with(func(c map[string]any) { c["iss"] = env.iss.URL + "/" })), controlplane.RejectUnknownIssuer},
		{"expired past the leeway", mint(with(func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-time.Hour).Unix(), now.Add(-2*time.Minute).Unix()
		})), controlplane.RejectExpired},
		{"expired inside the 60 s leeway", mint(with(func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-time.Hour).Unix(), now.Add(-30*time.Second).Unix()
		})), ""},
		{"nbf in the future", mint(with(func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() })), controlplane.RejectNotYetValid},
		{"nbf inside the leeway", mint(with(func(c map[string]any) { c["nbf"] = now.Add(30 * time.Second).Unix() })), ""},
		{"issued in the future", mint(with(func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(5*time.Minute).Unix(), now.Add(time.Hour).Unix()
		})), controlplane.RejectNotYetValid},
		{"lifetime over the issuer cap", mint(with(func(c map[string]any) { c["exp"] = now.Add(3 * time.Hour).Unix() })), controlplane.RejectTooLongLived},
		{"no iat: lifetime counted from now", mint(with(func(c map[string]any) {
			delete(c, "iat")
			c["exp"] = now.Add(3 * time.Hour).Unix()
		})), controlplane.RejectTooLongLived},
		{"no sub", mint(with(func(c map[string]any) { delete(c, "sub") })), controlplane.RejectMalformed},
		{"sub with a control character", mint(with(func(c map[string]any) { c["sub"] = "00u\n1" })), controlplane.RejectMalformed},
		{"sub over 255 bytes", mint(with(func(c map[string]any) { c["sub"] = strings.Repeat("s", 256) })), controlplane.RejectMalformed},
		{"exp is a string", mint(with(func(c map[string]any) { c["exp"] = "tomorrow" })), controlplane.RejectMalformed},
		{"no exp", mint(with(func(c map[string]any) { delete(c, "exp") })), controlplane.RejectMalformed},
		{"no aud", mint(with(func(c map[string]any) { delete(c, "aud") })), controlplane.RejectMalformed},
		{"header is not JSON", "YWJj.YWJj.YWJj", controlplane.RejectMalformed},
		{"payload is not JSON", segments[0] + ".YWJj." + segments[2], controlplane.RejectMalformed},
		{"over the 16 KB cap", mint(with(func(c map[string]any) { c["pad"] = strings.Repeat("a", MaxJWTBytes) })), controlplane.RejectMalformed},
		{"denied subject (emergency block)", mint(with(func(c map[string]any) { c["sub"] = "blocked" })), controlplane.RejectUnknownOrRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched, err := env.auth(tc.bearer)
			if !matched {
				t.Fatal("a JWT-shaped bearer must be decided by the verifier")
			}
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v, want accepted", err)
				}
				return
			}
			if got := reasonOf(err); got != tc.want {
				t.Fatalf("err = %v (reason %q), want %q", err, got, tc.want)
			}
		})
	}
}

func TestVerifierAccessAndFirstMatchBindings(t *testing.T) {
	env := newVerifierEnv(t, "")
	// Each matched binding carries its 1-based place in the file and its
	// canonical line, for whoami --explain (D22).
	payments := controlplane.TeamBinding{Role: "runner", Team: "payments", Index: 2, Rule: `test group="payments-eng" -> runner/payments`}
	cases := []struct {
		name   string
		groups []string
		roles  []string
		claims map[string]any
		want   []controlplane.TeamBinding
	}{
		{name: "one team", groups: []string{"payments-eng"}, want: []controlplane.TeamBinding{payments}},
		{name: "file order, not claim order", groups: []string{"billing-eng", "payments-eng"},
			want: []controlplane.TeamBinding{payments, {Role: "viewer", Team: "billing", Index: 3, Rule: `test group="billing-eng" -> viewer/billing`}}},
		{name: "fleet binding listed first wins", groups: []string{"payments-eng", "admins"},
			want: []controlplane.TeamBinding{{Role: "admin", Team: "*", Index: 1, Rule: `test group="admins" -> admin/*`}, payments}},
		{name: "app role", roles: []string{"AerolVM.Runner"},
			want: []controlplane.TeamBinding{{Role: "runner", Team: "checkout", Index: 4, Rule: `test app_role="AerolVM.Runner" -> runner/checkout`}}},
		// The later claim binding grants the same role and team: the first
		// binding is the one kept, and the one whoami --explain names.
		{name: "claim binding, deduplicated with a group binding", groups: []string{"payments-eng"}, claims: map[string]any{"repository": "acme/payments"},
			want: []controlplane.TeamBinding{payments}},
		{name: "claim binding alone", claims: map[string]any{"repository": "acme/payments"},
			want: []controlplane.TeamBinding{{Role: "runner", Team: "payments", Index: 5, Rule: `test claim:repository="acme/payments" -> runner/payments`}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := env.claims("00u1", tc.groups...)
			if tc.roles != nil {
				c["roles"] = tc.roles
			}
			for k, v := range tc.claims {
				c[k] = v
			}
			a, _, err := env.auth(env.iss.Mint(t, c))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a.Bindings, tc.want) {
				t.Fatalf("bindings = %+v, want %+v", a.Bindings, tc.want)
			}
			first := tc.want[0]
			if a.Role != first.Role || a.Team() != first.Team || a.Fleet != (first.Team == "*") {
				t.Fatalf("access is scoped to %s/%s (fleet %v), want the first binding %+v", a.Role, a.Team(), a.Fleet, first)
			}
			if a.Principal != (controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:test:00u1", Name: "00u1@acme.com"}) {
				t.Fatalf("principal = %+v", a.Principal)
			}
			if a.ClaimNames == nil || *a.ClaimNames != (controlplane.ClaimNames{Issuer: "test", Username: "email", Groups: "groups", Roles: "roles"}) {
				t.Fatalf("claim names = %+v", a.ClaimNames)
			}
			if !a.ExpiresAt.Equal(time.Unix(c["exp"].(int64), 0)) {
				t.Fatalf("expires = %v", a.ExpiresAt)
			}
		})
	}
}

// TestVerifierNoBinding is D9/DR8: a verified token that matches nothing
// is refused with the caller's own claims, and an Entra overage token is
// refused as group_overage with no groups.
func TestVerifierNoBinding(t *testing.T) {
	env := newVerifierEnv(t, "")
	_, _, err := env.auth(env.iss.Mint(t, env.claims("00u7", "marketing", "\x1bred")))
	nb, ok := controlplane.AsNoBindingError(err)
	if !ok {
		t.Fatalf("err = %v, want NoBindingError", err)
	}
	if nb.Issuer != "test" || nb.Name != "00u7@acme.com" || nb.Principal.ID != "oidc:test:00u7" || nb.Principal.Kind != controlplane.PrincipalOIDC || !reflect.DeepEqual(nb.Groups, []string{"marketing", "red"}) || nb.Overage || nb.Reason() != "no_binding" {
		t.Fatalf("no binding = %+v", nb)
	}

	overage := env.claims("00u8")
	overage["_claim_names"] = map[string]any{"groups": "src1"}
	overage["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}
	_, _, err = env.auth(env.iss.Mint(t, overage))
	nb, ok = controlplane.AsNoBindingError(err)
	if !ok || !nb.Overage || nb.Groups != nil || nb.Reason() != "group_overage" {
		t.Fatalf("overage = %+v (%v)", nb, err)
	}

	// The same overage token with an Entra app role is bound: app roles are
	// always sent, which is why the hint says to bind on them.
	overage["roles"] = []string{"AerolVM.Runner"}
	a, _, err := env.auth(env.iss.Mint(t, overage))
	if err != nil || a.Team() != "checkout" {
		t.Fatalf("overage with an app role: %+v, %v", a, err)
	}

	hasGroups := env.claims("00u9")
	hasGroups["hasgroups"] = true
	if _, _, err := env.auth(env.iss.Mint(t, hasGroups)); err == nil {
		t.Fatal("hasgroups overage must be refused")
	} else if nb, ok := controlplane.AsNoBindingError(err); !ok || !nb.Overage {
		t.Fatalf("hasgroups = %v", err)
	}
}

// TestVerifierKidRotation: a token signed by a newly rotated key triggers
// exactly one JWKS refetch; another unknown kid within the minute does not
// refetch; after the gap it may again.
func TestVerifierKidRotation(t *testing.T) {
	env := newVerifierEnv(t, "")
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); err != nil {
		t.Fatal(err)
	}
	if got := env.iss.JWKSHits.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times at first use, want 1", got)
	}
	env.clock.Advance(2 * time.Minute)
	env.iss.Rotate(t, jose.RS256)
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if got := env.iss.JWKSHits.Load(); got != 2 {
		t.Fatalf("JWKS hits after rotation = %d, want 2 (one refetch)", got)
	}
	env.clock.Advance(10 * time.Second)
	newer := env.iss.Rotate(t, jose.RS256)
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); reasonOf(err) != controlplane.RejectInvalidSignature {
		t.Fatalf("second rotation inside the gap: %v, want invalid_signature", err)
	}
	if got := env.iss.JWKSHits.Load(); got != 2 {
		t.Fatalf("refetched inside the one-minute gap: %d hits", got)
	}
	env.clock.Advance(time.Minute)
	if _, _, err := env.auth(env.iss.MintWith(t, env.claims("00u2", "payments-eng"), identitytest.MintOptions{Key: &newer})); err != nil {
		t.Fatalf("after the gap: %v", err)
	}
	if got := env.iss.JWKSHits.Load(); got != 3 {
		t.Fatalf("JWKS hits after the gap = %d, want 3", got)
	}
}

// TestVerifierKeyWithdrawal: once the issuer withdraws a key, a token the
// cache verified with it is checked again and refused.
func TestVerifierKeyWithdrawal(t *testing.T) {
	env := newVerifierEnv(t, "")
	old := env.iss.SigningKey()
	cached := env.iss.Mint(t, env.claims("00u1", "payments-eng"))
	if _, _, err := env.auth(cached); err != nil {
		t.Fatal(err)
	}
	fresh := env.iss.Rotate(t, jose.RS256)
	env.iss.Publish(fresh) // old withdrawn
	env.clock.Advance(2 * time.Minute)
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u2", "payments-eng"))); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if _, _, err := env.auth(cached); reasonOf(err) != controlplane.RejectInvalidSignature {
		t.Fatalf("token signed by withdrawn key %s: %v", old.ID, err)
	}
}

// TestVerifierHeadersIgnored is finding 3.5: jku, x5u and an embedded jwk
// are never used. A token the issuer signed verifies whatever those
// headers say, and a token an attacker signed is refused even when the
// headers point at the attacker's own key; the attacker's server is never
// contacted.
func TestVerifierHeadersIgnored(t *testing.T) {
	env := newVerifierEnv(t, "")
	attacker := env.iss.NewKey(t, jose.RS256)
	var attackerHits atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHits.Add(1)
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{attacker.Public()}}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(evil.Close)
	attackerJWK := attacker.Public()
	headers := map[jose.HeaderKey]any{"jku": evil.URL + "/jwks", "x5u": evil.URL + "/cert", "jwk": attackerJWK}

	signedByIssuer := env.iss.MintWith(t, env.claims("00u1", "payments-eng"), identitytest.MintOptions{Headers: headers})
	if _, _, err := env.auth(signedByIssuer); err != nil {
		t.Fatalf("issuer-signed token with hostile headers: %v", err)
	}
	env.clock.Advance(2 * time.Minute)
	signedByAttacker := env.iss.MintWith(t, env.claims("00u1", "admins"), identitytest.MintOptions{Key: &attacker, Headers: headers})
	if _, _, err := env.auth(signedByAttacker); reasonOf(err) != controlplane.RejectInvalidSignature {
		t.Fatalf("attacker-signed token: %v, want invalid_signature", err)
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("the attacker's key server was contacted %d times", attackerHits.Load())
	}
}

// TestVerifierAlgorithmsAdvertised: allowed algorithms are the issuer's
// advertised set intersected with ours, so a published ES256 key does not
// verify for an issuer that advertises only RS256.
func TestVerifierAlgorithmsAdvertised(t *testing.T) {
	env := newVerifierEnv(t, "")
	env.iss.SetAlgs("RS256", "HS256", "none")
	es := env.iss.NewKey(t, jose.ES256)
	env.iss.Publish(env.iss.SigningKey(), es)
	if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.auth(env.iss.MintWith(t, env.claims("00u1", "payments-eng"), identitytest.MintOptions{Key: &es})); reasonOf(err) != controlplane.RejectInvalidSignature {
		t.Fatalf("ES256 from an RS256-only issuer: %v", err)
	}
}

// TestVerifierProviderUnavailable: an unreachable provider at first use is
// a 503 (ErrIdentityUnavailable), retried at most once a minute, and the
// tokens work once a fetch succeeds.
func TestVerifierProviderUnavailable(t *testing.T) {
	env := newVerifierEnv(t, "")
	env.iss.FailDiscovery.Store(true)
	token := env.iss.Mint(t, env.claims("00u1", "payments-eng"))
	if _, _, err := env.auth(token); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("provider down: %v, want ErrIdentityUnavailable", err)
	}
	hits := env.iss.DiscoveryHits.Load()
	if _, _, err := env.auth(token); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("still down: %v", err)
	}
	if env.iss.DiscoveryHits.Load() != hits {
		t.Fatal("a second request inside the refetch gap must not call the provider")
	}
	env.iss.FailDiscovery.Store(false)
	env.clock.Advance(61 * time.Second)
	if _, _, err := env.auth(token); err != nil {
		t.Fatalf("provider back: %v", err)
	}
}

func TestVerifierUnavailableWithoutFile(t *testing.T) {
	v := NewVerifier(func() *Config { return nil }, VerifierOptions{})
	_, matched, err := v.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil), "a.b.c")
	if !matched || !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("no good identity file: matched %v err %v", matched, err)
	}
	v.Bootstrap(context.Background())
	v.maintainKeys(context.Background())
}

func TestVerifierNotAJWT(t *testing.T) {
	env := newVerifierEnv(t, "")
	for _, bearer := range []string{"", "pat-token", "avm_7Hq2aBcDeFgH_secret_abc123", "a.b", "a.b.c.d", ".b.c", "a..c", "a.b!.c", "a b.c.d"} {
		if _, matched, err := env.auth(bearer); matched || err != nil {
			t.Errorf("%q: matched %v err %v, want not mine", bearer, matched, err)
		}
	}
	if !looksLikeJWT("eyJh.eyJz.") {
		t.Error("an alg:none shape (empty signature) is claimed, so it is refused rather than passed on")
	}
}

func TestVerifierIssuerMismatchAndOversizeDocs(t *testing.T) {
	t.Run("discovery names another issuer", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		env.iss.SetDiscoveredIssuer("https://impostor.example")
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("issuer mismatch: %v", err)
		}
	})
	t.Run("JWKS over 1 MiB", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		before := jwksResult("test", fetchTooLarge)
		env.iss.SetJWKSBody([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`))
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("oversize JWKS: %v", err)
		}
		if jwksResult("test", fetchTooLarge) != before+1 {
			t.Fatal("an oversize JWKS must count result=too_large")
		}
	})
	t.Run("discovery over 1 MiB", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		before := oversizeCount(oversizeDiscovery)
		env.iss.SetDiscoveryBody([]byte(`{"issuer":"x","pad":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`))
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("oversize discovery: %v", err)
		}
		if oversizeCount(oversizeDiscovery) != before+1 {
			t.Fatal("an oversize discovery document must count the oversize metric")
		}
	})
	t.Run("JWKS with no usable key", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		env.iss.SetJWKSBody([]byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"h"},{"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"}]}`))
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("no usable key: %v", err)
		}
	})
	t.Run("JWKS endpoint down", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		env.iss.FailJWKS.Store(true)
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("JWKS down: %v", err)
		}
	})
	t.Run("issuer advertises no allowed algorithm", func(t *testing.T) {
		env := newVerifierEnv(t, "")
		env.iss.SetAlgs("HS256")
		if _, _, err := env.auth(env.iss.Mint(t, env.claims("00u1", "payments-eng"))); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("HS256-only issuer: %v", err)
		}
	})
}

func jwksResult(issuer, result string) int64 {
	m := map[string]map[string]int64{}
	_ = json.Unmarshal([]byte(jwksFetchTotal.String()), &m)
	return m[issuer][result]
}

func oversizeCount(input string) int64 {
	m := map[string]int64{}
	_ = json.Unmarshal([]byte(oversizeTotal.String()), &m)
	return m[input]
}

// TestVerifierJWKSFile: an issuer the node cannot reach publishes a static
// JWKS file; tokens verify with no network at all.
func TestVerifierJWKSFile(t *testing.T) {
	iss := identitytest.New(t)
	keys := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(keys, iss.JWKS(), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	cfg, err := Parse([]byte(fmt.Sprintf("version: 1\nissuers:\n  - {name: eks, url: %q, jwks_file: %q, audiences: [aerolvm]}\nbindings:\n  - {issuer: eks, claim: {sub: \"system:serviceaccount:payments:ci\"}, role: runner, team: payments}\n", iss.URL, keys)))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(func() *Config { return cfg }, VerifierOptions{Now: clock.Now, HTTPClient: &http.Client{Transport: failingTransport{}}})
	claims := iss.Claims(clock.Now(), "aerolvm", "system:serviceaccount:payments:ci")
	a, _, err := v.Authenticate(nil, iss.Mint(t, claims))
	if err != nil || a.Team() != "payments" || a.Principal.ID != "oidc:eks:system:serviceaccount:payments:ci" || a.Principal.Name != "system:serviceaccount:payments:ci" {
		t.Fatalf("jwks_file issuer: %+v, %v", a, err)
	}
	if iss.DiscoveryHits.Load() != 0 || iss.JWKSHits.Load() != 0 {
		t.Fatal("a jwks_file issuer must never be fetched")
	}

	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(`{"keys":[],"pad":"`+strings.Repeat("a", MaxDocumentBytes)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bigCfg, _ := Parse([]byte(fmt.Sprintf("version: 1\nissuers:\n  - {name: eks, url: %q, jwks_file: %q, audiences: [aerolvm]}\n", iss.URL, big)))
	v2 := NewVerifier(func() *Config { return bigCfg }, VerifierOptions{Now: clock.Now})
	if _, _, err := v2.Authenticate(nil, iss.Mint(t, claims)); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("oversize jwks_file: %v", err)
	}
	missingCfg, _ := Parse([]byte(fmt.Sprintf("version: 1\nissuers:\n  - {name: eks, url: %q, jwks_file: /nonexistent/jwks.json, audiences: [aerolvm]}\n", iss.URL)))
	v3 := NewVerifier(func() *Config { return missingCfg }, VerifierOptions{Now: clock.Now})
	if _, _, err := v3.Authenticate(nil, iss.Mint(t, claims)); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("missing jwks_file: %v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

// TestVerifierCacheAndReload: a repeat token is served from the cache
// without touching the keys; a reload builds a new cache with the new
// bindings but keeps the fetched keys; an expired cached token is refused.
func TestVerifierCacheAndReload(t *testing.T) {
	env := newVerifierEnv(t, "")
	token := env.iss.Mint(t, env.claims("00u1", "payments-eng"))
	if _, _, err := env.auth(token); err != nil {
		t.Fatal(err)
	}
	st, _ := env.v.current()
	if st.cache.len() != 1 {
		t.Fatalf("cache entries = %d", st.cache.len())
	}
	// Prove the hit skips verification: withdraw every key locally (same
	// generation, so the entry is not stale) and verify again.
	for _, iv := range st.issuers {
		iv.keys.snap.Store(&keySnapshot{algs: map[string]bool{"RS256": true}})
	}
	if _, _, err := env.auth(token); err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	for _, iv := range st.issuers {
		iv.keys.snap.Store(nil)
		iv.keys.ready.Store(false)
	}
	env.clock.Advance(2 * time.Minute)

	// Reload with payments-eng now a viewer: same token, new answer, and
	// no new key fetch beyond what the cleared snapshot needs.
	env.load(t, strings.Replace(testIdentityFile(env.iss.URL, ""), "group: payments-eng, role: runner", "group: payments-eng, role: viewer", 1))
	hits := env.iss.JWKSHits.Load()
	a, _, err := env.auth(token)
	if err != nil || a.Role != controlplane.RoleViewer {
		t.Fatalf("after reload: %+v, %v", a, err)
	}
	if env.iss.JWKSHits.Load() > hits+1 {
		t.Fatal("a reload must reuse the issuer's key set")
	}

	env.clock.Advance(2 * time.Hour)
	if _, _, err := env.auth(token); reasonOf(err) != controlplane.RejectExpired {
		t.Fatalf("expired cached token: %v", err)
	}
	st2, _ := env.v.current()
	if st2.cache.len() != 0 {
		t.Fatal("an expired entry must leave the cache")
	}
}

// TestVerifierReloadAddsDeny: an emergency deny entry applies on the first
// request after the reload, even to a token the old cache held.
func TestVerifierReloadAddsDeny(t *testing.T) {
	env := newVerifierEnv(t, "")
	token := env.iss.Mint(t, env.claims("00u1", "payments-eng"))
	if _, _, err := env.auth(token); err != nil {
		t.Fatal(err)
	}
	env.load(t, testIdentityFile(env.iss.URL, "deny_subjects: [\"test:00u1\"]\n"))
	if _, _, err := env.auth(token); reasonOf(err) != controlplane.RejectUnknownOrRevoked {
		t.Fatalf("denied after reload: %v", err)
	}
}

// TestVerifierBootstrapAndMaintain: Bootstrap fetches every issuer's keys
// at start (the latch), Run's maintenance retries an issuer without keys
// and refreshes one whose keys are older than the refresh interval.
func TestVerifierBootstrapAndMaintain(t *testing.T) {
	env := newVerifierEnv(t, "")
	env.v.Bootstrap(context.Background())
	if env.iss.JWKSHits.Load() != 1 {
		t.Fatalf("bootstrap JWKS hits = %d", env.iss.JWKSHits.Load())
	}
	st, _ := env.v.current()
	var ks *keySet
	for _, iv := range st.issuers {
		ks = iv.keys
	}
	if !ks.ready.Load() {
		t.Fatal("bootstrap must latch the key set")
	}
	env.v.Bootstrap(context.Background()) // ready: nothing to do
	env.clock.Advance(30 * time.Minute)
	env.v.maintainKeys(context.Background())
	if env.iss.JWKSHits.Load() != 1 {
		t.Fatal("fresh keys must not be refetched")
	}
	env.clock.Advance(31 * time.Minute)
	env.v.maintainKeys(context.Background())
	waitFor(t, "the hourly refresh", func() bool { return env.iss.JWKSHits.Load() == 2 })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { env.v.Run(ctx, time.Millisecond); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
}

func TestVerifierBootstrapLogsFailure(t *testing.T) {
	env := newVerifierEnv(t, "")
	env.iss.FailDiscovery.Store(true)
	env.v.Bootstrap(context.Background())
	st, _ := env.v.current()
	for _, iv := range st.issuers {
		if iv.keys.ready.Load() {
			t.Fatal("a failed bootstrap must leave the latch unset")
		}
	}
}

// TestKeyWaitTimeout: a request waits at most KeyWait for a fetch it
// started, then gets 503 while the fetch finishes for the next one.
func TestKeyWaitTimeout(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		http.Error(w, "late", http.StatusServiceUnavailable)
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	cfg, err := Parse([]byte(fmt.Sprintf("version: 1\nissuers:\n  - {name: slow, url: %q, audiences: [a]}\n", slow.URL)))
	if err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	v := NewVerifier(func() *Config { return cfg }, VerifierOptions{HTTPClient: slow.Client(), Now: clock.Now, KeyWait: 20 * time.Millisecond})
	iss := identitytest.New(t)
	claims := iss.Claims(clock.Now(), "a", "u")
	claims["iss"] = slow.URL
	start := time.Now()
	if _, _, err := v.Authenticate(nil, iss.Mint(t, claims)); !errors.Is(err, controlplane.ErrIdentityUnavailable) {
		t.Fatalf("slow provider: %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %v, want about KeyWait", waited)
	}
}

func TestParseClaims(t *testing.T) {
	ok := `{"iss":"i","sub":"s","aud":["a"],"exp":1800000000.5,"nbf":1,"iat":2}`
	c, err := parseClaims([]byte(ok))
	if err != nil || c.iss != "i" || c.sub != "s" || !reflect.DeepEqual(c.aud, []string{"a"}) || c.exp.Unix() != 1800000000 || c.nbf.Unix() != 1 || c.iat.Unix() != 2 {
		t.Fatalf("parseClaims = %+v, %v", c, err)
	}
	for _, bad := range []string{
		`null`, `[]`, `{"iss":1,"sub":"s","aud":"a","exp":1}`, `{"iss":"i","sub":2,"aud":"a","exp":1}`,
		`{"iss":"i","sub":"s","aud":3,"exp":1}`, `{"iss":"i","sub":"s","aud":"a","exp":-1}`,
		`{"iss":"i","sub":"s","aud":"a","exp":1,"nbf":"x"}`, `{"iss":"i","sub":"s","aud":"a","exp":1e300}`,
	} {
		if _, err := parseClaims([]byte(bad)); err == nil {
			t.Errorf("parseClaims(%s) accepted", bad)
		}
	}
}

// FuzzJWTHeader (D21): whatever bearer arrives, the verifier never panics;
// a bearer that is not JWT-shaped is never claimed, and a claimed one is
// always decided with a known refusal (random bytes never verify).
func FuzzJWTHeader(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJpc3MiOiJ4In0.c2ln")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
	f.Add("e30.e30.e30")
	f.Add("a.b.c")
	f.Add("not a jwt")
	f.Add(strings.Repeat("a", MaxJWTBytes) + ".b.c")
	cfg, err := Parse([]byte(testIdentityFile("https://idp.invalid", "")))
	if err != nil {
		f.Fatal(err)
	}
	v := NewVerifier(func() *Config { return cfg }, VerifierOptions{
		HTTPClient: &http.Client{Transport: failingTransport{}},
		RefetchGap: time.Hour,
		KeyWait:    time.Millisecond,
	})
	f.Fuzz(func(t *testing.T, bearer string) {
		a, matched, err := v.Authenticate(nil, bearer)
		if !matched {
			if err != nil || looksLikeJWT(bearer) {
				t.Fatalf("not claimed but err %v / JWT-shaped %v", err, looksLikeJWT(bearer))
			}
			return
		}
		if err == nil {
			t.Fatalf("a random bearer authenticated: %+v", a)
		}
		_, isCred := controlplane.AsCredentialError(err)
		_, isNB := controlplane.AsNoBindingError(err)
		if !isCred && !isNB && !errors.Is(err, controlplane.ErrIdentityUnavailable) {
			t.Fatalf("unclassified refusal: %v", err)
		}
	})
}
