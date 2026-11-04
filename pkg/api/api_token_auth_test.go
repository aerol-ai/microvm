package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The real apiToken authenticator (T3) through the whole server: the D17
// reasons, whoami for a token principal, and the stale-mirror rule (D16)
// on every surface.

// switchableTokens is a token index whose freshness a test flips, the way
// a worker's mirror goes stale when the server tier is unreachable.
type switchableTokens struct {
	identity.TokenSet
	stale atomic.Bool
}

func (s *switchableTokens) LookupToken(id string) (identity.TokenRecord, bool, bool) {
	rec, found, _ := s.TokenSet.LookupToken(id)
	return rec, found, !s.stale.Load()
}

func mintToken(t testing.TB, set *switchableTokens, name, team string, role controlplane.Role, expires time.Time) string {
	t.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := tok.SecretHash()
	set.Put(identity.TokenRecord{ID: tok.ID, Name: name, Role: role, OwnerRef: identity.OwnerRefForTeam(team),
		CreatedAt: time.Now(), ExpiresAt: expires, SecretHash: hash[:]})
	return tok.Plaintext()
}

func tokenServer(set identity.TokenLookup, identityOn bool) *Server {
	return NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: identityOn, MCPEnabled: true}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, identity.NewTokenAuthenticator(set, discardLogger())))
}

func TestAPITokenAuthenticatorThroughTheServer(t *testing.T) {
	set := &switchableTokens{}
	runner := mintToken(t, set, "ci-deploy", "payments", controlplane.RoleRunner, time.Now().Add(time.Hour))
	expired := mintToken(t, set, "old", "payments", controlplane.RoleRunner, time.Now().Add(-time.Hour))
	unknown, _ := identitywire.NewAPIToken(nil)
	h := tokenServer(set, true).Handler()

	rec := serve(h, http.MethodGet, "/v1/whoami", runner, nil)
	var who models.WhoAmI
	_ = json.Unmarshal(rec.Body.Bytes(), &who)
	if rec.Code != http.StatusOK || who.Principal.Kind != "token" || !strings.HasPrefix(who.Principal.ID, "tok_") ||
		who.Principal.Name != "ci-deploy" || who.Role != "runner" || who.Team != "payments" || who.ExpiresAt == nil {
		t.Fatalf("whoami as a token: %d %s", rec.Code, rec.Body.String())
	}
	for _, tc := range []struct {
		bearer string
		reason string
	}{
		{"avm_garbage", "malformed"},
		{unknown.Plaintext(), "unknown_or_revoked"},
		{expired, "expired"},
	} {
		rec := serve(h, http.MethodGet, "/v1/whoami", tc.bearer, nil)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error_description="`+tc.reason+`"`) ||
			!strings.Contains(rec.Body.String(), `"reason":"`+tc.reason+`"`) {
			t.Fatalf("%s: %d %q %s", tc.reason, rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
		}
	}

	// Identity off: the authenticator is not in the chain, so the same
	// token is an unrecognised bearer with today's bare 401 (L8).
	off := tokenServer(set, false).Handler()
	if rec := serve(off, http.MethodGet, "/v1/whoami", runner, nil); rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthorized"}`+"\n" || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("identity off: %d %q", rec.Code, rec.Body.String())
	}
}

// TestStaleTokenMirrorRefusesAllButMetrics is the D16 test through the
// whole server: with the mirror stale, a token is refused with 503 and
// Retry-After on sandbox.read (and every other permission, on every
// surface), but a fleet viewer's scrape of /v1/metrics is still served.
// The PAT never depends on the mirror.
func TestStaleTokenMirrorRefusesAllButMetrics(t *testing.T) {
	set := &switchableTokens{}
	scrape := mintToken(t, set, "prom", controlplane.FleetTeam, controlplane.RoleViewer, time.Now().Add(time.Hour))
	h := tokenServer(set, true).Handler()
	if rec := serve(h, http.MethodGet, "/v1/metrics", scrape, nil); rec.Code != http.StatusOK {
		t.Fatalf("fresh scrape: %d", rec.Code)
	}
	set.stale.Store(true)
	before := authFailures.String()
	for _, path := range []string{"/v1/sandboxes", "/v1/whoami", "/debug/vars", "/v1/tokens", "/e2b/sandboxes", "/runloop/v1/devboxes", "/daytona/sandbox"} {
		rec := serve(h, http.MethodGet, path, scrape, nil)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" || !strings.Contains(rec.Body.String(), "identity data is stale") {
			t.Fatalf("%s from a stale mirror: %d %q %s", path, rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
		}
	}
	if authFailures.String() == before || !strings.Contains(authFailures.String(), `"stale"`) {
		t.Fatalf("stale refusals are counted: %s", authFailures.String())
	}
	if rec := serve(h, http.MethodGet, "/v1/metrics", scrape, nil); rec.Code != http.StatusOK {
		t.Fatalf("a stale mirror still serves metrics.read (D16): %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(h, http.MethodGet, "/v1/whoami", "pat-token", nil); rec.Code != http.StatusOK {
		t.Fatalf("the PAT never needs the mirror: %d", rec.Code)
	}
}

// TestRouteStampsPermissionBeforeAuthentication: the token authenticator
// learns the route's permission at authentication time, per request for a
// RouteBy route.
func TestRouteStampsPermissionBeforeAuthentication(t *testing.T) {
	var seen []controlplane.Permission
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := controlplane.RoutePermissionFromContext(r.Context())
			seen = append(seen, p)
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
		})
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	router := apihttp.Router{Authenticate: auth}
	route := router.RouteBy("read|secrets", func(r *http.Request) controlplane.Permission {
		if r.URL.Query().Get("include_env") != "" {
			return controlplane.PermSandboxSecrets
		}
		return controlplane.PermSandboxRead
	}, ok)
	for _, target := range []string{"/x", "/x?include_env=1"} {
		rec := httptest.NewRecorder()
		route.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", target, rec.Code)
		}
	}
	if len(seen) != 2 || seen[0] != controlplane.PermSandboxRead || seen[1] != controlplane.PermSandboxSecrets {
		t.Fatalf("permissions seen at authentication: %v", seen)
	}
}
