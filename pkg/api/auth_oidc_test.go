package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/identity/identitytest"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// oidcFile is the identity file the API-edge OIDC tests verify against.
// payments-eng and billing-eng members match two team bindings. The
// workload issuer reads its keys from a file, so no test reaches the real
// network (its URL is never contacted).
func oidcFile(t *testing.T, iss *identitytest.Issuer) string {
	t.Helper()
	jwks := filepath.Join(t.TempDir(), "ci-jwks.json")
	if err := os.WriteFile(jwks, iss.JWKS(), 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`version: 1
issuers:
  - name: okta
    display_name: Acme Okta
    url: %s
    audiences: [cli, dash]
    clients: {cli: cli, dashboard: dash}
    claims: {username: email}
  - name: ci
    url: https://token.actions.githubusercontent.com
    jwks_file: %s
    audiences: [aerolvm]
bindings:
  - {issuer: okta, group: platform-admins, role: admin}
  - {issuer: okta, group: payments-eng, role: runner, team: payments}
  - {issuer: okta, group: billing-eng, role: viewer, team: billing}
`, iss.URL, jwks)
}

type oidcEnv struct {
	iss    *identitytest.Issuer
	cfg    *identity.Config
	v      *identity.Verifier
	server *Server
}

func newOIDCEnv(t *testing.T, cfg config.Config) *oidcEnv {
	t.Helper()
	env := &oidcEnv{iss: identitytest.New(t)}
	c, err := identity.Parse([]byte(oidcFile(t, env.iss)))
	if err != nil {
		t.Fatal(err)
	}
	env.cfg = c
	env.v = identity.NewVerifier(func() *identity.Config { return env.cfg }, identity.VerifierOptions{HTTPClient: env.iss.Client()})
	cfg.IdentityEnabled = true
	var svc *service.Service
	if cfg.EnableCluster {
		svc = service.New(config.Config{EnableCluster: true}, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&apiLivePeerCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")})
	}
	env.server = NewServer(discardLogger(), svc, nil, nil, cfg, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalOIDC, env.v),
		WithAuthDiscovery(func() []identitywire.DiscoveryIssuer { return env.cfg.DiscoveryIssuers() }))
	return env
}

func (e *oidcEnv) token(t *testing.T, groups ...string) string {
	t.Helper()
	return e.iss.Mint(t, e.iss.Claims(time.Now(), "cli", "ana", groups...))
}

// do runs bearer through the v1 auth edge (cluster header guard included)
// and returns the response and the Access the handler saw.
func (e *oidcEnv) do(t *testing.T, mw func(http.Handler) http.Handler, bearer string, header http.Header) (*httptest.ResponseRecorder, capture) {
	t.Helper()
	var c capture
	edge := e.server.clusterControlHeaderGuard(mw(c.handler()))
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if req.TLS == nil && header.Get(cluster.PeerNodeIDHeader) != "" {
		req.TLS = peerTLS(header.Get(cluster.PeerNodeIDHeader))
	}
	rec := httptest.NewRecorder()
	edge.ServeHTTP(rec, req)
	return rec, c
}

// TestOIDCNoBindingBody is D9 + DR8 through the edge: a verified token
// that matches no binding gets a 403 whose v1 body carries reason, issuer,
// name and groups, all the caller's own claims, and whose message names no
// binding or group from the identity file. The facades keep their body
// shape and carry the hint in the message.
func TestOIDCNoBindingBody(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	bearer := env.token(t, "marketing", "design")

	rec, c := env.do(t, env.server.requireAuth, bearer, nil)
	if rec.Code != http.StatusForbidden || c.called {
		t.Fatalf("status %d, handler ran %v", rec.Code, c.called)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	wantMsg := "no role binding for ana@acme.com through issuer okta; the sign-in carried groups: marketing, design; ask your AerolVM admin to add a binding for one of them"
	want := models.ErrorResponse{Error: wantMsg, Reason: "no_binding", Issuer: "okta", Name: "ana@acme.com", Groups: []string{"marketing", "design"}}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body =\n %+v\nwant\n %+v", body, want)
	}
	for _, leak := range []string{"platform-admins", "payments-eng", "billing-eng", "payments", "billing"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("the 403 names %q, which is the identity file's, not the caller's: %s", leak, rec.Body.String())
		}
	}

	// Facades: their own shape, the hint in the message, no DR8 fields.
	for name, mw := range map[string]func(http.Handler) http.Handler{"e2b": env.server.requireE2BAuth, "runloop": env.server.requireRunloopAuth} {
		rec, _ := env.do(t, mw, bearer, nil)
		var raw map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		if rec.Code != http.StatusForbidden || raw["message"] != wantMsg || raw["issuer"] != nil || raw["groups"] != nil || raw["reason"] != nil {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}

	// Many groups: the message lists ten, the body carries all.
	var groups []string
	for i := 0; i < 15; i++ {
		groups = append(groups, "g"+strconv.Itoa(i))
	}
	rec, _ = env.do(t, env.server.requireAuth, env.token(t, groups...), nil)
	body = models.ErrorResponse{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Groups) != 15 || !strings.Contains(body.Error, "g9 (and 5 more)") || strings.Contains(body.Error, "g10") {
		t.Fatalf("15 groups: %+v", body)
	}

	// No groups at all.
	rec, _ = env.do(t, env.server.requireAuth, env.token(t), nil)
	body = models.ErrorResponse{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Reason != "no_binding" || body.Groups != nil || !strings.Contains(body.Error, "carried no groups") {
		t.Fatalf("no groups: %+v", body)
	}
}

// TestOIDCGroupOverageBody: an Entra overage token is refused with reason
// group_overage, the app-role hint, and no groups.
func TestOIDCGroupOverageBody(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	claims := env.iss.Claims(time.Now(), "cli", "ana")
	claims["_claim_names"] = map[string]any{"groups": "src1"}
	claims["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/x"}}
	rec, _ := env.do(t, env.server.requireAuth, env.iss.Mint(t, claims), nil)
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if rec.Code != http.StatusForbidden || raw["reason"] != "group_overage" || raw["issuer"] != "okta" || raw["name"] != "ana@acme.com" ||
		raw["groups"] != nil || !strings.Contains(raw["error"].(string), "bind on Entra app roles") {
		t.Fatalf("overage: %d %s", rec.Code, rec.Body.String())
	}
}

// TestOIDCUnavailable: a JWT this node cannot check (no good identity
// file) is a 503 with Retry-After, on every surface; the PAT still works.
func TestOIDCUnavailable(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	env.cfg = nil
	before := authCount(authFailures, "oidc", "unavailable")
	rec, _ := env.do(t, env.server.requireAuth, "eyJh.eyJz.c2ln", nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != strconv.Itoa(identityUnavailableRetryAfter) ||
		!strings.Contains(rec.Body.String(), "unavailable on this server") {
		t.Fatalf("503: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if authCount(authFailures, "oidc", "unavailable") != before+1 {
		t.Fatal("aerolvm_auth_failures_total{oidc,unavailable} did not move")
	}
	rec, _ = env.do(t, env.server.requireE2BAuth, "eyJh.eyJz.c2ln", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("e2b 503: %d", rec.Code)
	}
	rec, c := env.do(t, env.server.requireAuth, "pat-token", nil)
	if rec.Code != http.StatusNoContent || c.access.Principal.Kind != controlplane.PrincipalOperator {
		t.Fatalf("PAT with OIDC unavailable: %d", rec.Code)
	}
}

func authCount(root interface{ String() string }, key, key2 string) int64 {
	m := map[string]map[string]int64{}
	_ = json.Unmarshal([]byte(root.String()), &m)
	return m[key][key2]
}

// TestOIDCTeamSelection is §5.3/D13 over several matched bindings: no
// header takes the first; the header selects among the token's own
// bindings; a team it is not bound to is 403 with the D9 hint naming only
// its own bindings; a malformed header is 400.
func TestOIDCTeamSelection(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	bearer := env.token(t, "billing-eng", "payments-eng")
	cases := []struct {
		name     string
		team     string
		wantCode int
		wantRole controlplane.Role
		wantTeam string
		wantMsg  string
	}{
		{name: "no header: first binding", wantCode: 204, wantRole: "runner", wantTeam: "payments"},
		{name: "select the second binding", team: "billing", wantCode: 204, wantRole: "viewer", wantTeam: "billing"},
		{name: "select the first explicitly", team: "payments", wantCode: 204, wantRole: "runner", wantTeam: "payments"},
		{name: "a team it is not bound to", team: "checkout", wantCode: 403,
			wantMsg: "X-AerolVM-Team: checkout is not one of this credential's teams (it holds role runner on team payments, role viewer on team billing); ask an admin for a binding on team checkout"},
		{name: "fleet is not a team name", team: "*", wantCode: 400},
		{name: "malformed", team: "Pay_Ments", wantCode: 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.team != "" {
				h.Set(HeaderTeam, tc.team)
			}
			rec, c := env.do(t, env.server.requireAuth, bearer, h)
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode == 204 {
				if c.access.Role != tc.wantRole || c.access.Team() != tc.wantTeam || c.access.Fleet ||
					c.access.Identity.OwnerRef != controlplane.TeamOwnerRef(tc.wantTeam) || c.access.Principal.ID != "oidc:okta:ana" {
					t.Fatalf("access = %+v", c.access)
				}
				return
			}
			if tc.wantMsg != "" && !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Fatalf("body = %s, want %q", rec.Body.String(), tc.wantMsg)
			}
		})
	}

	// An admin listed first: no header acts fleet-wide; naming one of the
	// token's teams narrows to that binding (DR2: the fleet binding itself
	// is never selected by name).
	admin := env.token(t, "payments-eng", "platform-admins")
	_, c := env.do(t, env.server.requireAuth, admin, nil)
	if !c.access.Fleet || c.access.Role != controlplane.RoleAdmin {
		t.Fatalf("admin first: %+v", c.access)
	}
	_, c = env.do(t, env.server.requireAuth, admin, http.Header{HeaderTeam: {"payments"}})
	if c.access.Fleet || c.access.Role != controlplane.RoleRunner || c.access.Team() != "payments" {
		t.Fatalf("admin selecting payments: %+v", c.access)
	}
}

// TestTeamNotBoundMessageManyBindings: the D9 hint lists at most ten of the
// caller's own bindings, fleet ones as "all teams", then a count.
func TestTeamNotBoundMessageManyBindings(t *testing.T) {
	bindings := []controlplane.TeamBinding{{Role: controlplane.RoleAdmin, Team: controlplane.FleetTeam}}
	for i := 0; i < 11; i++ {
		bindings = append(bindings, controlplane.TeamBinding{Role: controlplane.RoleViewer, Team: "t" + strconv.Itoa(i)})
	}
	msg := (&teamNotBoundError{team: "x", bindings: bindings}).Error()
	if !strings.Contains(msg, "it holds role admin on all teams, role viewer on team t0") || !strings.Contains(msg, "team t8, and 2 more)") ||
		strings.Contains(msg, "team t9") || !strings.HasSuffix(msg, "ask an admin for a binding on team x") {
		t.Fatalf("message = %q", msg)
	}
}

// TestOIDCCachedTokenTwoTeams is E7: the same JWT, verified once and then
// served from the cache, resolves the team each request's header selects.
// The cache holds the binding set, never a selected team.
func TestOIDCCachedTokenTwoTeams(t *testing.T) {
	env := newOIDCEnv(t, config.Config{})
	bearer := env.token(t, "payments-eng", "billing-eng")
	seen := []string{}
	for _, team := range []string{"payments", "billing", "", "billing", "payments"} {
		h := http.Header{}
		if team != "" {
			h.Set(HeaderTeam, team)
		}
		rec, c := env.do(t, env.server.requireAuth, bearer, h)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("team %q: %d", team, rec.Code)
		}
		seen = append(seen, c.access.Team())
	}
	if want := []string{"payments", "billing", "payments", "billing", "payments"}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("teams = %v, want %v", seen, want)
	}
	if env.iss.JWKSHits.Load() != 1 {
		t.Fatalf("JWKS fetched %d times; the cache and key set must serve repeats", env.iss.JWKSHits.Load())
	}
}

// TestOIDCForwardedKeepsSelection is L2: the edge resolves the team, its
// StampForward sends that team, and the owner, re-verifying the same token
// offline, applies the same selection and records the edge as Via. With no
// header and a fleet binding first, nothing is stamped and the owner also
// lands on the first binding.
func TestOIDCForwardedKeepsSelection(t *testing.T) {
	env := newOIDCEnv(t, config.Config{EnableCluster: true})
	bearer := env.token(t, "payments-eng", "billing-eng")

	rec, edge := env.do(t, env.server.requireAuth, bearer, http.Header{HeaderTeam: {"billing"}})
	if rec.Code != http.StatusNoContent || edge.access.Team() != "billing" {
		t.Fatalf("edge: %d %+v", rec.Code, edge.access)
	}
	out := httptest.NewRequest(http.MethodGet, "http://owner/v1/sandboxes", nil)
	cluster.StampForward(out, edge.access)
	if out.Header.Get(HeaderTeam) != "billing" {
		t.Fatalf("StampForward team = %q", out.Header.Get(HeaderTeam))
	}

	fwd := http.Header{}
	fwd.Set(cluster.PeerNodeIDHeader, "peer-test")
	fwd.Set(cluster.HeaderForwarded, out.Header.Get(cluster.HeaderForwarded))
	fwd.Set(HeaderTeam, out.Header.Get(HeaderTeam))
	rec, owner := env.do(t, env.server.requireAuth, bearer, fwd)
	if rec.Code != http.StatusNoContent || owner.access.Team() != "billing" || owner.access.Role != controlplane.RoleViewer || owner.access.Via != "peer-test" {
		t.Fatalf("owner: %d %+v", rec.Code, owner.access)
	}

	admin := env.token(t, "platform-admins", "payments-eng")
	_, edge = env.do(t, env.server.requireAuth, admin, nil)
	out = httptest.NewRequest(http.MethodGet, "http://owner/v1/sandboxes", nil)
	cluster.StampForward(out, edge.access)
	if out.Header.Get(HeaderTeam) != "" {
		t.Fatalf("a fleet selection must stamp no team, got %q", out.Header.Get(HeaderTeam))
	}
	fwd.Del(HeaderTeam)
	_, owner = env.do(t, env.server.requireAuth, admin, fwd)
	if !owner.access.Fleet || owner.access.Role != controlplane.RoleAdmin {
		t.Fatalf("owner without a team header: %+v", owner.access)
	}
}

// TestAuthDiscoveryDocument is §5.6, DR3 and DR9 through the public route:
// identity off lists no issuer; identity on lists the people issuers with
// their display names; ui_url follows SB_DOMAIN and is omitted without it.
func TestAuthDiscoveryDocument(t *testing.T) {
	get := func(s *Server) (int, http.Header, identitywire.AuthDiscovery, string) {
		req := httptest.NewRequest(http.MethodGet, identitywire.AuthDiscoveryPath, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var doc identitywire.AuthDiscovery
		_ = json.Unmarshal(rec.Body.Bytes(), &doc)
		return rec.Code, rec.Header(), doc, rec.Body.String()
	}

	off := NewServer(discardLogger(), nil, nil, nil, config.Config{}, "pat-token", nil,
		WithAuthDiscovery(func() []identitywire.DiscoveryIssuer { t.Fatal("identity off must not read issuers"); return nil }))
	code, _, _, raw := get(off)
	if code != http.StatusOK || raw != `{"version":1,"identity_enabled":false,"issuers":[]}`+"\n" {
		t.Fatalf("identity off: %d %q", code, raw)
	}

	env := newOIDCEnv(t, config.Config{Domain: "api.acme.dev"})
	code, hdr, doc, _ := get(env.server)
	want := identitywire.AuthDiscovery{
		Version: 1, IdentityEnabled: true, UIURL: "https://api.acme.dev/ui",
		Issuers: []identitywire.DiscoveryIssuer{{
			Name: "okta", DisplayName: "Acme Okta", Kind: "oidc", URL: env.iss.URL,
			Clients: identitywire.DiscoveryClients{CLI: "cli", Dashboard: "dash"},
		}},
	}
	if code != http.StatusOK || !reflect.DeepEqual(doc, want) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("identity on: %d %+v", code, doc)
	}

	noDomain := newOIDCEnv(t, config.Config{})
	noDomain.cfg = nil // no good identity file yet
	_, _, _, raw = get(noDomain.server)
	if strings.Contains(raw, "ui_url") || !strings.Contains(raw, `"issuers":[]`) || !strings.Contains(raw, `"identity_enabled":true`) {
		t.Fatalf("no domain, no file: %s", raw)
	}
}
