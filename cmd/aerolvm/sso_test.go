package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// The fake identity provider and fake sandboxd below are plain httptest
// servers on loopback. cmd/aerolvm may not import internal/identity (its
// server-side test issuer pulls go-jose and verifies signatures, which the
// CLI never does), so the CLI's tests carry their own: it only has to mint
// tokens whose claims the CLI reads, and speak the OAuth endpoints the CLI
// calls.

var updateGolden = flag.Bool("update", false, "rewrite the testdata/identity golden files")

// checkGolden compares got with testdata/identity/<name>. The golden files
// are the design review's DR15 wording, written by hand from the plan's
// table: a change to them is a change to the CLI's words.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "identity", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if string(want) != got {
		t.Fatalf("%s changed; review and run with -update:\n--- got\n%s--- want\n%s", name, got, want)
	}
}

// testClock is the one clock the CLI, the fake issuer and the fake sandboxd
// read, so expiry and renewal are decided by the test.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// fakeClaims are the claims of one ID token the fake issuer minted.
type fakeClaims struct {
	Sub    string
	Email  string
	Groups []string
	Exp    time.Time
}

// fakeIssuer is an OIDC provider in miniature: discovery, an authorize
// endpoint that signs the person in at once, a PKCE-checked code exchange,
// refresh with rotation, and the device flow.
type fakeIssuer struct {
	srv      *httptest.Server
	URL      string
	clock    *testClock
	clientID string

	mu sync.Mutex
	// secret is a required client secret ("" for a public client).
	secret   string
	lifetime time.Duration
	sub      string
	email    string
	groups   []string
	// deny is an error code /authorize redirects back with.
	deny          string
	failRefresh   bool
	noIDToken     bool
	junkIDToken   bool
	wrongNonce    bool
	devicePending int
	deviceDeny    bool
	noDevice      bool
	scopes        []string
	codes         map[string]fakeCode
	refresh       map[string]bool
	idTokens      map[string]fakeClaims
	lastAuth      url.Values
	grants        map[string]int
	n             int
}

type fakeCode struct {
	challenge, redirect, nonce string
}

func newFakeIssuer(t *testing.T, clock *testClock) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{
		clock: clock, clientID: "0oa1cli", lifetime: time.Hour,
		sub: "00u1alice", email: "alice@acme.com", groups: []string{"everyone", "payments-eng"},
		scopes: []string{"openid", "email", "profile", "offline_access", "groups"},
		codes:  map[string]fakeCode{}, refresh: map[string]bool{}, idTokens: map[string]fakeClaims{}, grants: map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("POST /device", f.device)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.URL = f.srv.URL
	return f
}

func (f *fakeIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc := map[string]any{
		"issuer":                 f.URL,
		"authorization_endpoint": f.URL + "/authorize",
		"token_endpoint":         f.URL + "/token",
		"scopes_supported":       f.scopes,
	}
	if !f.noDevice {
		doc["device_authorization_endpoint"] = f.URL + "/device"
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIssuer) authorize(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	f.lastAuth = q
	redirect := q.Get("redirect_uri")
	// RFC 8252: a loopback IP literal, any port; PKCE S256 is mandatory.
	if q.Get("response_type") != "code" || q.Get("client_id") != f.clientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || !strings.HasPrefix(redirect, "http://127.0.0.1:") || !strings.HasSuffix(redirect, "/callback") {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	back, _ := url.Parse(redirect)
	v := url.Values{"state": {q.Get("state")}}
	if f.deny != "" {
		v.Set("error", f.deny)
	} else {
		f.n++
		code := "code-" + strconv.Itoa(f.n)
		f.codes[code] = fakeCode{challenge: q.Get("code_challenge"), redirect: redirect, nonce: q.Get("nonce")}
		v.Set("code", code)
	}
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "the fake issuer said no"})
}

func (f *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	grant := r.PostForm.Get("grant_type")
	f.grants[grant]++
	if r.PostForm.Get("client_id") != f.clientID || r.PostForm.Get("client_secret") != f.secret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	nonce := ""
	switch grant {
	case "authorization_code":
		c, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || c.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		nonce = c.nonce
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		if f.failRefresh || !f.refresh[rt] {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		delete(f.refresh, rt) // rotation: a refresh token works once
	case "urn:ietf:params:oauth:grant-type:device_code":
		switch {
		case f.deviceDeny:
			oauthError(w, http.StatusBadRequest, "access_denied")
			return
		case f.devicePending > 0:
			f.devicePending--
			oauthError(w, http.StatusBadRequest, "authorization_pending")
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	f.n++
	refresh := "rt-" + strconv.Itoa(f.n)
	f.refresh[refresh] = true
	body := map[string]any{"access_token": "at-" + strconv.Itoa(f.n), "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh}
	switch {
	case f.junkIDToken:
		body["id_token"] = "not-a-jwt"
	case f.wrongNonce:
		body["id_token"] = f.mintLocked("someone-elses-nonce")
	case !f.noIDToken:
		body["id_token"] = f.mintLocked(nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeIssuer) device(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.PostForm.Get("client_id") != f.clientID {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code": "dc-1", "user_code": "ABCD-EFGH", "verification_uri": f.URL + "/activate",
		"expires_in": 600, "interval": 1,
	})
}

// mintLocked makes an ID token. Its signature is junk: sandboxd verifies
// signatures, the CLI never does, and the fake sandboxd trusts what this
// issuer minted.
func (f *fakeIssuer) mintLocked(nonce string) string {
	now := f.clock.Now()
	claims := fakeClaims{Sub: f.sub, Email: f.email, Groups: f.groups, Exp: now.Add(f.lifetime)}
	payload := map[string]any{
		"iss": f.URL, "sub": claims.Sub, "aud": f.clientID, "email": claims.Email, "groups": claims.Groups,
		"iat": now.Unix(), "exp": claims.Exp.Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	token := jwtFor(payload) + strconv.Itoa(f.n)
	f.idTokens[token] = claims
	return token
}

// jwtFor encodes claims as an unsigned-looking JWT.
func jwtFor(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func (f *fakeIssuer) claimsOf(token string) (fakeClaims, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.idTokens[token]
	return c, ok
}

func (f *fakeIssuer) grantCount(grant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants[grant]
}

func (f *fakeIssuer) set(fn func(f *fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// binding is one team an OIDC caller may act for in the fake sandboxd.
type binding struct {
	role, team string
}

// seenRequest is one request the fake sandboxd answered.
type seenRequest struct {
	path, bearer, team string
}

// fakeSandboxd answers the identity routes itself (discovery, whoami) and
// passes everything else to agenttoolstest, translating any credential it
// accepts into that fake's one token.
type fakeSandboxd struct {
	srv      *httptest.Server
	URL      string
	upstream *agenttoolstest.Server
	issuer   *fakeIssuer
	clock    *testClock

	mu          sync.Mutex
	discovery   *identitywire.AuthDiscovery
	bindings    []binding
	noBinding   *models.ErrorResponse
	explain     *identitywire.WhoAmIExplain
	tokens      map[string]models.WhoAmI
	whoamiCode  int
	whoamiCalls int
	seen        []seenRequest
}

func newFakeSandboxd(t *testing.T, issuer *fakeIssuer, clock *testClock) *fakeSandboxd {
	t.Helper()
	s := &fakeSandboxd{
		upstream: agenttoolstest.New(t), issuer: issuer, clock: clock,
		bindings: []binding{{"runner", "payments"}, {"viewer", "checkout"}},
		tokens: map[string]models.WhoAmI{
			agenttoolstest.Token: {Principal: models.WhoAmIPrincipal{Kind: "operator", ID: "operator", Name: "operator"}, Role: "admin", Team: "*"},
		},
	}
	if issuer != nil {
		s.discovery = &identitywire.AuthDiscovery{
			Version: identitywire.AuthDiscoveryVersion, IdentityEnabled: true,
			Issuers: []identitywire.DiscoveryIssuer{{
				Name: "okta", DisplayName: "Acme Okta", Kind: identitywire.IssuerKindOIDC, URL: issuer.URL,
				Clients: identitywire.DiscoveryClients{CLI: issuer.clientID, Dashboard: "0oa1dash"},
			}},
		}
	}
	upstream, _ := url.Parse(s.upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		s.seen = append(s.seen, seenRequest{path: r.URL.Path, bearer: bearer, team: r.Header.Get(identitywire.TeamHeader)})
		s.mu.Unlock()
		switch r.URL.Path {
		case identitywire.AuthDiscoveryPath:
			s.serveDiscovery(w)
			return
		case "/v1/whoami":
			s.serveWhoAmI(w, r, bearer)
			return
		}
		if _, status, _ := s.resolve(r, bearer); status != http.StatusOK {
			writeAPIError(w, status, models.ErrorResponse{Error: "unauthorized"})
			return
		}
		r.Header.Set("Authorization", "Bearer "+agenttoolstest.Token)
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

func writeAPIError(w http.ResponseWriter, status int, body models.ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *fakeSandboxd) serveDiscovery(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discovery == nil {
		http.NotFound(w, nil)
		return
	}
	_ = json.NewEncoder(w).Encode(s.discovery)
}

// resolve is the fake's authenticate: the WhoAmI for bearer, or the status
// and body of a refusal.
func (s *fakeSandboxd) resolve(r *http.Request, bearer string) (models.WhoAmI, int, models.ErrorResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if who, ok := s.tokens[bearer]; ok {
		return who, http.StatusOK, models.ErrorResponse{}
	}
	if s.issuer == nil {
		return models.WhoAmI{}, http.StatusUnauthorized, models.ErrorResponse{Error: "unauthorized"}
	}
	claims, ok := s.issuer.claimsOf(bearer)
	if !ok {
		return models.WhoAmI{}, http.StatusUnauthorized, models.ErrorResponse{Error: "unauthorized", Reason: "invalid_signature"}
	}
	if !s.clock.Now().Before(claims.Exp) {
		return models.WhoAmI{}, http.StatusUnauthorized, models.ErrorResponse{Error: "unauthorized", Reason: "expired"}
	}
	if s.noBinding != nil {
		return models.WhoAmI{}, http.StatusForbidden, *s.noBinding
	}
	exp := claims.Exp
	who := models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "oidc", ID: "oidc:okta:" + claims.Sub, Name: claims.Email}, ExpiresAt: &exp}
	team := r.Header.Get(identitywire.TeamHeader)
	for _, b := range s.bindings {
		if team == "" || b.team == team {
			who.Role, who.Team = b.role, b.team
			return who, http.StatusOK, models.ErrorResponse{}
		}
	}
	return models.WhoAmI{}, http.StatusForbidden, models.ErrorResponse{Error: "X-AerolVM-Team: " + team + " is not one of this credential's teams"}
}

func (s *fakeSandboxd) serveWhoAmI(w http.ResponseWriter, r *http.Request, bearer string) {
	s.mu.Lock()
	s.whoamiCalls++
	code := s.whoamiCode
	explain := s.explain
	s.mu.Unlock()
	if code != 0 {
		writeAPIError(w, code, models.ErrorResponse{Error: "sign-in with an identity provider is unavailable on this server right now"})
		return
	}
	who, status, body := s.resolve(r, bearer)
	if status != http.StatusOK {
		writeAPIError(w, status, body)
		return
	}
	out := whoAmIResponse{WhoAmI: who}
	if r.URL.Query().Get(identitywire.WhoAmIExplainQuery) == "1" {
		// As pkg/api/v1's whoami answers: the configured explanation for an
		// SSO caller (nil plays a sandboxd that predates it), and a note for
		// a credential that carries its own role.
		out.Explain = explain
		if who.Principal.Kind != "oidc" && explain != nil {
			out.Explain = &identitywire.WhoAmIExplain{Note: "binding matching doesn't apply to a " + who.Principal.Kind + " credential", Matched: []identitywire.ExplainBinding{}}
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *fakeSandboxd) whoamis() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.whoamiCalls
}

func (s *fakeSandboxd) requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenRequest(nil), s.seen...)
}

func (s *fakeSandboxd) set(fn func(s *fakeSandboxd)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// ssoWorld is a CLI with no credentials, a fake issuer and a fake sandboxd
// that trusts it, on one clock.
type ssoWorld struct {
	h       *harness
	path    string
	clock   *testClock
	issuer  *fakeIssuer
	server  *fakeSandboxd
	authURL string
	// browserBody is what the loopback page answered the "browser".
	browserBody string
}

// day0 is the tests' "now": 14:10 UTC, so a 54 minute token expires at
// 15:04 UTC, the DR15 example.
var day0 = time.Date(2026, 10, 17, 14, 10, 0, 0, time.UTC)

func newSSOWorld(t *testing.T) *ssoWorld {
	t.Helper()
	h, path := loginHarness(t)
	h.env["XDG_CACHE_HOME"] = t.TempDir()
	clock := &testClock{t: day0}
	issuer := newFakeIssuer(t, clock)
	w := &ssoWorld{h: h, path: path, clock: clock, issuer: issuer, server: newFakeSandboxd(t, issuer, clock)}
	h.app.now = clock.Now
	// The "browser" follows the authorize redirect straight back to the
	// CLI's loopback listener, as a signed-in browser would.
	h.app.openBrowser = func(u string) error {
		w.authURL = u
		resp, err := http.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		w.browserBody = string(b)
		return nil
	}
	return w
}

// normalize makes output comparable with the golden files: the test
// servers' addresses become the plan's example hosts.
func (w *ssoWorld) normalize(s string) string {
	pairs := []string{w.path, "<path>", w.server.URL, "https://api.acme.dev", w.issuer.URL, "https://acme.okta.com"}
	if w.authURL != "" {
		pairs = append([]string{w.authURL, "<url>"}, pairs...)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

func (w *ssoWorld) saved(t *testing.T) savedLogin {
	t.Helper()
	return readSaved(t, w.path)
}

// TestSSOLoginBrowserEndToEnd is the loopback flow against the fake issuer:
// the DR15 issuer choice and browser prompt, PKCE and the nonce checked,
// the login saved readable only by its owner, and every command then
// working on it.
func TestSSOLoginBrowserEndToEnd(t *testing.T) {
	w := newSSOWorld(t)
	w.server.discovery.Issuers = append(w.server.discovery.Issuers,
		identitywire.DiscoveryIssuer{Name: "google", DisplayName: "Google", Kind: identitywire.IssuerKindGoogle, URL: "https://accounts.google.com", Clients: identitywire.DiscoveryClients{CLI: "123-cli"}},
		// A workload issuer has no CLI client and is never offered.
		identitywire.DiscoveryIssuer{Name: "github-actions", URL: "https://token.actions.githubusercontent.com"},
	)
	w.issuer.lifetime = 54 * time.Minute
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	h := w.h
	h.app.stdinIsTTY = true
	h.app.stdin = strings.NewReader("\n") // Enter takes [1]

	if code := h.run("login", w.server.URL); code != exitOK {
		t.Fatalf("login = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "login-browser.golden", w.normalize(h.stderr.String()))
	if !strings.Contains(w.browserBody, "You're signed in to AerolVM") {
		t.Fatalf("the browser saw %q", w.browserBody)
	}
	auth := w.issuer.lastAuth
	if got := auth.Get("scope"); got != "openid email profile offline_access groups" {
		t.Fatalf("scopes = %q", got)
	}
	if auth.Get("nonce") == "" || auth.Get("state") == "" || auth.Get("access_type") != "" {
		t.Fatalf("authorize query = %v", auth)
	}

	saved := w.saved(t)
	if saved.SSO == nil || saved.SSO.Issuer != "okta" || saved.SSO.DisplayName != "Acme Okta" || saved.SSO.ClientID != "0oa1cli" ||
		saved.SSO.RefreshToken == "" || saved.SSO.ClientSecret != "" || saved.SSO.TokenURL != w.issuer.URL+"/token" ||
		!saved.SSO.Expiry.Equal(day0.Add(54*time.Minute)) || saved.APIURL != w.server.URL || saved.Team != "" {
		t.Fatalf("saved login = %+v %+v", saved, saved.SSO)
	}
	if _, ok := w.issuer.claimsOf(saved.Token); !ok {
		t.Fatal("the saved token is not the ID token the issuer minted")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(w.path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("login file mode = %v %v", info.Mode().Perm(), err)
		}
	}
	if strings.Contains(h.stderr.String()+h.stdout.String(), saved.Token) || strings.Contains(h.stderr.String(), saved.SSO.RefreshToken) {
		t.Fatal("login printed a token")
	}

	// Every command runs on the login, sending the ID token and no team.
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stdout.String(), "box") {
		t.Fatalf("list on the SSO login = %d %q", code, h.stderr.String())
	}
	last := w.server.requests()[len(w.server.requests())-1]
	if last.bearer != saved.Token || last.team != "" {
		t.Fatalf("list sent %+v", last)
	}
	if code := h.run("whoami"); code != exitOK {
		t.Fatalf("whoami = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "whoami-sso.golden", h.stdout.String())
	if code := h.run("auth", "token"); code != exitOK || h.stdout.String() != saved.Token+"\n" {
		t.Fatalf("auth token = %d %q", code, h.stdout.String())
	}
	if code := h.run("auth", "token", "--json"); code != exitOK {
		t.Fatalf("auth token --json = %d", code)
	}
	var tok struct {
		APIURL    string    `json:"api_url"`
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	h.jsonOut(&tok)
	if tok.Token != saved.Token || tok.APIURL != w.server.URL || !tok.ExpiresAt.Equal(saved.SSO.Expiry) {
		t.Fatalf("auth token --json = %+v", tok)
	}
	if grants := w.issuer.grantCount("refresh_token"); grants != 0 {
		t.Fatalf("a fresh login was renewed %d times", grants)
	}
}

// TestSSOLoginDeviceFlowWithTeam is the device flow (RFC 8628) for an SSH
// session, with --team saved and sent as X-AerolVM-Team (D13).
func TestSSOLoginDeviceFlowWithTeam(t *testing.T) {
	w := newSSOWorld(t)
	w.issuer.devicePending = 1 // the person is still typing the code at the first poll
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	h := w.h
	h.app.stdinIsTTY = false // an SSH session piping nothing still signs in with --device

	if code := h.run("login", w.server.URL, "--device", "--team", "checkout"); code != exitOK {
		t.Fatalf("login --device = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "login-device.golden", w.normalize(h.stderr.String()))
	if w.authURL != "" {
		t.Fatal("--device opened a browser")
	}
	saved := w.saved(t)
	if saved.Team != "checkout" || saved.SSO == nil || saved.SSO.RefreshToken == "" {
		t.Fatalf("saved = %+v", saved)
	}
	if code := h.run("list"); code != exitOK {
		t.Fatalf("list = %d %q", code, h.stderr.String())
	}
	for _, r := range w.server.requests() {
		if r.path != identitywire.AuthDiscoveryPath && r.team != "checkout" {
			t.Fatalf("%s went without the team header: %+v", r.path, r)
		}
	}
	// SB_TEAM picks another team for one command; the saved one stays.
	h.env["SB_TEAM"] = "payments"
	if code := h.run("whoami", "--json"); code != exitOK {
		t.Fatalf("whoami with SB_TEAM = %d %q", code, h.stderr.String())
	}
	var who models.WhoAmI
	h.jsonOut(&who)
	if who.Team != "payments" || who.Role != "runner" {
		t.Fatalf("whoami with SB_TEAM = %+v", who)
	}
	h.env["SB_TEAM"] = "Not A Team"
	if code := h.run("whoami"); code != exitError || !strings.Contains(h.stderr.String(), `SB_TEAM="Not A Team" is not a team name`) {
		t.Fatalf("bad SB_TEAM = %d %q", code, h.stderr.String())
	}
}

// TestSSOLoginRefusals: the DR15 "no binding" line with the ten-group cap,
// DR8's overage and no-groups wording, a team the sign-in can't act for,
// the D17 reasons and a 503. Nothing is saved after any of them.
func TestSSOLoginRefusals(t *testing.T) {
	groups := []string{"everyone", "eng-all", "vpn-users", "wiki-editors", "payments-readonly", "oncall",
		"laptops", "github-users", "jira-users", "slack-users", "contractors", "building-3"}
	for _, tc := range []struct {
		name   string
		setup  func(w *ssoWorld)
		args   []string
		code   int
		golden string
		want   string
	}{
		{name: "no binding", golden: "login-no-binding.golden", code: exitError, setup: func(w *ssoWorld) {
			w.server.noBinding = &models.ErrorResponse{Error: "no role binding", Reason: "no_binding", Issuer: "okta", Name: "alice@acme.com", Groups: groups}
		}},
		{name: "overage", golden: "login-overage.golden", code: exitError, setup: func(w *ssoWorld) {
			w.server.noBinding = &models.ErrorResponse{Error: "no role binding", Reason: "group_overage", Issuer: "okta", Name: "alice@acme.com"}
		}},
		{name: "no groups, name from the token", code: exitError,
			want: "aerolvm: signed in as alice@acme.com through Acme Okta, but no access rule on https://api.acme.dev matches your account. Ask your AerolVM admin to add one for a group you're in. Your sign-in carried no groups.\n",
			setup: func(w *ssoWorld) {
				w.server.noBinding = &models.ErrorResponse{Error: "no role binding", Reason: "no_binding", Issuer: "okta"}
			}},
		{name: "a team the sign-in can't act for", args: []string{"--team", "billing"}, code: exitError,
			want: "X-AerolVM-Team: billing is not one of this credential's teams"},
		{name: "wrong audience", code: exitError, want: "refused the sign-in from Acme Okta (wrong_audience)\nhint: this server doesn't accept sign-ins from that app",
			setup: func(w *ssoWorld) { w.server.srv.Config.Handler = wrongAudience(w.server.srv.Config.Handler) }},
		{name: "unavailable", code: exitError, want: "sign-in is unavailable on https://api.acme.dev right now\nhint: try again in a minute",
			setup: func(w *ssoWorld) { w.server.whoamiCode = http.StatusServiceUnavailable }},
		{name: "the provider says no", code: exitError, want: "aerolvm: Acme Okta didn't sign you in (access_denied)\nhint: try again, or sign in with a different account",
			setup: func(w *ssoWorld) { w.issuer.deny = "access_denied" }},
		{name: "the provider sends no ID token", code: exitError, want: "Acme Okta sent no ID token",
			setup: func(w *ssoWorld) { w.issuer.noIDToken = true }},
		{name: "a provider app with a secret, none given", code: exitError, want: "Acme Okta refused the sign-in (invalid_client: the fake issuer said no)",
			setup: func(w *ssoWorld) { w.issuer.secret = "s3cret" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSSOWorld(t)
			if tc.setup != nil {
				tc.setup(w)
			}
			args := append([]string{"login", w.server.URL, "--sso"}, tc.args...)
			code := w.h.run(args...)
			got := w.normalize(w.h.stderr.String())
			if code != tc.code {
				t.Fatalf("login = %d %q", code, got)
			}
			if tc.golden != "" {
				// The golden is the refusal; the browser prompt before it is
				// pinned by TestSSOLoginBrowserEndToEnd.
				checkGolden(t, tc.golden, got[strings.Index(got, "\n")+1:])
			} else if !strings.Contains(got, tc.want) {
				t.Fatalf("stderr = %q, want %q", got, tc.want)
			}
			if _, err := os.Stat(w.path); !os.IsNotExist(err) {
				t.Fatal("a refused sign-in was saved")
			}
		})
	}
}

// wrongAudience answers whoami the way sandboxd answers a token for another
// app (D17).
func wrongAudience(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/whoami" {
			writeAPIError(w, http.StatusUnauthorized, models.ErrorResponse{Error: "unauthorized", Reason: "wrong_audience"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TestSSOLoginFlagsAndChoices covers the paths around the flows: no SSO on
// offer, --issuer, a choice a script can't make, a client secret on stdin
// kept for the next login, and Google's options.
func TestSSOLoginFlagsAndChoices(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	google := identitywire.DiscoveryIssuer{Name: "corp", DisplayName: "Corp Google", Kind: identitywire.IssuerKindGoogle, URL: w.issuer.URL, Clients: identitywire.DiscoveryClients{CLI: w.issuer.clientID}}
	okta := w.server.discovery.Issuers[0]
	w.server.discovery.Issuers = []identitywire.DiscoveryIssuer{{Name: "other", DisplayName: "Other", URL: "https://other.example.com", Clients: identitywire.DiscoveryClients{CLI: "x"}}, google}

	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		tty   bool
		code  int
		want  string
	}{
		{"a script can't choose", []string{"--sso"}, "", false, exitUsage, "offers 2 sign-in providers; choose one with --issuer (other, corp)"},
		{"an unknown issuer", []string{"--issuer", "nope"}, "", false, exitUsage, `has no sign-in provider "nope"; it offers other, corp`},
		{"a bad choice", []string{}, "7\n", true, exitUsage, `"7" is not one of the choices; give a number from 1 to 2`},
		{"--token-stdin and --sso", []string{"--token-stdin", "--sso"}, "", false, exitUsage, "can't be combined with --sso"},
		{"a bad --team", []string{"--team", "Payments!"}, "", false, exitUsage, "--team must be a team name"},
		{"an empty secret", []string{"--client-secret-stdin"}, "  \n", false, exitUsage, "the client secret is empty"},
		{"a provider that isn't reachable", []string{"--issuer", "other"}, "", false, exitError, "Other can't be reached"},
	} {
		h.app.stdinIsTTY = tc.tty
		h.app.stdin = strings.NewReader(tc.stdin)
		if code := h.run(append([]string{"login", w.server.URL}, tc.args...)...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%s: %v = %d %q; want %d and %q", tc.name, tc.args, code, h.stderr.String(), tc.code, tc.want)
		}
	}

	// A Google desktop app: the secret comes once on stdin and is saved
	// with the login; Google gets access_type=offline and the consent
	// screen, and no offline_access scope.
	w.issuer.secret = "GOCSPX-not-secret"
	h.app.stdinIsTTY = true
	h.app.stdin = strings.NewReader("GOCSPX-not-secret\n")
	if code := h.run("login", w.server.URL, "--issuer", "Corp Google", "--client-secret-stdin"); code != exitOK {
		t.Fatalf("google login = %d %q", code, h.stderr.String())
	}
	if got := w.issuer.lastAuth; got.Get("access_type") != "offline" || got.Get("prompt") != "consent" || got.Get("scope") != "openid email profile" {
		t.Fatalf("google authorize query = %v", got)
	}
	if s := w.saved(t); s.SSO.ClientSecret != "GOCSPX-not-secret" || s.SSO.Kind != identitywire.IssuerKindGoogle {
		t.Fatalf("saved = %+v", s.SSO)
	}
	// Signing in again needs no secret: the saved one is reused.
	h.app.stdin = strings.NewReader("")
	if code := h.run("login", w.server.URL, "--issuer", "corp"); code != exitOK || w.saved(t).SSO.ClientSecret != "GOCSPX-not-secret" {
		t.Fatalf("second google login = %d %q", code, h.stderr.String())
	}
	// Without it, Google's refusal says how to give it.
	if err := os.Remove(w.path); err != nil {
		t.Fatal(err)
	}
	if code := h.run("login", w.server.URL, "--issuer", "corp", "--json"); code != exitError ||
		!strings.Contains(h.stderr.String(), "Google sign-in needs the client secret your AerolVM admin gave you: aerolvm login --sso "+w.server.URL+" --client-secret-stdin") {
		t.Fatalf("google with no secret = %d %q", code, h.stderr.String())
	}

	// --json prints exactly what a token login prints (stdout unchanged).
	w.issuer.secret = ""
	w.server.discovery.Issuers = []identitywire.DiscoveryIssuer{okta}
	if code := h.run("login", w.server.URL, "--json"); code != exitOK {
		t.Fatalf("login --json = %d %q", code, h.stderr.String())
	}
	var out map[string]string
	h.jsonOut(&out)
	if len(out) != 3 || out["api_url"] != w.server.URL || out["config_path"] != w.path || out["server_version"] != "fake" {
		t.Fatalf("login --json = %v", out)
	}

	// A provider without the device flow.
	w.issuer.noDevice = true
	if code := h.run("login", w.server.URL, "--device"); code != exitError || !strings.Contains(h.stderr.String(), "Acme Okta doesn't offer sign-in with a code") {
		t.Fatalf("no device flow = %d %q", code, h.stderr.String())
	}
	w.issuer.noDevice = false
	w.issuer.deviceDeny = true
	if code := h.run("login", w.server.URL, "--device"); code != exitError || !strings.Contains(h.stderr.String(), "Acme Okta didn't sign you in (access_denied)") {
		t.Fatalf("device denied = %d %q", code, h.stderr.String())
	}
}

// TestSSOLoginNoSSOOnOffer: --sso against a server without SSO fails with
// the way out; a person at a terminal falls back to the token prompt, as
// before (TestLoginAsksSavesAndEveryCommandUsesIt).
func TestSSOLoginNoSSOOnOffer(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	w.server.discovery = nil // an older sandboxd: 404
	if code := h.run("login", w.server.URL, "--sso"); code != exitError ||
		!strings.Contains(h.stderr.String(), "sandboxd at "+w.server.URL+" offers no SSO sign-in for the CLI") ||
		!strings.Contains(h.stderr.String(), "--token-stdin") {
		t.Fatalf("--sso on an older server = %d %q", code, h.stderr.String())
	}
	w.server.discovery = &identitywire.AuthDiscovery{Version: 1, IdentityEnabled: false}
	if code := h.run("login", w.server.URL, "--sso"); code != exitError || !strings.Contains(h.stderr.String(), "offers no SSO") {
		t.Fatalf("--sso with identity off = %d %q", code, h.stderr.String())
	}
	if code := h.run("login", "http://127.0.0.1:1", "--sso"); code != exitError || strings.Contains(h.stderr.String(), "offers no SSO") {
		t.Fatalf("--sso against nothing = %d %q", code, h.stderr.String())
	}
	h.app.stdinIsTTY = true
	h.app.term = fakeTerm{secret: secretIs(agenttoolstest.Token)}
	if code := h.run("login", w.server.URL); code != exitOK || !strings.Contains(h.stderr.String(), "API token (typing is hidden)") {
		t.Fatalf("token prompt fallback = %d %q", code, h.stderr.String())
	}
}

// seedLogin saves an SSO login whose ID token expires at exp, with a live
// refresh token at the fake issuer.
func (w *ssoWorld) seedLogin(t *testing.T, exp time.Time) savedLogin {
	t.Helper()
	var token, refresh string
	w.issuer.set(func(f *fakeIssuer) {
		f.n++
		refresh = "rt-seed-" + strconv.Itoa(f.n)
		f.refresh[refresh] = true
		saved := f.lifetime
		f.lifetime = exp.Sub(f.clock.Now())
		token = f.mintLocked("")
		f.lifetime = saved
	})
	login := savedLogin{APIURL: w.server.URL, Token: token, SSO: &ssoLogin{
		Issuer: "okta", DisplayName: "Acme Okta", IssuerURL: w.issuer.URL, ClientID: w.issuer.clientID,
		TokenURL: w.issuer.URL + "/token", RefreshToken: refresh, Expiry: exp,
	}}
	if err := saveLogin(w.path, login); err != nil {
		t.Fatal(err)
	}
	return login
}

// TestSSORenewalEdge: a command renews the ID token when less than 60 s is
// left, and not at 60 s or more (§5.6). The renewed tokens are saved, with
// the rotated refresh token.
func TestSSORenewalEdge(t *testing.T) {
	for _, tc := range []struct {
		left    time.Duration
		renewed bool
	}{
		{59 * time.Second, true},
		{60 * time.Second, false},
		{61 * time.Second, false},
		{-time.Hour, true}, // long expired: a refresh token outlives it
	} {
		t.Run(tc.left.String(), func(t *testing.T) {
			w := newSSOWorld(t)
			w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
			before := w.seedLogin(t, day0.Add(tc.left))
			if code := w.h.run("list"); code != exitOK && tc.left > 0 {
				t.Fatalf("list = %d %q", code, w.h.stderr.String())
			}
			if got := w.issuer.grantCount("refresh_token"); got != map[bool]int{true: 1, false: 0}[tc.renewed] {
				t.Fatalf("refresh grants = %d", got)
			}
			after := w.saved(t)
			if !tc.renewed {
				if after.Token != before.Token {
					t.Fatal("a token with a minute left was replaced")
				}
				return
			}
			if after.Token == before.Token || after.SSO.RefreshToken == before.SSO.RefreshToken || !after.SSO.Expiry.Equal(day0.Add(time.Hour)) {
				t.Fatalf("renewed login = %+v", after.SSO)
			}
			if w.h.run("list") != exitOK {
				t.Fatalf("list after renewal: %q", w.h.stderr.String())
			}
			if last := w.server.requests()[len(w.server.requests())-1]; last.bearer != after.Token {
				t.Fatal("the command did not send the renewed token")
			}
		})
	}
}

// TestSSORenewalFailure is DR15's refresh-failure line, before the command
// sends anything, on stderr and in the --json envelope.
func TestSSORenewalFailure(t *testing.T) {
	w := newSSOWorld(t)
	w.seedLogin(t, day0.Add(10*time.Second))
	w.issuer.failRefresh = true
	before := len(w.server.requests())
	if code := w.h.run("list"); code != exitError {
		t.Fatalf("list = %d", code)
	}
	checkGolden(t, "refresh-failed.golden", w.normalize(w.h.stderr.String()))
	if len(w.server.requests()) != before {
		t.Fatal("a command whose sign-in couldn't be renewed still called sandboxd")
	}
	if code := w.h.run("list", "--json"); code != exitError || w.h.errorEnvelope().Message != "your sign-in to "+w.server.URL+" expired and couldn't be renewed. Sign in again: aerolvm login --sso "+w.server.URL {
		t.Fatalf("list --json = %d %q", code, w.h.stderr.String())
	}
	// --debug says why, for a support ticket.
	if code := w.h.run("whoami", "--debug"); code != exitError || !strings.Contains(w.h.stderr.String(), "aerolvm debug: renewing the sign-in failed: oauth2:") {
		t.Fatalf("whoami --debug = %d %q", code, w.h.stderr.String())
	}
	// A login with no refresh token can't be renewed either.
	login := w.saved(t)
	login.SSO.RefreshToken = ""
	if err := saveLogin(w.path, login); err != nil {
		t.Fatal(err)
	}
	if code := w.h.run("whoami"); code != exitError || !strings.Contains(w.h.stderr.String(), "couldn't be renewed") {
		t.Fatalf("no refresh token = %d %q", code, w.h.stderr.String())
	}
}

// TestSSORenewalSharedAcrossProcesses: an aerolvm whose copy of the login
// is stale takes the tokens another one already renewed (so a rotated
// refresh token is never spent twice), and never writes over a login that
// replaced its own.
func TestSSORenewalSharedAcrossProcesses(t *testing.T) {
	w := newSSOWorld(t)
	stale := w.seedLogin(t, day0.Add(10*time.Second))
	session := &ssoSession{a: w.h.app, path: w.path, login: stale}

	// Another process renewed it: the file now holds a fresh token.
	fresh := w.seedLogin(t, day0.Add(time.Hour))
	got, err := session.token(context.Background())
	if err != nil || got != fresh.Token || w.issuer.grantCount("refresh_token") != 0 {
		t.Fatalf("token = %q, %v (refresh grants %d)", got, err, w.issuer.grantCount("refresh_token"))
	}

	// The login was replaced by one for another server: renew in memory,
	// leave the file alone.
	session = &ssoSession{a: w.h.app, path: w.path, login: stale}
	other := savedLogin{APIURL: "https://other.example.com", Token: "other-token"}
	if err := saveLogin(w.path, other); err != nil {
		t.Fatal(err)
	}
	got, err = session.token(context.Background())
	if err != nil || got == stale.Token || w.saved(t).Token != "other-token" {
		t.Fatalf("renewal over a replaced login: %q, %v, file %+v", got, err, w.saved(t))
	}

	// A failed renewal is retried at most once a minute, and remembered so
	// the 401 that follows is worded as DR15's refresh failure.
	w.issuer.failRefresh = true
	session = &ssoSession{a: w.h.app, path: w.path, login: w.seedLogin(t, day0.Add(10*time.Second))}
	if _, err := session.token(context.Background()); err == nil || !session.renewalFailed() {
		t.Fatal("a failed renewal was not reported")
	}
	if _, err := session.token(context.Background()); err == nil || w.issuer.grantCount("refresh_token") != 2 {
		t.Fatalf("retry within a minute: refresh grants = %d", w.issuer.grantCount("refresh_token"))
	}
	w.clock.Set(day0.Add(2 * time.Minute))
	w.issuer.failRefresh = false
	if _, err := session.token(context.Background()); err != nil || session.renewalFailed() {
		t.Fatalf("retry after a minute: %v", err)
	}
}

// TestSSORenewalMidRun: a long-running command (mcp, a shell) renews before
// a request when the token is about to expire, and a 401 after a failed
// renewal gets DR15's words.
func TestSSORenewalMidRun(t *testing.T) {
	w := newSSOWorld(t)
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	login := w.seedLogin(t, day0.Add(10*time.Minute))
	conn, err := w.h.app.prepare(context.Background(), nil)
	if err != nil || conn.token != login.Token {
		t.Fatalf("prepare = %q, %v", conn.token, err)
	}
	client := w.h.app.apiHTTPClient(nil, conn)
	get := func() (int, string) {
		resp, err := client.Get(w.server.URL + "/v1/sandboxes")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		reqs := w.server.requests()
		return resp.StatusCode, reqs[len(reqs)-1].bearer
	}
	if code, bearer := get(); code != http.StatusOK || bearer != login.Token {
		t.Fatalf("first call = %d with %q", code, bearer)
	}
	w.clock.Set(day0.Add(9*time.Minute + 30*time.Second)) // 30 s left
	code, bearer := get()
	if code != http.StatusOK || bearer == login.Token || w.issuer.grantCount("refresh_token") != 1 {
		t.Fatalf("call with 30 s left = %d with the old token %v", code, bearer == login.Token)
	}

	w.issuer.failRefresh = true
	w.clock.Set(day0.Add(3 * time.Hour)) // the renewed token is long gone
	if code, _ := get(); code != http.StatusUnauthorized {
		t.Fatalf("expired call = %d", code)
	}
	e := w.h.app.explainRefusal(&agenttools.Error{Code: agenttools.CodeUnauthorized, HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"})
	if e.Message != "your sign-in to "+w.server.URL+" expired and couldn't be renewed. Sign in again: aerolvm login --sso "+w.server.URL || e.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("explainRefusal after a failed renewal = %+v", e)
	}
	// Without a failed renewal, a 401 on an SSO login points at --sso.
	w.h.app.conn.sso = &ssoSession{a: w.h.app, login: login}
	e = w.h.app.explainRefusal(&agenttools.Error{HTTPStatus: http.StatusUnauthorized})
	if e.Message != "sandboxd at "+w.server.URL+" refused your sign-in" || e.Hint != "sign in again: aerolvm login --sso "+w.server.URL {
		t.Fatalf("explainRefusal on an SSO login = %+v", e)
	}
}

// TestPrecedenceUnchanged: SB_PAT_TOKEN wins, SB_API_TOKEN is its alias
// and loses to it, and a saved SSO login is sent only to its own URL
// (login.go's rules, §5.6).
func TestPrecedenceUnchanged(t *testing.T) {
	w := newSSOWorld(t)
	login := w.seedLogin(t, day0.Add(time.Hour))
	h := w.h
	for _, tc := range []struct {
		name      string
		env       map[string]string
		wantToken string
		wantFrom  string
		wantErr   string
	}{
		{name: "the SSO login", wantToken: login.Token, wantFrom: w.path},
		{name: "SB_PAT_TOKEN wins", env: map[string]string{"SB_PAT_TOKEN": "pat"}, wantToken: "pat", wantFrom: "SB_PAT_TOKEN"},
		{name: "SB_API_TOKEN is its alias", env: map[string]string{"SB_API_TOKEN": "api"}, wantToken: "api", wantFrom: "SB_API_TOKEN"},
		{name: "SB_PAT_TOKEN beats SB_API_TOKEN", env: map[string]string{"SB_PAT_TOKEN": "pat", "SB_API_TOKEN": "api"}, wantToken: "pat", wantFrom: "SB_PAT_TOKEN"},
		{name: "never to another server", env: map[string]string{"SB_API_URL": "https://other.example.com"}, wantErr: "SB_API_URL points elsewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"SB_PAT_TOKEN", "SB_API_TOKEN", "SB_API_URL"} {
				h.env[k] = tc.env[k]
			}
			conn, err := h.app.prepare(context.Background(), nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || conn.token != tc.wantToken || conn.from != tc.wantFrom || (conn.sso != nil) != (tc.wantFrom == w.path) {
				t.Fatalf("connection = %+v, %v", conn, err)
			}
		})
	}
	// An env token is refused in its own words, naming the variable.
	h.env["SB_API_TOKEN"], h.env["SB_PAT_TOKEN"], h.env["SB_API_URL"] = "nope", "", w.server.URL
	if code := h.run("list"); code != exitError || !strings.Contains(h.stderr.String(), "refused the token in SB_API_TOKEN") || !strings.Contains(h.stderr.String(), "hint: check SB_API_TOKEN") {
		t.Fatalf("a bad SB_API_TOKEN = %d %q", code, h.stderr.String())
	}
	h.app.stdinIsTTY = false
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", w.server.URL, "--token-stdin"); code != exitOK || !strings.Contains(h.stderr.String(), "SB_API_TOKEN is set in this shell and takes precedence") {
		t.Fatalf("login with SB_API_TOKEN set = %d %q", code, h.stderr.String())
	}
	if code := h.run("logout"); code != exitOK || !strings.Contains(h.stderr.String(), "SB_API_TOKEN is still set") {
		t.Fatalf("logout = %d %q", code, h.stderr.String())
	}
}

// TestTokenLoginWithTeam: --team works with an API token too, and a 403
// for it says to check the team.
func TestTokenLoginWithTeam(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	h.app.stdinIsTTY = false
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", w.server.URL, "--token-stdin", "--team", "payments"); code != exitOK || w.saved(t).Team != "payments" {
		t.Fatalf("token login --team = %d %q", code, h.stderr.String())
	}
	if last := w.server.requests()[len(w.server.requests())-1]; last.team != "payments" {
		t.Fatalf("the check went without the team: %+v", last)
	}
	forbid := w.server.srv.Config.Handler
	w.server.srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		writeAPIError(rw, http.StatusForbidden, models.ErrorResponse{Error: "not your team"})
	})
	defer func() { w.server.srv.Config.Handler = forbid }()
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", w.server.URL, "--token-stdin", "--team", "billing"); code != exitError || !strings.Contains(h.stderr.String(), "hint: check the token, and that it may act for team billing") {
		t.Fatalf("token login, wrong team = %d %q", code, h.stderr.String())
	}
}

func TestLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json.lock")
	unlock, err := lockFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	if _, err := lockFile(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a held lock was taken: %v", err)
	}
	unlock()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unlock left the lock behind")
	}
	// A lock left by a crashed aerolvm is taken over.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	unlock, err = lockFile(context.Background(), path)
	if err != nil {
		t.Fatalf("a stale lock: %v", err)
	}
	unlock()
	if _, err := lockFile(context.Background(), filepath.Join(path, "under-a-file", "x")); err == nil {
		t.Fatal("a lock in a missing directory")
	}
}

func TestCallbackHandler(t *testing.T) {
	results := make(chan callbackResult, 1)
	h := callbackHandler("st", results)
	serve := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}
	for _, target := range []string{"/callback?state=other&code=x", "/favicon.ico", "/callback?code=x"} {
		if rec := serve(target); rec.Code != http.StatusBadRequest || len(results) != 0 {
			t.Fatalf("%s = %d (delivered %d)", target, rec.Code, len(results))
		}
	}
	if rec := serve("/callback?state=st"); !strings.Contains(rec.Body.String(), "Sign-in failed") || (<-results).err != "no_code" {
		t.Fatalf("no code = %q", rec.Body.String())
	}
	serve("/callback?state=st&code=c1")
	serve("/callback?state=st&code=c2") // a second redirect never blocks
	if r := <-results; r.code != "c1" {
		t.Fatalf("delivered %+v", r)
	}
}

func TestBrowserFlowWaitsAndGivesUp(t *testing.T) {
	w := newSSOWorld(t)
	w.h.app.openBrowser = func(string) error { return errors.New("no browser here") }
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p, err := w.h.app.fetchProviderConfig(ctx, nil, w.server.discovery.Issuers[0])
	if err != nil {
		t.Fatal(err)
	}
	login := &ssoLogin{DisplayName: "Acme Okta", ClientID: w.issuer.clientID, TokenURL: p.TokenEndpoint}
	_, _, err = w.h.app.browserFlow(ctx, nil, login, p, "https://api.acme.dev")
	if !agenttools.IsCode(err, agenttools.CodeTimeout) || !strings.Contains(agenttools.Classify(err).Hint, "aerolvm login --device https://api.acme.dev") {
		t.Fatalf("no browser, nobody signs in: %v", err)
	}
	if !strings.Contains(w.h.stderr.String(), "If it doesn't open, visit: http") {
		t.Fatalf("the URL was not printed: %q", w.h.stderr.String())
	}
}

func TestFetchProviderConfigChecks(t *testing.T) {
	w := newSSOWorld(t)
	iss := w.server.discovery.Issuers[0]
	mux := http.NewServeMux()
	var doc map[string]any
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(rw).Encode(doc) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, tc := range []struct {
		name string
		url  string
		doc  map[string]any
		want string
	}{
		{"plain http off this machine", "http://idp.example.com", nil, "has an issuer URL that isn't https"},
		{"another issuer", srv.URL, map[string]any{"issuer": "https://evil.example.com"}, `describes itself as "https://evil.example.com"`},
		{"a non-https endpoint", srv.URL, map[string]any{"issuer": srv.URL, "authorization_endpoint": "http://evil.example.com/a", "token_endpoint": srv.URL + "/t"}, "publishes an endpoint that isn't https"},
		{"a file endpoint", srv.URL, map[string]any{"issuer": srv.URL, "authorization_endpoint": "file:///etc/passwd", "token_endpoint": srv.URL + "/t"}, "isn't https"},
		{"a non-https device endpoint", srv.URL, map[string]any{"issuer": srv.URL + "/", "authorization_endpoint": srv.URL + "/a", "token_endpoint": srv.URL + "/t", "device_authorization_endpoint": "javascript:alert(1)"}, "isn't https"},
	} {
		iss.URL, doc = tc.url, tc.doc
		if _, err := w.h.app.fetchProviderConfig(context.Background(), nil, iss); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestSSOHelpers(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "open", "windows": "rundll32", "linux": "xdg-open", "freebsd": "xdg-open"} {
		if name, args := browserCommand(goos, "https://x"); name != want || args[len(args)-1] != "https://x" {
			t.Errorf("browserCommand(%s) = %s %v", goos, name, args)
		}
	}
	for raw, want := range map[string]bool{
		"https://idp.example.com": true, "http://127.0.0.1:9": true, "http://localhost/x": true,
		"http://idp.example.com": false, "file:///x": false, "https://u:p@idp.example.com": false, "::": false, "https://": false,
	} {
		if secureURL(raw) != want {
			t.Errorf("secureURL(%q) = %v", raw, !want)
		}
	}
	if errorCode("access_denied") != "access_denied" || errorCode("\x1b[31mevil") != "31mevil" || errorCode("") != "unknown_error" || len(errorCode(strings.Repeat("a", 100))) != 64 {
		t.Fatal("errorCode")
	}
	if printable(" a\x1b]0;x\x07b\u0085 ") != "a]0;xb" || len([]rune(printable(strings.Repeat("é", 300)))) != 200 {
		t.Fatalf("printable = %q", printable(" a\x1b]0;x\x07b\u0085 "))
	}
	var c idTokenClaims
	if err := json.Unmarshal([]byte(`{"groups":"solo","roles":[1,"r",null]}`), &c); err != nil || len(c.Groups) != 1 || c.Groups[0] != "solo" || len(c.Roles) != 1 {
		t.Fatalf("claim lists = %+v %v", c, err)
	}
	if err := json.Unmarshal([]byte(`{"groups":{"a":1},"roles":""}`), &c); err != nil {
		t.Fatalf("odd claim shapes must not fail the token: %v", err)
	}
	for _, raw := range []string{"a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if _, ok := decodeIDToken(raw); ok {
			t.Errorf("decodeIDToken(%q) read it", raw)
		}
	}
	if (idTokenClaims{}).person() != "-" || (idTokenClaims{Subject: "s"}).person() != "s" || (idTokenClaims{Name: "N", Subject: "s"}).person() != "N" {
		t.Fatal("person")
	}
	if got := ssoScopes(identitywire.IssuerKindOIDC, providerConfig{}); strings.Join(got, " ") != "openid email profile offline_access" {
		t.Fatalf("scopes with nothing advertised = %v", got)
	}
	if got := ssoScopes(identitywire.IssuerKindOIDC, providerConfig{ScopesSupported: []string{"openid"}}); strings.Join(got, " ") != "openid email profile" {
		t.Fatalf("scopes without offline_access = %v", got)
	}
	if browserOptions(identitywire.IssuerKindOIDC) != nil {
		t.Fatal("only Google gets extra options")
	}
	if listUpTo([]string{"a", "b", "c"}, 2) != "a, b (and 1 more)" || listUpTo([]string{"a"}, 2) != "a" {
		t.Fatal("listUpTo")
	}
	if roleAndTeam(models.WhoAmI{Role: "admin", Team: "*"}) != "role admin, all teams" || roleAndTeam(models.WhoAmI{Role: "runner"}) != "role runner" {
		t.Fatal("roleAndTeam")
	}
	if displayName(identitywire.DiscoveryIssuer{Name: "okta"}) != "okta" {
		t.Fatal("displayName falls back to the name")
	}
	if cliIssuers(identitywire.AuthDiscovery{Issuers: []identitywire.DiscoveryIssuer{{Name: "x", URL: "https://x", Clients: identitywire.DiscoveryClients{CLI: "c"}}}}) != nil {
		t.Fatal("identity off offers no issuer")
	}
	// noSSOError: a missing or unreadable document means no SSO; a network
	// error stays a network error.
	if e := noSSOError("https://a", &httpStatusError{url: "u", status: 404}); !strings.Contains(e.Error(), "offers no SSO") {
		t.Fatal(e)
	}
	if e := noSSOError("https://a", &json.SyntaxError{}); !strings.Contains(e.Error(), "offers no SSO") {
		t.Fatal(e)
	}
	netErr := &url.Error{Op: "Get", URL: "u", Err: errors.New("refused")}
	if e := noSSOError("https://a", netErr); e != netErr {
		t.Fatal(e)
	}
	if (&httpStatusError{url: "u", status: 404}).Error() != "u answered 404 Not Found" {
		t.Fatal("httpStatusError")
	}
	if signInRefusal("u", "v", idTokenClaims{}, io.EOF) != io.EOF {
		t.Fatal("a non-API error passes through")
	}
	teapot := &apiRefusal{APIError: &microvm.APIError{StatusCode: http.StatusTeapot}}
	if signInRefusal("u", "v", idTokenClaims{}, teapot) != error(teapot) {
		t.Fatal("other statuses pass through")
	}
	for reason, want := range map[string]string{
		"not_yet_valid": "clock", "unknown_issuer": "doesn't accept", "too_long_lived": "doesn't accept", "expired": "try again", "": "try again",
	} {
		if !strings.Contains(reasonHint(reason), want) {
			t.Errorf("reasonHint(%q) = %q", reason, reasonHint(reason))
		}
	}
	login := &ssoLogin{DisplayName: "Acme Okta"}
	if tokenEndpointError(login, "u", io.EOF) != io.EOF {
		t.Fatal("a transport error passes through")
	}
	if e := tokenEndpointError(login, "u", &oauth2.RetrieveError{ErrorCode: "expired_token"}); !strings.Contains(e.Error(), "didn't sign you in (expired_token)") {
		t.Fatal(e)
	}
	if e := tokenEndpointError(login, "u", &oauth2.RetrieveError{ErrorCode: "server_error"}); e.Error() != "Acme Okta refused the sign-in (server_error)" {
		t.Fatal(e)
	}
}

func TestOpenBrowserStartsACommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rundll32 would open a real browser")
	}
	// PATH holds only a fake opener, so no real browser starts.
	dir := t.TempDir()
	name, _ := browserCommand(runtime.GOOS, "")
	marker := filepath.Join(dir, "opened")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %q\n", marker)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err := openBrowser("https://idp.example.com/authorize"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == "https://idp.example.com/authorize" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the opener never ran")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Setenv("PATH", t.TempDir())
	if err := openBrowser("https://x"); err == nil {
		t.Fatal("a missing opener must fail")
	}
	if (&app{}).browser() == nil || newApp().clock().IsZero() || (&app{}).clock().IsZero() {
		t.Fatal("defaults")
	}
}

// TestSSOEdges: what a provider or a discovery document can get wrong, a
// choice made by number, a code nobody enters, and a login that can't be
// written.
func TestSSOEdges(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h

	// Discovery documents: too big, not JSON, an unusable URL.
	big := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = rw.Write([]byte(`{"x":"` + strings.Repeat("a", maxDiscoveryBytes) + `"}`))
			return
		}
		_, _ = rw.Write([]byte("<html>not json</html>"))
	}))
	defer big.Close()
	var v map[string]any
	for target, want := range map[string]string{big.URL + "/big": "more than", big.URL + "/html": "unreadable document", "http://a b": "invalid"} {
		if err := h.app.getJSON(context.Background(), nil, target, &v); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("getJSON(%s) = %v, want %q", target, err, want)
		}
	}

	for _, tc := range []struct {
		name  string
		setup func()
		args  []string
		want  string
	}{
		{"an ID token for another sign-in", func() { w.issuer.set(func(f *fakeIssuer) { f.wrongNonce = true }) }, nil, "Acme Okta sent an ID token for a different sign-in"},
		{"an unreadable ID token", func() { w.issuer.set(func(f *fakeIssuer) { f.wrongNonce, f.junkIDToken = false, true }) }, nil, "Acme Okta sent an ID token aerolvm can't read"},
		{"a device code for another app", func() {
			w.issuer.set(func(f *fakeIssuer) { f.junkIDToken = false })
			w.server.set(func(s *fakeSandboxd) { s.discovery.Issuers[0].Clients.CLI = "someone-else" })
		}, []string{"--device"}, "Acme Okta refused the sign-in (invalid_client"},
	} {
		tc.setup()
		if code := h.run(append([]string{"login", w.server.URL, "--sso"}, tc.args...)...); code != exitError || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%s = %d %q", tc.name, code, h.stderr.String())
		}
	}
	w.server.set(func(s *fakeSandboxd) { s.discovery.Issuers[0].Clients.CLI = w.issuer.clientID })

	// A code nobody enters runs out.
	saved := ssoWaitTimeout
	ssoWaitTimeout = 1500 * time.Millisecond
	defer func() { ssoWaitTimeout = saved }()
	w.issuer.set(func(f *fakeIssuer) { f.devicePending = 100 })
	if code := h.run("login", w.server.URL, "--device"); code != exitError || !strings.Contains(h.stderr.String(), "the sign-in code expired before anyone used it") {
		t.Fatalf("an unused code = %d %q", code, h.stderr.String())
	}
	ssoWaitTimeout = saved

	// Picking the second provider by number.
	w.server.set(func(s *fakeSandboxd) {
		s.discovery.Issuers = append([]identitywire.DiscoveryIssuer{{Name: "first", URL: "https://first.example.com", Clients: identitywire.DiscoveryClients{CLI: "x"}}}, s.discovery.Issuers...)
	})
	h.app.stdinIsTTY = true
	h.app.stdin = strings.NewReader("2\n")
	if code := h.run("login", w.server.URL); code != exitOK || w.saved(t).SSO.Issuer != "okta" {
		t.Fatalf("choice 2 = %d %q", code, h.stderr.String())
	}

	// A renewal whose provider answers without an ID token fails, and the
	// old login stays as it was.
	before := w.seedLogin(t, day0.Add(5*time.Second))
	w.issuer.set(func(f *fakeIssuer) { f.noIDToken = true })
	if code := h.run("whoami"); code != exitError || !strings.Contains(h.stderr.String(), "couldn't be renewed") || w.saved(t).Token != before.Token {
		t.Fatalf("renewal without an ID token = %d %q", code, h.stderr.String())
	}
	w.issuer.set(func(f *fakeIssuer) { f.noIDToken = false })

	// A login that can't be written is reported, not half-saved.
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.env["XDG_CONFIG_HOME"] = blocker
	h.app.stdin = strings.NewReader("2\n")
	if code := h.run("login", w.server.URL); code != exitError {
		t.Fatalf("unwritable login = %d %q", code, h.stderr.String())
	}
}

// TestStreamsCarryTheTeam: streamed exec and shell attach open WebSockets,
// which no HTTP client reaches; the SDK's Team option puts the login's
// --team (or SB_TEAM) on their handshakes too, so a person in several
// teams execs into their selected team's sandbox (D13).
func TestStreamsCarryTheTeam(t *testing.T) {
	w := newSSOWorld(t)
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	h := w.h
	h.app.stdinIsTTY = false
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", w.server.URL, "--token-stdin", "--team", "payments"); code != exitOK {
		t.Fatalf("login = %d %q", code, h.stderr.String())
	}
	handshakes := func(suffix string) []seenRequest {
		var out []seenRequest
		for _, r := range w.server.requests() {
			if strings.HasSuffix(r.path, suffix) {
				out = append(out, r)
			}
		}
		return out
	}

	if code := h.run("exec", "box", "--", "echo", "hi"); code != 0 || h.stdout.String() != "hi\n" {
		t.Fatalf("exec = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if got := handshakes("/toolbox/process/exec/stream"); len(got) != 1 || got[0].team != "payments" {
		t.Fatalf("exec stream handshakes = %+v, want one carrying team payments", got)
	}

	w.server.upstream.Observe(func(s *agenttoolstest.Server) {
		s.LiveAttach = true
		s.ExecFunc = miniShell
	})
	h.app.stdinIsTTY, h.app.stdoutIsTTY, h.app.term = true, true, fakeTerm{}
	keys := h.keyboard()
	done := h.runAsync("shell", "box")
	typeKeys(t, keys, "exit 0\n")
	if code := h.wait(done); code != 0 {
		t.Fatalf("shell = %d %q", code, h.stderr.String())
	}
	if got := handshakes("/attach"); len(got) != 1 || got[0].team != "payments" {
		t.Fatalf("shell attach handshakes = %+v, want one carrying team payments", got)
	}

	// SB_TEAM picks another team for one command, handshake included.
	h.env["SB_TEAM"] = "checkout"
	w.server.upstream.Observe(func(s *agenttoolstest.Server) { s.LiveAttach, s.ExecFunc = false, nil })
	h.app.stdinIsTTY, h.app.stdoutIsTTY = false, false
	h.app.stdin = strings.NewReader("")
	if code := h.run("exec", "box", "--", "echo", "hi"); code != 0 {
		t.Fatalf("exec with SB_TEAM = %d %q", code, h.stderr.String())
	}
	if got := handshakes("/toolbox/process/exec/stream"); len(got) != 2 || got[1].team != "checkout" {
		t.Fatalf("exec stream handshakes = %+v, want the second carrying team checkout", got)
	}

	// aerolvm mcp hands the SDK the same team.
	var mcpTeam string
	h.app.newTools = func(cfg agenttools.Config) (*agenttools.Tools, error) {
		mcpTeam = cfg.Team
		return agenttools.New(cfg)
	}
	if code := h.run("mcp"); code != exitOK || mcpTeam != "checkout" {
		t.Fatalf("mcp = %d, team %q; stderr %q", code, mcpTeam, h.stderr.String())
	}
}
