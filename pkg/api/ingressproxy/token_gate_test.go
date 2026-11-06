package ingressproxy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// testKeys is a one-key ring: what secrets.Cipher is to the real service.
type testKeys struct{ priv ed25519.PrivateKey }

func newTestKeys() testKeys {
	return testKeys{priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
}

func (k testKeys) SandboxTokenSigner() (uint32, ed25519.PrivateKey, error) { return 0, k.priv, nil }
func (k testKeys) SandboxTokenVerifyKey(id uint32) (ed25519.PublicKey, bool) {
	if id != 0 {
		return nil, false
	}
	return k.priv.Public().(ed25519.PublicKey), true
}
func (k testKeys) VerifySandboxToken(raw string) (sandboxtoken.Claims, error) {
	return sandboxtoken.Verify(k, raw, time.Now(), 24*time.Hour)
}

func (k testKeys) token(t *testing.T, sandboxID string, port int, prefix string, ttl time.Duration) string {
	t.Helper()
	id, _ := sandboxtoken.NewTokenID()
	now := time.Now()
	iat := now
	if ttl < 0 {
		iat = now.Add(2 * ttl)
	}
	raw, _, err := sandboxtoken.Sign(k, sandboxtoken.Claims{
		TokenID: id, SandboxID: sandboxID, Port: port, PathPrefix: prefix,
		IssuedAt: iat.Unix(), ExpiresAt: now.Add(ttl).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// gateUpstream records what reached the sandbox's app.
type gateUpstream struct {
	mu      sync.Mutex
	calls   int
	cookies []string
	queries []string
}

func (u *gateUpstream) server(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls++
		u.cookies = append(u.cookies, r.Header.Get("Cookie"))
		u.queries = append(u.queries, r.URL.RawQuery)
		u.mu.Unlock()
		_, _ = io.WriteString(w, "app")
	}))
	t.Cleanup(ts.Close)
	return ts
}

func gatedHandler(res PortResolver, tokens TokenVerifier, hosts *HostRoutes) http.Handler {
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Resolver:       res,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBufferBytes: 1 << 20,
		Hosts:          hosts,
		Tokens:         tokens,
	})
	return mux
}

func gateDo(h http.Handler, method, target, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "sb1-8080.d.test"
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// A2 end to end on the wake path: no token is a 401 that wakes nothing;
// ?token= sets a host-only __Host- cookie and redirects to the same URL
// without the token; the cookie then gets through, and the app never sees
// the token in its query or its cookies.
func TestTokenGateExchangeAndCookie(t *testing.T) {
	keys := newTestKeys()
	up := &gateUpstream{}
	ts := up.server(t)
	res := &fakeResolver{target: ts.URL, started: true, gated: true}
	h := gatedHandler(res, keys, nil)
	tok := keys.token(t, "sb1", 8080, "/app", time.Hour)

	if rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/app/page", ""); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "?token=") {
		t.Fatalf("no token: %d %s", rr.Code, rr.Body.String())
	}
	if res.callCnt != 0 || up.calls != 0 {
		t.Fatal("a request without a token reached the wake path or the app")
	}

	rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/app/page?a=1&token="+tok+"&b=%2F2", "")
	if rr.Code != http.StatusFound {
		t.Fatalf("exchange: %d %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/app/page?a=1&b=%2F2" {
		t.Fatalf("Location = %q", loc)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("redirect headers: %v", rr.Header())
	}
	setCookie := rr.Header().Get("Set-Cookie")
	for _, want := range []string{TokenCookieName + "=" + tok, "Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Max-Age="} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("Set-Cookie %q lacks %q", setCookie, want)
		}
	}
	if strings.Contains(strings.ToLower(setCookie), "domain=") {
		t.Fatalf("Set-Cookie names a Domain: %q", setCookie)
	}
	if up.calls != 0 || res.callCnt != 0 {
		t.Fatal("the exchange request was proxied")
	}

	ok := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/app/page?a=1", "theme=dark; "+TokenCookieName+"="+tok+"; session=abc")
	if ok.Code != http.StatusOK || ok.Body.String() != "app" {
		t.Fatalf("with the cookie: %d %s", ok.Code, ok.Body.String())
	}
	if up.calls != 1 || up.cookies[0] != "theme=dark; session=abc" || strings.Contains(up.queries[0], "token") {
		t.Fatalf("the app saw cookies %q query %q", up.cookies, up.queries)
	}
}

// Every bad token is refused before the wake path, with no cookie set.
func TestTokenGateRefusals(t *testing.T) {
	keys := newTestKeys()
	up := &gateUpstream{}
	ts := up.server(t)
	res := &fakeResolver{target: ts.URL, started: true, gated: true}
	h := gatedHandler(res, keys, nil)
	other := newTestKeys()
	other.priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

	cases := []struct {
		name, target, cookie string
		status               int
		says                 string
	}{
		{"another sandbox's token", "/app?token=" + keys.token(t, "sb2", 8080, "", time.Hour), "", http.StatusForbidden, "sandbox"},
		{"another port's token", "/app?token=" + keys.token(t, "sb1", 9090, "", time.Hour), "", http.StatusForbidden, "port"},
		{"a toolbox token", "/app?token=" + keys.token(t, "sb1", 0, "", time.Hour), "", http.StatusForbidden, "port"},
		{"outside the path prefix", "/admin?token=" + keys.token(t, "sb1", 8080, "/app", time.Hour), "", http.StatusForbidden, "path"},
		{"expired", "/app?token=" + keys.token(t, "sb1", 8080, "", -time.Hour), "", http.StatusUnauthorized, "expired"},
		{"another server key", "/app?token=" + other.token(t, "sb1", 8080, "", time.Hour), "", http.StatusUnauthorized, "invalid_signature"},
		{"empty token", "/app?token=", "", http.StatusUnauthorized, "malformed"},
		{"garbage token", "/app?token=" + sandboxtoken.Prefix + "x", "", http.StatusUnauthorized, "malformed"},
		{"bad escape", "/app?token=%zz", "", http.StatusUnauthorized, "malformed"},
		{"another sandbox's cookie", "/app", TokenCookieName + "=" + keys.token(t, "sb2", 8080, "", time.Hour), http.StatusForbidden, "sandbox"},
		{"expired cookie", "/app", TokenCookieName + "=" + keys.token(t, "sb1", 8080, "", -time.Hour), http.StatusUnauthorized, "expired"},
		{"cookie of another name", "/app", "aerolvm-token=" + keys.token(t, "sb1", 8080, "", time.Hour), http.StatusUnauthorized, "?token="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080"+tc.target, tc.cookie)
			if rr.Code != tc.status || !strings.Contains(rr.Body.String(), tc.says) {
				t.Fatalf("%d %s, want %d naming %q", rr.Code, rr.Body.String(), tc.status, tc.says)
			}
			if rr.Header().Get("Set-Cookie") != "" {
				t.Fatal("a refusal set a cookie")
			}
		})
	}
	if up.calls != 0 || res.callCnt != 0 {
		t.Fatalf("a refused request reached the app (%d) or the wake path (%d)", up.calls, res.callCnt)
	}

	// No verifier wired: every token is refused, the port stays shut.
	shut := gatedHandler(res, nil, nil)
	if rr := gateDo(shut, http.MethodGet, PathPrefix+"/sb1/8080/app", TokenCookieName+"="+keys.token(t, "sb1", 8080, "", time.Hour)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no verifier: %d", rr.Code)
	}
}

// Two cookies of the name (one stale): the good one lets the request in.
func TestTokenGateAnyGoodCookie(t *testing.T) {
	keys := newTestKeys()
	up := &gateUpstream{}
	ts := up.server(t)
	h := gatedHandler(&fakeResolver{target: ts.URL, started: true, gated: true}, keys, nil)
	stale := keys.token(t, "sb1", 8080, "", -time.Hour)
	good := keys.token(t, "sb1", 8080, "", time.Hour)
	rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/", TokenCookieName+"="+stale+"; "+TokenCookieName+"=\""+good+"\"")
	if rr.Code != http.StatusOK || up.cookies[0] != "" {
		t.Fatalf("%d, app saw cookies %q", rr.Code, up.cookies)
	}
}

// A port that is not gated is proxied exactly as before: no check, and its
// cookies (even one of the token's name) and query reach the app untouched.
func TestTokenGateOnlyForGatedPorts(t *testing.T) {
	keys := newTestKeys()
	up := &gateUpstream{}
	ts := up.server(t)
	h := gatedHandler(&fakeResolver{target: ts.URL, started: true}, keys, nil)
	rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/x?token=abc", TokenCookieName+"=v")
	if rr.Code != http.StatusOK || up.queries[0] != "token=abc" || up.cookies[0] != TokenCookieName+"=v" {
		t.Fatalf("public port: %d query %q cookies %q", rr.Code, up.queries, up.cookies)
	}
}

// The host router (SB_INGRESS_PROXY_ROUTING) serves through the same gate.
func TestTokenGateOnTheHostRouter(t *testing.T) {
	keys := newTestKeys()
	up := &gateUpstream{}
	ts := up.server(t)
	owner := routedns.NewOwnerTable()
	owner.Set("sb1-8080.d.test", routedns.OwnerTarget{State: routedns.TargetWake, SandboxID: "sb1", GuestPort: 8080})
	h := gatedHandler(&fakeResolver{target: ts.URL, started: true, gated: true}, keys, &HostRoutes{Owner: owner, ClusterMode: true})
	if rr := gateDo(h, http.MethodGet, "/x", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("router without a token: %d", rr.Code)
	}
	tok := keys.token(t, "sb1", 8080, "", time.Hour)
	if rr := gateDo(h, http.MethodGet, "/x?token="+tok, ""); rr.Code != http.StatusFound || rr.Header().Get("Location") != "/x" {
		t.Fatalf("router exchange: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if rr := gateDo(h, http.MethodGet, "/x", TokenCookieName+"="+tok); rr.Code != http.StatusOK {
		t.Fatalf("router cookie: %d", rr.Code)
	}
}

// An unknown gate (a store error) refuses rather than guessing the port is
// open.
func TestTokenGateFailsClosedOnAccessError(t *testing.T) {
	up := &gateUpstream{}
	ts := up.server(t)
	h := gatedHandler(&fakeResolver{target: ts.URL, startedErr: errors.New("database is locked")}, newTestKeys(), nil)
	if rr := gateDo(h, http.MethodGet, PathPrefix+"/sb1/8080/", ""); rr.Code < 400 || up.calls != 0 {
		t.Fatalf("store error: %d, app calls %d", rr.Code, up.calls)
	}
}

func TestLocationWithoutToken(t *testing.T) {
	for _, tc := range []struct{ path, query, want string }{
		{"/", "token=x", "/"},
		{"/a", "", "/a"},
		{"/a b", "token=x&q=1", "/a%20b?q=1"},
		{"//evil.example/x", "token=x", "/evil.example/x"},
		{"/a?b", "token=x", "/a%3Fb"},
		{"", "token=x&&k", "/?k"},
		{"/p", "tok%65n=x&token2=y", "/p?token2=y"},
	} {
		if got := locationWithoutToken(tc.path, tc.query); got != tc.want {
			t.Fatalf("locationWithoutToken(%q, %q) = %q, want %q", tc.path, tc.query, got, tc.want)
		}
	}
}

func TestTokenCookieHelpers(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "a=1; "+TokenCookieName+"=t1")
	h.Add("Cookie", TokenCookieName+"=t2")
	h.Add("Cookie", "b=2;;")
	if got := tokenCookies(h.Values("Cookie")); len(got) != 2 || got[0] != "t1" || got[1] != "t2" {
		t.Fatalf("tokenCookies = %v", got)
	}
	stripTokenCookie(h)
	if got := h.Values("Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Fatalf("after strip = %q", got)
	}
	empty := http.Header{}
	stripTokenCookie(empty)
	if len(empty) != 0 {
		t.Fatal("strip added a header")
	}
	if _, ok := tokenFromQuery("a=1&b=2"); ok {
		t.Fatal("found a token where there is none")
	}
	if v, ok := tokenFromQuery("%zz=1&token=abc"); !ok || v != "abc" {
		t.Fatalf("tokenFromQuery = %q %v", v, ok)
	}
}
