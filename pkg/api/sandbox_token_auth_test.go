package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// toolboxUpstream is a fake toolboxd: it records what the proxy sent it.
type toolboxUpstream struct {
	mu    sync.Mutex
	paths []string
	auths []string
}

func (u *toolboxUpstream) seen() (paths, auths []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.paths...), append([]string(nil), u.auths...)
}

// sandboxTokenServer is a single-node server over a real store and server
// key whose sandboxes' toolboxes are one fake toolboxd on 127.0.0.1.
func sandboxTokenServer(t *testing.T, identityOn bool, sandboxes ...*models.Sandbox) (*Server, *secrets.Cipher, *toolboxUpstream, *recSink) {
	t.Helper()
	up := &toolboxUpstream{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.paths = append(up.paths, r.Method+" "+r.URL.Path)
		up.auths = append(up.auths, r.Header.Get("Authorization"))
		up.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	for _, sb := range sandboxes {
		sb.ContainerIP = host
		sb.ToolboxToken = "toolbox-secret-" + sb.ID
	}
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st := storeWith(t, "tokens")
	svc := service.New(config.Config{ToolboxPort: port, SandboxTokenMaxTTL: time.Hour}, discardLogger(), st, nil, nil, nil, cipher, nil, nil)
	// After service.New: it hands the store the cipher that seals toolbox
	// tokens at rest.
	for _, sb := range sandboxes {
		if err := st.Create(context.Background(), sb); err != nil {
			t.Fatal(err)
		}
	}
	sink := &recSink{}
	svc.UseAuditSinkForTest(sink)
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{IdentityEnabled: identityOn}, "pat-token", nil,
		WithCredentialAuthenticator(controlplane.PrincipalToken, stubCredential{
			prefix: "avm_",
			kind:   controlplane.PrincipalToken,
			accept: map[string]controlplane.Access{
				"avm_viewer": tokenAccess("payments", controlplane.RoleViewer),
				"avm_runner": tokenAccess("payments", controlplane.RoleRunner),
				"avm_growth": tokenAccess("growth", controlplane.RoleRunner),
			},
		}))
	return srv, cipher, up, sink
}

func issueToken(t *testing.T, srv *Server, bearer, sandboxID, body string) (*httptest.ResponseRecorder, models.SandboxToken) {
	t.Helper()
	rec := do(t, srv, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/tokens", bearer, body, nil)
	var tok models.SandboxToken
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	return rec, tok
}

// A1 through the whole server: the operator issues a toolbox token; it
// works on that sandbox's toolbox inside its scope; the sandbox's toolboxd
// sees its own toolbox token, never the sandbox token; the call's audit
// record names the token's id as the caller.
func TestSandboxTokenThroughTheServer(t *testing.T) {
	srv, _, up, sink := sandboxTokenServer(t, false, ownedSandbox("sb-a", "payments"), ownedSandbox("sb-b", "payments"))

	rec, tok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m","path_prefix":"/files","methods":["GET"]}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" || !sandboxtoken.IsToken(tok.Token) ||
		tok.SandboxID != "sb-a" || tok.PathPrefix != "/files" || len(tok.Methods) != 1 {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}

	ok := do(t, srv, http.MethodGet, "/v1/sandboxes/sb-a/toolbox/files/download?path=/etc/hostname", tok.Token, "", nil)
	if ok.Code != http.StatusNoContent {
		t.Fatalf("in scope: %d %s", ok.Code, ok.Body.String())
	}
	paths, auths := up.seen()
	if len(paths) != 1 || paths[0] != "GET /files/download" || auths[0] != "Bearer toolbox-secret-sb-a" {
		t.Fatalf("toolboxd saw %v %v", paths, auths)
	}
	for _, a := range auths {
		if strings.Contains(a, tok.Token) {
			t.Fatal("the sandbox token reached the sandbox")
		}
	}

	// The api record of the token's own call names it by id.
	found := false
	for _, ev := range sink.waitRecords(t, 2) {
		if ev.Caller != nil && ev.Caller.Kind == string(controlplane.PrincipalSandboxToken) && ev.Caller.ID == tok.TokenID {
			found = true
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), tok.Token) {
			t.Fatalf("an audit record holds the token: %s", raw)
		}
	}
	if !found {
		t.Fatalf("no api record names caller sandbox_token:%s: %+v", tok.TokenID, sink.records())
	}
}

// Every way to misuse a good token is refused at the edge before the
// toolbox sees anything: another sandbox, another path, another method,
// every route that is not the toolbox (it can never mint, read or delete),
// and every facade.
func TestSandboxTokenScopeRefusals(t *testing.T) {
	srv, _, up, _ := sandboxTokenServer(t, true, ownedSandbox("sb-a", "payments"), ownedSandbox("sb-b", "payments"))
	_, tok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m","path_prefix":"/files","methods":["GET","POST"]}`)
	_, portTok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m","port":3000}`)
	if tok.Token == "" || portTok.Token == "" {
		t.Fatal("issue failed")
	}
	cases := []struct {
		name, method, path, bearer, body string
		status                           int
		reason                           string
	}{
		{"another sandbox", http.MethodGet, "/v1/sandboxes/sb-b/toolbox/files", tok.Token, "", http.StatusForbidden, ": sandbox"},
		{"a path outside the prefix", http.MethodPost, "/v1/sandboxes/sb-a/toolbox/process/execute", tok.Token, `{}`, http.StatusForbidden, "path"},
		{"a sibling of the prefix", http.MethodGet, "/v1/sandboxes/sb-a/toolbox/files-x", tok.Token, "", http.StatusForbidden, "path"},
		{"an encoded dot-dot escape", http.MethodGet, "/v1/sandboxes/sb-a/toolbox/files%2F..%2Fprocess", tok.Token, "", http.StatusForbidden, "path"},
		{"a method not listed", http.MethodDelete, "/v1/sandboxes/sb-a/toolbox/files", tok.Token, "", http.StatusForbidden, "method"},
		{"sessions outside the prefix", http.MethodGet, "/v1/sandboxes/sb-a/sessions", tok.Token, "", http.StatusForbidden, "path"},
		{"a port token on the toolbox", http.MethodGet, "/v1/sandboxes/sb-a/toolbox/files", portTok.Token, "", http.StatusForbidden, "port"},
		{"get the sandbox", http.MethodGet, "/v1/sandboxes/sb-a", tok.Token, "", http.StatusForbidden, "toolbox"},
		{"list sandboxes", http.MethodGet, "/v1/sandboxes", tok.Token, "", http.StatusForbidden, "toolbox"},
		{"mint another token", http.MethodPost, "/v1/sandboxes/sb-a/tokens", tok.Token, `{"expires_in":"1h"}`, http.StatusForbidden, "toolbox"},
		{"delete the sandbox", http.MethodDelete, "/v1/sandboxes/sb-a", tok.Token, "", http.StatusForbidden, "toolbox"},
		{"expose a port", http.MethodPost, "/v1/sandboxes/sb-a/ports/80", tok.Token, "", http.StatusForbidden, "toolbox"},
		{"whoami", http.MethodGet, "/v1/whoami", tok.Token, "", http.StatusForbidden, "toolbox"},
		{"the Daytona toolbox", http.MethodGet, "/daytona/toolbox/sb-a/files", tok.Token, "", http.StatusForbidden, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, tc.method, tc.path, tc.bearer, tc.body, nil)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.reason) {
				t.Fatalf("%s %s = %d %s, want %d naming %q", tc.method, tc.path, rec.Code, rec.Body.String(), tc.status, tc.reason)
			}
			if strings.Contains(rec.Body.String(), tok.Token) {
				t.Fatal("the refusal echoes the token")
			}
		})
	}
	if paths, _ := up.seen(); len(paths) != 0 {
		t.Fatalf("a refused request reached the toolbox: %v", paths)
	}

	// The E2B and Runloop surfaces read the same credential and refuse it.
	for _, path := range []string{"/e2b/sandboxes", "/runloop/v1/devboxes"} {
		if rec := do(t, srv, http.MethodGet, path, tok.Token, "", map[string]string{"X-API-KEY": tok.Token}); rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s accepted a sandbox token: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// Bad tokens are 401s with a fixed D17 reason, on any node, and never
// fall through to the managed provider.
func TestSandboxTokenCredentialRefusals(t *testing.T) {
	srv, cipher, up, _ := sandboxTokenServer(t, false, ownedSandbox("sb-a", "payments"))
	_, tok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m"}`)
	sign := func(c sandboxtoken.Claims) string {
		raw, _, err := sandboxtoken.Sign(cipher, c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	now := time.Now()
	base := sandboxtoken.Claims{TokenID: "stk_00000000000000000000000000000000", SandboxID: "sb-a", Owner: "team:payments"}
	expired := base
	expired.IssuedAt, expired.ExpiresAt = now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()
	future := base
	future.IssuedAt, future.ExpiresAt = now.Add(time.Hour).Unix(), now.Add(90*time.Minute).Unix()
	tooLong := base
	tooLong.IssuedAt, tooLong.ExpiresAt = now.Unix(), now.Add(2*time.Hour).Unix()
	otherKey, _ := secrets.NewCipher("", filepath.Join(t.TempDir(), "other"))
	foreign, _, _ := sandboxtoken.Sign(otherKey, func() sandboxtoken.Claims {
		c := base
		c.IssuedAt, c.ExpiresAt = now.Unix(), now.Add(time.Minute).Unix()
		return c
	}())
	tampered := tok.Token[:len(tok.Token)-3] + "AAA"

	for _, tc := range []struct {
		name, bearer, reason string
	}{
		{"expired", sign(expired), "expired"},
		{"issued in the future", sign(future), "not_yet_valid"},
		{"longer than the cap", sign(tooLong), "too_long_lived"},
		{"another server key", foreign, "invalid_signature"},
		{"tampered signature", tampered, "invalid_signature"},
		{"malformed", sandboxtoken.Prefix + "garbage", "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, srv, http.MethodGet, "/v1/sandboxes/sb-a/toolbox/files", tc.bearer, "", nil)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error_description="`+tc.reason+`"`) ||
				!strings.Contains(rec.Body.String(), `"reason":"`+tc.reason+`"`) {
				t.Fatalf("%d %q %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
			}
		})
	}
	if paths, _ := up.seen(); len(paths) != 0 {
		t.Fatalf("a refused token reached the toolbox: %v", paths)
	}
}

// A token works over the WebSocket bearer smuggle the SDKs use for
// sessions, and the smuggled token is stripped before the sandbox.
func TestSandboxTokenOnTheWebSocketSubprotocol(t *testing.T) {
	srv, _, up, _ := sandboxTokenServer(t, false, ownedSandbox("sb-a", "payments"))
	_, tok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m","path_prefix":"/sessions"}`)
	rec := do(t, srv, http.MethodGet, "/v1/sandboxes/sb-a/sessions/abc", "", "", map[string]string{"Sec-WebSocket-Protocol": "sandbox.bearer, " + tok.Token})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("sessions over the subprotocol: %d %s", rec.Code, rec.Body.String())
	}
	if paths, auths := up.seen(); len(paths) != 1 || paths[0] != "GET /sessions/abc" || auths[0] != "Bearer toolbox-secret-sb-a" {
		t.Fatalf("toolboxd saw %v %v", paths, auths)
	}
}

// Issuing needs sandbox.exec and owner visibility: a viewer cannot, a
// runner of another team gets 404, a bad request is a 400 naming the
// field.
func TestIssueSandboxTokenRoute(t *testing.T) {
	srv, _, _, sink := sandboxTokenServer(t, true, ownedSandbox("sb-a", "payments"))
	for _, tc := range []struct {
		name, bearer, body string
		status             int
		contains           string
	}{
		{"viewer", "avm_viewer", `{"expires_in":"1m"}`, http.StatusForbidden, "sandbox.exec"},
		{"runner of another team", "avm_growth", `{"expires_in":"1m"}`, http.StatusNotFound, "not found"},
		{"no lifetime", "pat-token", `{}`, http.StatusBadRequest, "expires_in is required"},
		{"over the cap", "pat-token", `{"expires_in":"2h"}`, http.StatusBadRequest, "SB_SANDBOX_TOKEN_MAX_TTL"},
		{"bad JSON", "pat-token", `{`, http.StatusBadRequest, "invalid JSON"},
		{"unknown sandbox", "pat-token", `{"expires_in":"1m"}`, http.StatusNotFound, "not found"},
		{"runner of the team", "avm_runner", `{"expires_in":"1m"}`, http.StatusCreated, sandboxtoken.Prefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "sb-a"
			if tc.name == "unknown sandbox" {
				id = "sb-none"
			}
			rec := do(t, srv, http.MethodPost, "/v1/sandboxes/"+id+"/tokens", tc.bearer, tc.body, nil)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.contains) {
				t.Fatalf("%d %s, want %d with %q", rec.Code, rec.Body.String(), tc.status, tc.contains)
			}
		})
	}
	// The issue call's api record names the token id as its target.
	var tok models.SandboxToken
	rec := do(t, srv, http.MethodPost, "/v1/sandboxes/sb-a/tokens", "pat-token", `{"expires_in":"1m"}`, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range sink.records() {
			if ev.Kind == auditlog.KindAPI && ev.Request != nil && ev.Request.Target == tok.TokenID {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no api record targets %s", tok.TokenID)
}

func TestSandboxTokenAuthenticatorUnits(t *testing.T) {
	// Not a sandbox token: not mine.
	if _, matched, _ := (sandboxTokenAuthenticator{}).Authenticate(nil, "avm_x"); matched {
		t.Fatal("claimed an avm_ token")
	}
	// No verifier: claimed and refused, never passed on.
	_, matched, err := (sandboxTokenAuthenticator{}).Authenticate(nil, sandboxtoken.Prefix+"x")
	if ce, ok := controlplane.AsCredentialError(err); !matched || !ok || ce.Reason != controlplane.RejectInvalidSignature {
		t.Fatalf("no verifier: matched %v err %v", matched, err)
	}
	if got := sandboxTokenReason(errors.New("odd")); got != controlplane.RejectMalformed {
		t.Fatalf("an unexpected error maps to %q", got)
	}
	// A server with no service claims and refuses avmst_ bearers.
	bare := &Server{patToken: "pat-token"}
	if _, f := bare.authenticate(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), sandboxtoken.Prefix+"1.a.b"); f == nil || f.status != http.StatusUnauthorized {
		t.Fatalf("bare server: %+v", f)
	}
	// The scope step with no claims, and a scope error without a part.
	a := controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalSandboxToken}}
	if _, err := enforceSandboxTokenScope(httptest.NewRequest(http.MethodGet, "/", nil), a); !errors.Is(err, errSandboxTokenRoute) {
		t.Fatalf("no claims: %v", err)
	}
	if scopePart(sandboxtoken.ErrOutOfScope) != "request" {
		t.Fatal("scopePart fallback")
	}
}
