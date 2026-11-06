//go:build integration

package suite

// Live checks for plans/agent-sandbox-feature-parity.md §5.9 (A1–A3):
// signed per-sandbox tokens, token-gated public ports and trace context
// into toolboxd. Each use case maps to one plan item.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// tokenDo sends one request through baseURL (empty: the scenario's ingress)
// with a sandbox token as the bearer instead of the scenario's credential.
func tokenDo(t *testing.T, ctx context.Context, method, baseURL, path, token string, body any) (int, []byte) {
	t.Helper()
	return fcDo(t, ctx, method, baseURL, path, body, map[string]string{"Authorization": "Bearer " + token})
}

func downloadPath(sandboxID, file string) string {
	return "/v1/sandboxes/" + sandboxID + "/toolbox/files/download?path=" + url.QueryEscape(file)
}

// issueSandboxToken makes a token through the Go SDK and checks its shape.
func issueSandboxToken(t *testing.T, ctx context.Context, sb *microvm.Sandbox, opts sdktypes.CreateSandboxTokenOptions) sdktypes.SandboxToken {
	t.Helper()
	tok, err := sb.CreateToken(ctx, opts)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if !strings.HasPrefix(tok.Token, "avmst_") || !strings.HasPrefix(tok.TokenID, "stk_") || tok.SandboxID != sb.ID {
		t.Fatalf("token = id %q sandbox %q (token prefix ok: %v)", tok.TokenID, tok.SandboxID, strings.HasPrefix(tok.Token, "avmst_"))
	}
	return tok
}

// UC-423 — a sandbox token works on its own sandbox's toolbox, inside its
// path prefix and methods: a read-only /files token downloads a file.
func TestParitySandboxTokenToolbox(t *testing.T) {
	harness.Require(t, sc, "UC-423")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/tmp/uc423.txt", []byte("uc423-content")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	tok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", PathPrefix: "/files", Methods: []string{"GET"}})

	st, body := tokenDo(t, ctx, http.MethodGet, "", downloadPath(sb.ID, "/tmp/uc423.txt"), tok.Token, nil)
	if st != http.StatusOK || string(body) != "uc423-content" {
		t.Fatalf("download with the token = %d %q", st, body)
	}

	// A /sessions token as an SDK credential, the docs' example: the
	// client-level calls that take a sandbox id work.
	sessTok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", PathPrefix: "/sessions"})
	user, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: sc.BaseURL, PATToken: sessTok.Token, HTTPClient: harness.HTTPClient(0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.ListSessions(ctx, sb.ID); err != nil {
		t.Fatalf("SDK ListSessions with a /sessions token: %v", err)
	}
}

// UC-424 — the same token is refused on another sandbox, on a path or a
// method it does not cover, on every non-toolbox route (it cannot mint
// another token), and once it has expired (plus the 30 s clock skew).
func TestParitySandboxTokenRefusals(t *testing.T) {
	harness.Require(t, sc, "UC-424")
	sb := paritySandbox(t)
	other := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", PathPrefix: "/files", Methods: []string{"GET"}})

	for _, tc := range []struct {
		name, method, path string
		body               any
		want               int
		part               string
	}{
		{"another sandbox", http.MethodGet, downloadPath(other.ID, "/etc/hostname"), nil, http.StatusForbidden, "sandbox"},
		// GET, a listed method, so only the path is outside the token.
		{"a path outside the prefix", http.MethodGet, "/v1/sandboxes/" + sb.ID + "/toolbox/version", nil, http.StatusForbidden, "path"},
		{"a method not listed", http.MethodPost, "/v1/sandboxes/" + sb.ID + "/toolbox/files/upload", map[string]any{}, http.StatusForbidden, "method"},
		{"a sandbox read", http.MethodGet, "/v1/sandboxes/" + sb.ID, nil, http.StatusForbidden, "toolbox"},
		{"minting another token", http.MethodPost, "/v1/sandboxes/" + sb.ID + "/tokens", map[string]any{"expires_in": "1h"}, http.StatusForbidden, "toolbox"},
		{"a delete", http.MethodDelete, "/v1/sandboxes/" + sb.ID, nil, http.StatusForbidden, "toolbox"},
	} {
		st, body := tokenDo(t, ctx, tc.method, "", tc.path, tok.Token, tc.body)
		if st != tc.want || !strings.Contains(string(body), tc.part) {
			t.Fatalf("%s: %d %s, want %d naming %q", tc.name, st, body, tc.want, tc.part)
		}
		if strings.Contains(string(body), tok.Token) {
			t.Fatalf("%s: the refusal echoes the token", tc.name)
		}
	}
	if _, err := sb.ExecCommand(ctx, "true"); err != nil {
		t.Fatalf("the sandbox was harmed by the refused calls: %v", err)
	}

	short := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "2s", PathPrefix: "/files"})
	if st, body := tokenDo(t, ctx, http.MethodGet, "", downloadPath(sb.ID, "/etc/hostname"), short.Token, nil); st != http.StatusOK {
		t.Fatalf("a fresh short token = %d %s", st, body)
	}
	time.Sleep(2*time.Second + 31*time.Second)
	st, body := tokenDo(t, ctx, http.MethodGet, "", downloadPath(sb.ID, "/etc/hostname"), short.Token, nil)
	if st != http.StatusUnauthorized || !strings.Contains(string(body), "expired") {
		t.Fatalf("an expired token = %d %s, want 401 expired", st, body)
	}
}

// UC-425 — a token issued through one node works through another: every
// node derives the same signing key from the shared server key, so no node
// needs a database call or a peer to check it.
func TestParitySandboxTokenAcrossNodes(t *testing.T) {
	harness.Require(t, sc, "UC-425")
	targets := identityTargets(t)
	if len(targets.Nodes) < 2 {
		t.Skip("needs two nodes")
	}
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/tmp/uc425.txt", []byte("uc425")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	bases := make([]string, 0, len(targets.Nodes))
	for _, node := range targets.Nodes {
		bases = append(bases, nodeBase(t, node))
	}
	for i, issueBase := range bases {
		resp, err := harness.NewAPIClient(issueBase, sc.OperatorPAT).Do(ctx, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/tokens",
			map[string]any{"expires_in": "10m", "path_prefix": "/files", "methods": []string{"GET"}})
		if err != nil || resp.Status != http.StatusCreated {
			t.Fatalf("issue through %s: %v %s", targets.Nodes[i].Name, err, resp)
		}
		var tok sdktypes.SandboxToken
		if err := json.Unmarshal(resp.Body, &tok); err != nil {
			t.Fatal(err)
		}
		for j, useBase := range bases {
			st, body := tokenDo(t, ctx, http.MethodGet, useBase, downloadPath(sb.ID, "/tmp/uc425.txt"), tok.Token, nil)
			if st != http.StatusOK || string(body) != "uc425" {
				t.Fatalf("token from %s used through %s = %d %q", targets.Nodes[i].Name, targets.Nodes[j].Name, st, body)
			}
		}
	}
}

// UC-468 — revoking a sandbox's tokens: a token that works is refused right
// after the revoke, and one issued right after it works. In a cluster the
// revoke is written in the owner's row, so both must hold whichever node
// the request lands on (each forwards the toolbox call to the owner).
func TestParitySandboxTokenRevoke(t *testing.T) {
	harness.Require(t, sc, "UC-468")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/tmp/uc468.txt", []byte("uc468")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	file := downloadPath(sb.ID, "/tmp/uc468.txt")
	scope := sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", PathPrefix: "/files", Methods: []string{"GET"}}
	old := issueSandboxToken(t, ctx, sb, scope)
	if st, body := tokenDo(t, ctx, http.MethodGet, "", file, old.Token, nil); st != http.StatusOK || string(body) != "uc468" {
		t.Fatalf("before the revoke = %d %q", st, body)
	}

	revoked, err := sb.RevokeTokens(ctx)
	if err != nil || revoked.SandboxID != sb.ID || revoked.TokensNotBefore.IsZero() {
		t.Fatalf("RevokeTokens = %+v, %v", revoked, err)
	}
	fresh := issueSandboxToken(t, ctx, sb, scope)

	// Every node when the scenario lists them, else the scenario's ingress.
	bases := []string{""}
	if targets := harness.LoadIntegrationTargets(); sc.Has(harness.CapCluster) && targets != nil && len(targets.Nodes) > 1 {
		bases = bases[:0]
		for _, node := range targets.Nodes {
			bases = append(bases, nodeBase(t, node))
		}
	}
	for _, base := range bases {
		st, body := tokenDo(t, ctx, http.MethodGet, base, file, old.Token, nil)
		if st != http.StatusUnauthorized || !strings.Contains(string(body), "revoked") || strings.Contains(string(body), old.Token) {
			t.Fatalf("the revoked token through %q = %d %s, want 401 naming revoked", base, st, body)
		}
		if st, body := tokenDo(t, ctx, http.MethodGet, base, file, fresh.Token, nil); st != http.StatusOK || string(body) != "uc468" {
			t.Fatalf("a token issued after the revoke, through %q = %d %q", base, st, body)
		}
	}

	// A second revoke, a whole second later, also refuses the newer token
	// (one issued in the same second as a revoke is lifted to it, so the
	// wait makes this deterministic).
	time.Sleep(1100 * time.Millisecond)
	again, err := sb.RevokeTokens(ctx)
	if err != nil || !again.TokensNotBefore.After(revoked.TokensNotBefore) {
		t.Fatalf("second RevokeTokens = %+v, %v; want a later not-before than %s", again, err, revoked.TokensNotBefore)
	}
	for name, tok := range map[string]string{"old": old.Token, "newer": fresh.Token} {
		if st, body := tokenDo(t, ctx, http.MethodGet, "", file, tok, nil); st != http.StatusUnauthorized || !strings.Contains(string(body), "revoked") {
			t.Fatalf("the %s token after the second revoke = %d %s", name, st, body)
		}
	}
	if _, err := sb.ExecCommand(ctx, "true"); err != nil {
		t.Fatalf("the revokes harmed the sandbox: %v", err)
	}
}

// publicGet sends one GET to a public URL without following redirects.
func publicGet(t *testing.T, target, cookie string) (int, http.Header, string) {
	t.Helper()
	hc := *harness.HTTPClient(30 * time.Second)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	return resp.StatusCode, resp.Header, string(body[:n])
}

// UC-426 — a port exposed with visibility "token": without a token it is a
// 401 (never the app); ?token= sets the host-only __Host- cookie and 302s
// to the URL without the token; the cookie then reaches the app; another
// sandbox's token and a toolbox token are refused; a plain re-expose keeps
// the gate; the toolboxd /proxy/<port>/ path does not serve it.
func TestParityTokenGatedPort(t *testing.T) {
	harness.Require(t, sc, "UC-426")
	c := client(t)
	sb := privateHTTPServerSandbox(t, c)
	other := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	res, err := sb.ExposePort(ctx, 8080, microvm.WithVisibility(sdktypes.ExposeVisibilityToken))
	if err != nil {
		t.Fatalf("expose with token visibility: %v", err)
	}
	if res.Visibility != "token" || res.PublicURL == "" {
		t.Fatalf("expose = %+v", res)
	}
	tok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", Port: 8080})

	// Wait for the route: until it is live the answer is a 404 or a 5xx.
	deadline := time.Now().Add(90 * time.Second)
	for {
		st, _, body := publicGet(t, res.PublicURL, "")
		if st == http.StatusUnauthorized {
			break
		}
		if st == http.StatusOK {
			t.Fatalf("the token port answered without a token: %s", body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("token port never answered 401: last %d %s", st, body)
		}
		time.Sleep(3 * time.Second)
	}

	st, hdr, body := publicGet(t, res.PublicURL+"?a=1&token="+tok.Token, "")
	if st != http.StatusFound {
		t.Fatalf("?token= = %d %s, want 302", st, body)
	}
	if loc := hdr.Get("Location"); strings.Contains(loc, "token") || !strings.HasSuffix(loc, "?a=1") {
		t.Fatalf("Location = %q, want the URL without the token", loc)
	}
	setCookie := hdr.Get("Set-Cookie")
	for _, want := range []string{"__Host-aerolvm-token=", "Secure", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("Set-Cookie lacks %q (has the attributes: %v)", want, strings.Contains(setCookie, "Secure"))
		}
	}
	if strings.Contains(strings.ToLower(setCookie), "domain=") {
		t.Fatal("the cookie names a Domain")
	}
	cookie := "__Host-aerolvm-token=" + tok.Token
	if st, _, body := publicGet(t, res.PublicURL, cookie); st != http.StatusOK {
		t.Fatalf("with the cookie = %d %s", st, body)
	}

	otherTok := issueSandboxToken(t, ctx, other, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m", Port: 8080})
	toolboxTok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{ExpiresIn: "10m"})
	for name, bad := range map[string]string{"another sandbox's token": otherTok.Token, "a toolbox token": toolboxTok.Token} {
		if st, _, body := publicGet(t, res.PublicURL+"?token="+bad, ""); st != http.StatusForbidden {
			t.Fatalf("%s = %d %s, want 403", name, st, body)
		}
		if st, _, _ := publicGet(t, res.PublicURL, "__Host-aerolvm-token="+bad); st != http.StatusForbidden {
			t.Fatalf("%s as a cookie = %d, want 403", name, st)
		}
	}

	// A retry that names no visibility keeps the gate.
	if again, err := sb.ExposePort(ctx, 8080); err != nil || again.Visibility != "token" {
		t.Fatalf("plain re-expose = %+v, %v", again, err)
	}
	if st, _, _ := publicGet(t, res.PublicURL, ""); st != http.StatusUnauthorized {
		t.Fatalf("after a plain re-expose = %d, want 401", st)
	}

	// The path form through toolboxd never serves a gated port.
	if root, err := url.Parse(res.PublicURL); err == nil {
		host := strings.Replace(root.Host, sb.ID+"-8080.", sb.ID+".", 1)
		if st, _, body := publicGet(t, root.Scheme+"://"+host+"/proxy/8080/", ""); st == http.StatusOK {
			t.Fatalf("/proxy/8080/ served the gated port: %s", body)
		}
	}
}

// UC-427 — sandboxd forwards W3C trace context to toolboxd: an exec sent
// with a traceparent is logged by toolboxd with that trace id. toolboxd
// logs to the container's output, which the suite reads over SSH on the
// sandbox's owner node: `docker logs` on the dockerd engine, the task log
// under /var/lib/sandboxd/containerd/logs on the containerd engine.
func TestParityToolboxLogsTraceID(t *testing.T) {
	harness.Require(t, sc, "UC-427")
	targets := identityTargets(t)
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	traceID := hex.EncodeToString(raw[:])
	traceparent := "00-" + traceID + "-00f067aa0ba902b7-01"
	st, body := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes/"+sb.ID+"/toolbox/process/execute",
		map[string]any{"command": "true"}, map[string]string{"traceparent": traceparent})
	if st != http.StatusOK {
		t.Fatalf("exec = %d %s", st, body)
	}

	// Every node is searched: the owner lookup can miss (and used to fall
	// back to the first node), and the line is on whichever node runs the
	// sandbox. The task log is named by the sandbox, or by the warm slot it
	// was adopted from, so every log is read.
	script := "id=" + shellQuote(sb.ID) + "; tr=" + shellQuote(traceID) + `
{ sudo docker logs "$id" 2>&1 || true; sudo sh -c 'cat /var/lib/sandboxd/containerd/logs/*.log' 2>/dev/null || true; } | grep -c "trace_id=$tr" || true`
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, node := range targets.Nodes {
			if out := strings.TrimSpace(nodeSSH(t, node, script)); out != "" && out != "0" {
				return
			}
		}
		if time.Now().After(deadline) {
			// Say what is there, so a failure points at the cause.
			diag := "id=" + shellQuote(sb.ID) + `
echo "-- docker:"; sudo docker logs --tail 5 "$id" 2>&1 | tail -5
echo "-- containerd logs:"; sudo sh -c 'ls -la /var/lib/sandboxd/containerd/logs/ 2>&1 | tail -8'
echo "-- this sandbox's log:"; sudo sh -c "tail -5 /var/lib/sandboxd/containerd/logs/$id.log 2>&1"`
			for _, node := range targets.Nodes {
				t.Logf("UC-427 %s:\n%s", node.Name, nodeSSH(t, node, diag))
			}
			t.Fatalf("no node logged trace_id=%s for sandbox %s", traceID, sb.ID)
		}
		time.Sleep(3 * time.Second)
	}
}
