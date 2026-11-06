//go:build integration

package suite

// Live checks for plans/agent-sandbox-feature-parity.md section 5.11 (the
// images and recipes lane): G12 the E2B mcp option and an MCP server run as
// a session, G8 the computer-use image, G10 the code-server image. Each
// check does what its docs page tells a reader to do.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// recipesHTTP sends one request to a sandbox's public URL and reads the
// answer. It does not follow redirects: a token gate answers with one.
func recipesHTTP(t *testing.T, method, target string, headers map[string]string, body []byte) (int, string) {
	t.Helper()
	hc := *harness.HTTPClient(60 * time.Second)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rdr)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, target, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		// A route that is not live yet can reset the connection; the
		// callers poll, so a network error reads as "not yet".
		return 0, err.Error()
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(out)
}

// recipesPoll calls try until it reports done or the deadline passes, and
// fails with the last answer it saw.
func recipesPoll(t *testing.T, what string, within time.Duration, try func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		done, last := try()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: gave up after %v; last answer: %s", what, within, last)
		}
		time.Sleep(3 * time.Second)
	}
}

func recipesExec(t *testing.T, ctx context.Context, sb *microvm.Sandbox, command string, timeoutSeconds int) {
	t.Helper()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: command, TimeoutSeconds: timeoutSeconds})
	if err != nil {
		t.Fatalf("exec %q: %v", command, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exec %q exit %d\nstdout: %s\nstderr: %s", command, res.ExitCode, res.Stdout, res.Stderr)
	}
}

// mcpInitialize is the first JSON-RPC call every MCP client makes.
var mcpInitialize = []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"aerolvm-itest","version":"1"}}}`)

func mcpHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// UC-463 — the E2B SDK's mcp option through the live E2B facade (plan G12):
// E2B's own mcp-gateway template is refused with a 501 that names it; with
// a template AerolVM has, the create succeeds, port 50005 is exposed public
// (E2B's gateway checks its own token), and a server the client starts on
// 50005, as the E2B SDK starts mcp-gateway, answers on that URL.
func TestParityE2BMCPOption(t *testing.T) {
	harness.Require(t, sc, "UC-463")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes", map[string]any{
		"templateID": "mcp-gateway",
		"mcp":        map[string]any{"exa": map[string]any{"apiKey": "not-a-real-key"}},
	}, nil)
	if st != http.StatusNotImplemented || !strings.Contains(string(body), "mcp-gateway template is not available") {
		t.Fatalf("create with E2B's mcp-gateway template = %d %s, want a 501 naming the missing gateway", st, body)
	}

	st, body = fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes", map[string]any{
		"templateID": "base",
		"timeout":    600,
		"mcp":        map[string]any{"github/acme/tools": map[string]any{"runCmd": "node server.js"}},
	}, nil)
	if st != http.StatusCreated {
		t.Fatalf("E2B create with mcp = %d, want 201; body=%s", st, body)
	}
	var created struct {
		SandboxID string `json:"sandboxID"`
	}
	fcDecode(t, body, &created)
	destroySandbox(t, created.SandboxID)

	sb, err := client(t).SDK().Get(ctx, created.SandboxID)
	if err != nil {
		t.Fatalf("get the E2B sandbox through v1: %v", err)
	}
	waitRunning(t, sb)
	var gatewayURL string
	for _, p := range sb.ExposedPorts {
		if p.Port == 50005 {
			if p.TokenGated() {
				t.Fatalf("gateway port %+v is token-gated; the E2B SDK cannot send a sandbox token", p)
			}
			gatewayURL = p.PublicURL
		}
	}
	if gatewayURL == "" {
		t.Fatalf("port 50005 not exposed after an mcp create: %+v", sb.ExposedPorts)
	}

	// A stand-in for E2B's gateway: base is ubuntu:22.04, whose perl can
	// serve one HTTP answer per connection on 50005. It reads the whole
	// request head first: closing with unread bytes would reset the
	// connection before the proxy read the answer.
	const standIn = `perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(LocalPort=>50005,Listen=>16,ReuseAddr=>1) or die $!; while($c=$s->accept){while(<$c>){last if /^\r?$/} print $c "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\nConnection: close\r\n\r\naerolvm-mcp-standin"; close $c}'`
	if _, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{Name: "mcp-gateway", Command: standIn}); err != nil {
		t.Fatalf("start the stand-in gateway: %v", err)
	}
	recipesPoll(t, "the gateway URL answers", 2*time.Minute, func() (bool, string) {
		st, got := recipesHTTP(t, http.MethodGet, strings.TrimRight(gatewayURL, "/")+"/mcp", nil, nil)
		return st == http.StatusOK && strings.Contains(got, "aerolvm-mcp-standin"), got
	})
}

// UC-466 — the "Host an MCP server" recipe (plan G12): an MCP server started
// as a session behind supergateway answers a JSON-RPC initialize through
// its exposed port with the key, refuses a request without it, and once the
// port is exposed with visibility token, needs the sandbox token as well.
func TestParityMCPServerAsSession(t *testing.T) {
	harness.Require(t, sc, "UC-466")
	c := client(t)
	key := "uc466-" + harness.UniqueName(sc, t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:  harness.UniqueName(sc, t),
		Image: "node:22-bookworm",
		Env:   map[string]string{"MCP_API_KEY": key},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	recipesExec(t, ctx, sb, "npm install -g supergateway@4.2.1 @modelcontextprotocol/server-filesystem@2.2.0 && mkdir -p /workspace", 600)
	if _, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name: "mcp",
		Command: `supergateway --stdio "mcp-server-filesystem /workspace"` +
			` --outputTransport streamableHttp --port 8000 --apiKey "$MCP_API_KEY"`,
	}); err != nil {
		t.Fatalf("start the MCP server session: %v", err)
	}
	exposure, err := sb.ExposePort(ctx, 8000)
	if err != nil {
		t.Fatalf("expose 8000: %v", err)
	}
	mcpURL := strings.TrimRight(exposure.PublicURL, "/") + "/mcp"
	withKey := map[string]string{"Authorization": "Bearer " + key}

	recipesPoll(t, "initialize with the key", 3*time.Minute, func() (bool, string) {
		st, got := recipesHTTP(t, http.MethodPost, mcpURL, mcpHeaders(withKey), mcpInitialize)
		return st == http.StatusOK && strings.Contains(got, `"serverInfo"`) && strings.Contains(got, "secure-filesystem-server"), got
	})
	if st, got := recipesHTTP(t, http.MethodPost, mcpURL, mcpHeaders(nil), mcpInitialize); st != http.StatusUnauthorized {
		t.Fatalf("initialize without the key = %d %s, want 401 from supergateway", st, got)
	}

	if _, err := sb.ExposePort(ctx, 8000, microvm.WithVisibility(sdktypes.ExposeVisibilityToken)); err != nil {
		t.Fatalf("re-expose 8000 with visibility token: %v", err)
	}
	tok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{Port: 8000, ExpiresIn: "10m"})
	recipesPoll(t, "the gate refuses the key alone", 90*time.Second, func() (bool, string) {
		st, got := recipesHTTP(t, http.MethodPost, mcpURL, mcpHeaders(withKey), mcpInitialize)
		if st == http.StatusOK {
			return false, "still open: " + got
		}
		return st == http.StatusUnauthorized && !strings.Contains(got, "serverInfo"), got
	})
	both := map[string]string{"Authorization": "Bearer " + key, "Cookie": "__Host-aerolvm-token=" + tok.Token}
	if st, got := recipesHTTP(t, http.MethodPost, mcpURL, mcpHeaders(both), mcpInitialize); st != http.StatusOK || !strings.Contains(got, `"serverInfo"`) {
		t.Fatalf("initialize with the key and the token cookie = %d %s", st, got)
	}
}

// repoDockerfile reads images/<name>/Dockerfile from this checkout, so the
// live check builds exactly the file the docs tell readers to build. The
// suite runs from integration-tests/suite.
func repoDockerfile(t *testing.T, name string) *microvm.Image {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "images", name, "Dockerfile"))
	if err != nil {
		t.Fatalf("read images/%s/Dockerfile: %v", name, err)
	}
	img := microvm.FromDockerfile(string(data))
	if err := img.Err(); err != nil {
		t.Fatalf("images/%s/Dockerfile: %v", name, err)
	}
	return img
}

// recipesImageSandbox builds a repo image on the server with the SDK's
// image builder and creates a sandbox from it, as the docs do. Builds of
// these images download hundreds of MB, so the deadline is generous.
func recipesImageSandbox(t *testing.T, ctx context.Context, name string, opts sdktypes.CreateSandboxOptions) *microvm.Sandbox {
	t.Helper()
	c := client(t)
	opts.Name = harness.UniqueName(sc, t)
	sb, err := c.SDK().CreateWithImage(ctx, repoDockerfile(t, name), opts)
	if err != nil {
		t.Fatalf("build images/%s and create from it: %v", name, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)
	return sb
}

// recipesExecOut runs a command and returns its trimmed stdout, failing on
// a transport error only (callers poll on the output).
func recipesExecOut(t *testing.T, ctx context.Context, sb *microvm.Sandbox, command string) string {
	t.Helper()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: command, TimeoutSeconds: 120})
	if err != nil {
		t.Fatalf("exec %q: %v", command, err)
	}
	return strings.TrimSpace(res.Stdout + res.Stderr)
}

// UC-464 — the computer-use image (plan G8): images/computer-use/Dockerfile
// builds on the server through the SDK's image builder; in a sandbox from
// it, Chrome's DevTools answers on 127.0.0.1:9222, noVNC serves on 6080, and
// the docs' Playwright script drives the browser over CDP and writes a PNG.
func TestParityComputerUseImage(t *testing.T) {
	harness.Require(t, sc, "UC-464")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	sb := recipesImageSandbox(t, ctx, "computer-use", sdktypes.CreateSandboxOptions{CPU: 2, MemoryMB: 2048})

	recipesPoll(t, "DevTools on 9222", 2*time.Minute, func() (bool, string) {
		out := recipesExecOut(t, ctx, sb, "curl -s http://127.0.0.1:9222/json/version")
		return strings.Contains(out, "webSocketDebuggerUrl") && strings.Contains(out, "Chrome/"), out
	})
	if out := recipesExecOut(t, ctx, sb, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:6080/vnc.html"); out != "200" {
		t.Fatalf("noVNC on 6080 = %q, want 200", out)
	}
	if out := recipesExecOut(t, ctx, sb, "id -u"); out != "1000" {
		t.Fatalf("commands run as uid %q, want the image's non-root user 1000", out)
	}

	script := `from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
    page = browser.contexts[0].new_page()
    page.set_content("<h1>uc464 from AerolVM</h1>")
    print(page.inner_text("h1"))
    page.screenshot(path="/tmp/uc464.png")
    page.close()
`
	if err := sb.UploadFile(ctx, "/tmp/uc464.py", []byte(script)); err != nil {
		t.Fatalf("upload the Playwright script: %v", err)
	}
	if out := recipesExecOut(t, ctx, sb, "python3 /tmp/uc464.py"); !strings.Contains(out, "uc464 from AerolVM") {
		t.Fatalf("Playwright over CDP printed %q", out)
	}
	png, err := sb.DownloadFile(ctx, "/tmp/uc464.png")
	if err != nil {
		t.Fatalf("download the screenshot: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("screenshot is not a PNG (%d bytes)", len(png))
	}
}

// UC-465 — the code-server image (plan G10): images/code-server/Dockerfile
// builds on the server through the SDK's image builder; the editor answers
// on 8080 inside the sandbox as uid 1000 with no sudo; and once 8080 is
// exposed with visibility token, its public URL is a 401 without a token
// and serves code-server's health check with the token cookie.
func TestParityCodeServerImage(t *testing.T) {
	harness.Require(t, sc, "UC-465")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	sb := recipesImageSandbox(t, ctx, "code-server", sdktypes.CreateSandboxOptions{CPU: 2, MemoryMB: 2048})

	recipesPoll(t, "code-server on 8080 inside", 2*time.Minute, func() (bool, string) {
		out := recipesExecOut(t, ctx, sb, "curl -s http://127.0.0.1:8080/healthz")
		return strings.Contains(out, `"status"`), out
	})
	if out := recipesExecOut(t, ctx, sb, "id -u; sudo -n true >/dev/null 2>&1 && echo has-sudo || echo no-sudo"); out != "1000\nno-sudo" {
		t.Fatalf("user and sudo = %q, want uid 1000 without sudo", out)
	}

	exposure, err := sb.ExposePort(ctx, 8080, microvm.WithVisibility(sdktypes.ExposeVisibilityToken))
	if err != nil {
		t.Fatalf("expose 8080 with visibility token: %v", err)
	}
	health := strings.TrimRight(exposure.PublicURL, "/") + "/healthz"
	recipesPoll(t, "the editor URL refuses a visitor without a token", 90*time.Second, func() (bool, string) {
		st, got := recipesHTTP(t, http.MethodGet, health, nil, nil)
		if st == http.StatusOK {
			t.Fatalf("the editor answered without a token: %s", got)
		}
		return st == http.StatusUnauthorized, got
	})
	tok := issueSandboxToken(t, ctx, sb, sdktypes.CreateSandboxTokenOptions{Port: 8080, ExpiresIn: "10m"})
	cookie := map[string]string{"Cookie": "__Host-aerolvm-token=" + tok.Token}
	// Only Caddy's own catch-all ("Sandbox not found", for a host with no
	// route) is retried: on a single node with per-sandbox Caddy routes the
	// port's route once went missing for a moment right after it had
	// answered 401 (single-node-fc, 2026-11-06; TODOS.md). Any other
	// answer fails at once.
	recipesPoll(t, "health with the token cookie", 60*time.Second, func() (bool, string) {
		st, got := recipesHTTP(t, http.MethodGet, health, cookie, nil)
		if st == http.StatusNotFound && strings.Contains(got, "Sandbox not found") {
			t.Logf("health with the token cookie hit the route-less fallback; retrying: %s", got)
			return false, got
		}
		if st != http.StatusOK || !strings.Contains(got, `"status"`) {
			t.Fatalf("health with the token cookie = %d %s", st, got)
		}
		return true, got
	})
}
