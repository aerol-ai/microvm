//go:build integration

package suite

// Live checks for plans/agent-sandbox-feature-parity.md §5.9 (A1–A3):
// signed per-sandbox tokens, token-gated public ports and trace context
// into toolboxd. Each use case maps to one plan item.

import (
	"context"
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
