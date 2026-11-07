package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func revokeTokens(t *testing.T, srv *Server, bearer, sandboxID string) (*httptest.ResponseRecorder, models.RevokeSandboxTokensResponse) {
	t.Helper()
	rec := do(t, srv, http.MethodPost, "/v1/sandboxes/"+sandboxID+"/tokens/revoke", bearer, "", nil)
	var out models.RevokeSandboxTokensResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// Revoking needs what issuing needs (sandbox.exec and owner visibility),
// and a sandbox token cannot revoke. After a revoke the old token is a 401
// "revoked" on the toolbox, as a bearer and over the WebSocket subprotocol,
// and nothing reaches the sandbox; a token issued right after works. The
// call's api record names the sandbox and the route.
func TestRevokeSandboxTokensRoute(t *testing.T) {
	srv, _, up, sink := sandboxTokenServer(t, true, ownedSandbox("sb-a", "payments"))
	_, tok := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m"}`)
	toolbox := func(bearer string, header map[string]string) *httptest.ResponseRecorder {
		return do(t, srv, http.MethodGet, "/v1/sandboxes/sb-a/sessions/abc", bearer, "", header)
	}
	if rec := toolbox(tok.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("before the revoke: %d %s", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name, bearer, id string
		status           int
		contains         string
	}{
		{"viewer", "avm_viewer", "sb-a", http.StatusForbidden, "sandbox.exec"},
		{"runner of another team", "avm_growth", "sb-a", http.StatusNotFound, "not found"},
		{"unknown sandbox", "pat-token", "sb-none", http.StatusNotFound, "not found"},
		{"the sandbox token itself", tok.Token, "sb-a", http.StatusForbidden, "toolbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec, _ := revokeTokens(t, srv, tc.bearer, tc.id); rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.contains) {
				t.Fatalf("%d %s, want %d with %q", rec.Code, rec.Body.String(), tc.status, tc.contains)
			}
		})
	}
	if rec := toolbox(tok.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("a refused revoke revoked: %d %s", rec.Code, rec.Body.String())
	}

	rec, got := revokeTokens(t, srv, "avm_runner", "sb-a")
	if rec.Code != http.StatusOK || got.SandboxID != "sb-a" || got.TokensNotBefore.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	seen, _ := up.seen()
	for name, header := range map[string]map[string]string{
		"bearer":    nil,
		"websocket": {"Sec-WebSocket-Protocol": "sandbox.bearer, " + tok.Token},
	} {
		bearer := tok.Token
		if header != nil {
			bearer = ""
		}
		rec := toolbox(bearer, header)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "revoked") || strings.Contains(rec.Body.String(), tok.Token) {
			t.Fatalf("%s after the revoke: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if now, _ := up.seen(); len(now) != len(seen) {
		t.Fatalf("a revoked token reached the sandbox: %v", now[len(seen):])
	}

	_, fresh := issueToken(t, srv, "pat-token", "sb-a", `{"expires_in":"10m"}`)
	if rec := toolbox(fresh.Token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("a token issued after the revoke: %d %s", rec.Code, rec.Body.String())
	}
	// A retry is safe: same answer shape, never an earlier not-before.
	if rec, again := revokeTokens(t, srv, "pat-token", "sb-a"); rec.Code != http.StatusOK || again.TokensNotBefore.Before(got.TokensNotBefore) {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range sink.records() {
			if ev.Kind == auditlog.KindAPI && ev.Ref == "POST /v1/sandboxes/{id}/tokens/revoke" && ev.SandboxID == "sb-a" &&
				ev.Result == "ok" && ev.Caller != nil && ev.Caller.Kind == string(controlplane.PrincipalToken) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no api record for the revoke: %+v", sink.records())
}

// The cluster path, edge to owner in process: the edge holds no row and
// forwards the issue, the toolbox calls and the revoke to the owner (the
// edge's store stays empty, so a 200 from the revoke is the owner's). The
// owner re-verifies the forwarded bearer into the same token Access, so
// the revoke written in the owner's row refuses a token presented through
// the edge, and a token issued after it works through the edge too.
func TestSandboxTokenRevokeIsForwardedToTheOwner(t *testing.T) {
	up := &toolboxUpstream{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.paths = append(up.paths, r.Method+" "+r.URL.Path)
		up.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	host, port := u.Hostname(), u.Port()

	keyPath := filepath.Join(t.TempDir(), "shared-key")
	ownerCipher, err := secrets.NewCipher("", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	edgeCipher, err := secrets.NewCipher("", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	toolboxPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	clusterCfg := config.Config{IdentityEnabled: true, EnableCluster: true}
	tokens := WithCredentialAuthenticator(controlplane.PrincipalToken, stubTokens())

	ownerStore := storeWith(t, "owner")
	ownerSvc := service.New(config.Config{EnableCluster: true, ToolboxPort: toolboxPort, SandboxTokenMaxTTL: time.Hour}, discardLogger(), ownerStore, nil, nil, nil, ownerCipher, nil, nil)
	sb := ownedSandbox("sb-owned", "payments")
	sb.ContainerIP, sb.ToolboxToken = host, "toolbox-secret"
	if err := ownerStore.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	ownerSvc.AttachCluster(&openGateCluster{peerSideCluster{Noop: cluster.NewNoop("owner-1", "", ""), edge: "edge-1"}})
	owner := NewServer(discardLogger(), ownerSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	edgeStore := storeWith(t, "edge")
	edgeSvc := service.New(config.Config{EnableCluster: true, SandboxTokenMaxTTL: time.Hour}, discardLogger(), edgeStore, nil, nil, nil, edgeCipher, nil, nil)
	edgeSvc.AttachCluster(&forwardingCluster{Noop: cluster.NewNoop("edge-1", "", ""), owner: owner})
	edge := NewServer(discardLogger(), edgeSvc, nil, nil, clusterCfg, "pat-token", nil, tokens)

	toolboxCall := func(bearer string) *httptest.ResponseRecorder {
		return do(t, edge, http.MethodGet, "/v1/sandboxes/sb-owned/toolbox/files", bearer, "", nil)
	}
	rec, tok := issueToken(t, edge, "avm_payments", "sb-owned", `{"expires_in":"10m"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue through the edge: %d %s", rec.Code, rec.Body.String())
	}
	if rec := toolboxCall(tok.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("the token through the edge: %d %s", rec.Code, rec.Body.String())
	}

	rec, got := revokeTokens(t, edge, "avm_payments", "sb-owned")
	if rec.Code != http.StatusOK || got.SandboxID != "sb-owned" {
		t.Fatalf("revoke through the edge: %d %s", rec.Code, rec.Body.String())
	}
	if row, err := ownerStore.Get(context.Background(), "sb-owned"); err != nil || row.TokensNotBefore != got.TokensNotBefore.Unix() {
		t.Fatalf("the owner's row: %+v %v, want not-before %d", row, err, got.TokensNotBefore.Unix())
	}
	if rows, _ := edgeStore.List(context.Background()); len(rows) != 0 {
		t.Fatalf("the edge holds rows: %d", len(rows))
	}
	if rec := toolboxCall(tok.Token); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "revoked") {
		t.Fatalf("the revoked token through the edge: %d %s", rec.Code, rec.Body.String())
	}

	_, fresh := issueToken(t, edge, "avm_payments", "sb-owned", `{"expires_in":"10m"}`)
	if rec := toolboxCall(fresh.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("a new token through the edge: %d %s", rec.Code, rec.Body.String())
	}
	up.mu.Lock()
	reached := len(up.paths)
	up.mu.Unlock()
	if reached != 2 {
		t.Fatalf("toolboxd saw %d calls, want 2 (the revoked token's never reached it)", reached)
	}
}
