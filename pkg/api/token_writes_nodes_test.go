package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/service"
)

// tokenServerCluster is a server node's cluster for the public token
// routes: wkr-1, gw-1 and srv-1 are live members, only srv-1 writes tokens,
// and a token write lands here as this server's own Raft write.
type tokenServerCluster struct {
	*cluster.Noop
	mu     sync.Mutex
	writes []cluster.APITokenWriteRequest
}

func (c *tokenServerCluster) LookupMember(id string) (cluster.Member, bool) {
	switch id {
	case "wkr-1", "gw-1", "srv-1":
		return cluster.Member{NodeID: id, Alive: true}, true
	}
	return c.Noop.LookupMember(id)
}

func (c *tokenServerCluster) IsTokenWritePeer(id string) bool { return id == "srv-1" }

func (c *tokenServerCluster) WriteAPIToken(_ context.Context, req cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, req)
	return cluster.APITokenWriteResponse{Token: req.Token}, nil
}

func (c *tokenServerCluster) ListAPITokens(context.Context) ([]identity.TokenRecord, error) {
	return nil, nil
}

// Token writes come only from servers (defense in depth): a token create
// or revoke a worker or gateway makes as itself, with no caller's
// credential or with the PAT over mTLS, is refused and nothing is written.
// A caller's own credential a worker or gateway forwarded is that caller
// and passes.
func TestTokenWritesComeOnlyFromServers(t *testing.T) {
	cfg := config.Config{EnableCluster: true, IdentityEnabled: true, NodeRole: config.NodeRoleServer, PATToken: "operator-pat-token"}
	svc := service.New(cfg, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	cl := &tokenServerCluster{Noop: cluster.NewNoop("server-0", "http://server-0", "")}
	svc.AttachCluster(cl)
	h := NewServer(discardLogger(), svc, nil, nil, cfg, "operator-pat-token", nil).Handler()
	create := `{"name":"ci","role":"admin","team":"*","expires_in":"8760h"}`
	for _, tc := range []struct {
		name, method, path, body, peer, bearer string
		forwarded                              bool
		want                                   int
	}{
		{"worker cert, no bearer: create", http.MethodPost, "/v1/tokens", create, "wkr-1", "", false, http.StatusForbidden},
		{"worker cert, no bearer: revoke", http.MethodDelete, "/v1/tokens/tok_aaaaaaaaaaaa", "", "wkr-1", "", false, http.StatusForbidden},
		{"worker cert with the PAT, for itself: create", http.MethodPost, "/v1/tokens", create, "wkr-1", "operator-pat-token", false, http.StatusForbidden},
		{"worker forwarding an operator's PAT: create", http.MethodPost, "/v1/tokens", create, "wkr-1", "operator-pat-token", true, http.StatusCreated},
		{"worker forwarding an operator's PAT: revoke", http.MethodDelete, "/v1/tokens/tok_aaaaaaaaaaaa", "", "wkr-1", "operator-pat-token", true, http.StatusNoContent},
		{"gateway cert: create", http.MethodPost, "/v1/tokens", create, "gw-1", "", false, http.StatusForbidden},
		{"server cert: create", http.MethodPost, "/v1/tokens", create, "srv-1", "", false, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl.mu.Lock()
			cl.writes = nil
			cl.mu.Unlock()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = "10.0.0.9:7002"
			req.TLS = peerTLSRole(tc.peer, map[string]string{"wkr-1": "worker", "gw-1": "ingress", "srv-1": "server"}[tc.peer])
			req = req.WithContext(cluster.ContextWithInternalPeer(req.Context(), tc.peer))
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.forwarded {
				req.Header.Set(cluster.HeaderForwarded, "1")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			cl.mu.Lock()
			writes := len(cl.writes)
			cl.mu.Unlock()
			if rec.Code != tc.want {
				t.Fatalf("= %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if tc.want == http.StatusForbidden && (writes != 0 || strings.Contains(rec.Body.String(), "avm_")) {
				t.Fatalf("a refused write reached the cluster (%d writes) or answered a token: %s", writes, rec.Body.String())
			}
			// A local tool using the node's own token learns what to use.
			if tc.want == http.StatusForbidden && !strings.Contains(rec.Body.String(), "use an operator token or a user token") &&
				!strings.Contains(rec.Body.String(), "with an operator token or a user token") {
				t.Fatalf("the refusal does not say what to use instead: %s", rec.Body.String())
			}
		})
	}
}
