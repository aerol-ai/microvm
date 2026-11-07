package v1

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// joinStubCluster has every join capability, with canned answers.
type joinStubCluster struct {
	*cluster.Noop
	createReq  cluster.JoinTokenCreateRequest
	created    cluster.JoinTokenCreated
	createErr  error
	list       cluster.JoinTokenList
	listErr    error
	revoked    string
	revokeErr  error
	adoptReq   cluster.AdoptRequest
	adopt      cluster.AdoptResponse
	adoptErr   error
	writePeers map[string]bool
	writeReq   cluster.JoinWriteRequest
	writeResp  cluster.JoinWriteResponse
	writeErr   error
	renewPeer  string
	renewCSR   string
	renew      cluster.RenewCertResponse
	renewErr   error
	caKey      cluster.CAKeyResponse
	caKeyErr   error
	keyErr     error
}

func (c *joinStubCluster) CreateJoinToken(_ context.Context, req cluster.JoinTokenCreateRequest) (cluster.JoinTokenCreated, error) {
	c.createReq = req
	return c.created, c.createErr
}

func (c *joinStubCluster) ListJoinTokens(context.Context) (cluster.JoinTokenList, error) {
	return c.list, c.listErr
}

func (c *joinStubCluster) RevokeJoinToken(_ context.Context, id string) error {
	c.revoked = id
	return c.revokeErr
}

func (c *joinStubCluster) Adopt(_ context.Context, req cluster.AdoptRequest) (cluster.AdoptResponse, error) {
	c.adoptReq = req
	return c.adopt, c.adoptErr
}

func (c *joinStubCluster) WriteJoin(_ context.Context, req cluster.JoinWriteRequest) (cluster.JoinWriteResponse, error) {
	c.writeReq = req
	return c.writeResp, c.writeErr
}

func (c *joinStubCluster) IsJoinWritePeer(id string) bool { return c.writePeers[id] }

func (c *joinStubCluster) RenewNodeCert(_ context.Context, peer string, _ *x509.Certificate, csr []byte) (cluster.RenewCertResponse, error) {
	c.renewPeer, c.renewCSR = peer, string(csr)
	return c.renew, c.renewErr
}

func (c *joinStubCluster) CAKeyForPeer(string) (cluster.CAKeyResponse, error) {
	return c.caKey, c.caKeyErr
}

func (c *joinStubCluster) CheckPeerKey(string, *x509.Certificate) error { return c.keyErr }

func (c *joinStubCluster) LookupMember(id string) (cluster.Member, bool) {
	return cluster.Member{NodeID: id, Alive: true}, true
}

func newJoinStub() *joinStubCluster {
	return &joinStubCluster{Noop: cluster.NewNoop("srv-1", "http://srv-1", "")}
}

// joinRoutesMux serves the real v1 routes as caller.
func joinRoutesMux(t *testing.T, c cluster.Client, caller controlplane.Access) *http.ServeMux {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), caller)))
		})
	}})
	return mux
}

func joinOperator() controlplane.Access {
	return controlplane.Access{Fleet: true, Role: controlplane.RoleAdmin, Principal: controlplane.Principal{Kind: controlplane.PrincipalOperator, ID: "operator:alice"}}
}

func serveBody(mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	mux.ServeHTTP(rr, httptest.NewRequest(method, path, r))
	return rr
}

func TestJoinTokenRoutes(t *testing.T) {
	stub := newJoinStub()
	stub.created = cluster.JoinTokenCreated{Token: "abcdef." + strings.Repeat("x", 32), ID: "abcdef", Role: "worker"}
	stub.list = cluster.JoinTokenList{Tokens: []cluster.JoinTokenInfo{{ID: "abcdef", Role: "worker"}}}
	mux := joinRoutesMux(t, stub, joinOperator())

	// The caller's principal is the creator; a body claim from an operator
	// is ignored.
	rr := serveBody(mux, http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker","ttl":"0","reusable":true,"created_by":"forged"}`)
	var created cluster.JoinTokenCreated
	if rr.Code != http.StatusCreated || json.Unmarshal(rr.Body.Bytes(), &created) != nil || created.ID != "abcdef" {
		t.Fatalf("create = %d %s", rr.Code, rr.Body.String())
	}
	if stub.createReq.CreatedBy != "operator:alice" || stub.createReq.TTL != "0" || !stub.createReq.Reusable {
		t.Fatalf("create request = %+v", stub.createReq)
	}
	if rr := serveBody(mux, http.MethodPost, "/v1/cluster/join-tokens", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("broken body = %d", rr.Code)
	}
	for err, want := range map[error]int{
		cluster.ErrJoinTTLNeedsWrappedCustody: http.StatusForbidden,
		cluster.ErrJoinTTLInvalid:             http.StatusBadRequest,
		cluster.ErrClusterVersion:             http.StatusConflict,
		cluster.ErrNotLeader:                  http.StatusServiceUnavailable,
	} {
		stub.createErr = err
		if rr := serveBody(mux, http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker"}`); rr.Code != want {
			t.Fatalf("create with %v = %d, want %d", err, rr.Code, want)
		}
	}

	rr = serveBody(mux, http.MethodGet, "/v1/cluster/join-tokens", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"abcdef"`) || strings.Contains(rr.Body.String(), "secret") {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	stub.listErr = errors.New("boom")
	if rr := serveBody(mux, http.MethodGet, "/v1/cluster/join-tokens", ""); rr.Code != http.StatusInternalServerError {
		t.Fatalf("list error = %d", rr.Code)
	}

	rr = serveBody(mux, http.MethodDelete, "/v1/cluster/join-tokens/abcdef", "")
	if rr.Code != http.StatusOK || stub.revoked != "abcdef" || !strings.Contains(rr.Body.String(), `"revoked":true`) {
		t.Fatalf("revoke = %d %s", rr.Code, rr.Body.String())
	}
	stub.revokeErr = cluster.ErrJoinBadRequest
	if rr := serveBody(mux, http.MethodDelete, "/v1/cluster/join-tokens/BAD", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("revoke bad id = %d", rr.Code)
	}

	// Single-node mode (Noop) has no join service.
	noop := joinRoutesMux(t, cluster.NewNoop("solo", "http://solo", ""), joinOperator())
	for _, req := range [][2]string{{http.MethodPost, "/v1/cluster/join-tokens"}, {http.MethodGet, "/v1/cluster/join-tokens"}, {http.MethodDelete, "/v1/cluster/join-tokens/abcdef"}, {http.MethodPost, "/v1/cluster/adopt"}} {
		if rr := serveBody(noop, req[0], req[1], `{}`); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s under Noop = %d", req[0], req[1], rr.Code)
		}
	}
}

// A worker relaying an operator's create names that operator; a node
// principal's claim is honoured, nobody else's.
func TestJoinTokenCreatorFromRelayingNode(t *testing.T) {
	stub := newJoinStub()
	node := controlplane.Access{Role: controlplane.RoleAdmin, Principal: controlplane.Principal{Kind: controlplane.PrincipalNode, ID: "node:wkr-1"}, Fleet: true}
	mux := joinRoutesMux(t, stub, node)
	serveBody(mux, http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker","created_by":"operator:bob"}`)
	if stub.createReq.CreatedBy != "operator:bob" {
		t.Fatalf("relayed creator = %q", stub.createReq.CreatedBy)
	}
	serveBody(mux, http.MethodPost, "/v1/cluster/join-tokens", `{"role":"worker"}`)
	if stub.createReq.CreatedBy != "node:wkr-1" {
		t.Fatalf("node without a claim = %q", stub.createReq.CreatedBy)
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if got := joinTokenCreator(req, " claimed "); got != "claimed" {
		t.Fatalf("no access = %q", got)
	}
}

func TestAdoptRoute(t *testing.T) {
	stub := newJoinStub()
	stub.adopt = cluster.AdoptResponse{ClusterID: "sha256:x", Admitted: []string{"srv-1"}}
	mux := joinRoutesMux(t, stub, joinOperator())
	rr := serveBody(mux, http.MethodPost, "/v1/cluster/adopt", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "sha256:x") {
		t.Fatalf("adopt without a body = %d %s", rr.Code, rr.Body.String())
	}
	rr = serveBody(mux, http.MethodPost, "/v1/cluster/adopt", `{"ca_key":"PEM"}`)
	if rr.Code != http.StatusOK || stub.adoptReq.CAKey != "PEM" {
		t.Fatalf("adopt with a key = %d %+v", rr.Code, stub.adoptReq)
	}
	if rr := serveBody(mux, http.MethodPost, "/v1/cluster/adopt", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("adopt broken body = %d", rr.Code)
	}
	stub.adoptErr = cluster.ErrNoCASigner
	if rr := serveBody(mux, http.MethodPost, "/v1/cluster/adopt", `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("adopt error = %d", rr.Code)
	}
}

// internalReq is an internal call from peer over verified mTLS.
func internalReq(method, path, body, peer string) *http.Request {
	req := httptest.NewRequest(method, "https://internal"+path, bytes.NewBufferString(body))
	addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"node:" + peer}})
	return req.WithContext(context.WithValue(req.Context(), clusterPeerNodeIDContextKey{}, peer))
}

func joinHandlers(t *testing.T, c cluster.Client) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func TestInternalJoinWriteRoute(t *testing.T) {
	stub := newJoinStub()
	stub.writePeers = map[string]bool{"srv-2": true}
	h := joinHandlers(t, stub)
	call := func(peer, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.clusterInternalJoinWrite(rr, internalReq(http.MethodPost, cluster.PublicInternalJoinWritePath, body, peer))
		return rr
	}
	// A worker may not propose join state.
	if rr := call("wkr-1", `{"kind":"put_token"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("worker join write = %d", rr.Code)
	}
	stub.writeResp = cluster.JoinWriteResponse{Admit: &cluster.JoinAdmitResult{Replay: true}}
	rr := call("srv-2", `{"kind":"admit","admit":{"node_id":"n"}}`)
	if rr.Code != http.StatusOK || stub.writeReq.Kind != "admit" || !strings.Contains(rr.Body.String(), `"replay":true`) {
		t.Fatalf("server join write = %d %s", rr.Code, rr.Body.String())
	}
	// A refusal travels as a 200 with its code, so the sentinel survives.
	stub.writeErr = cluster.ErrJoinTokenUsed
	rr = call("srv-2", `{"kind":"admit"}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"token_used"`) {
		t.Fatalf("refused write = %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = errors.New("raft down")
	if rr := call("srv-2", `{"kind":"admit"}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed write = %d", rr.Code)
	}
	if rr := call("srv-2", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("broken body = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	joinHandlers(t, cluster.NewNoop("solo", "http://solo", "")).clusterInternalJoinWrite(rr, internalReq(http.MethodPost, "/", "{}", "srv-2"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("join write under Noop = %d", rr.Code)
	}
}

func TestInternalRenewAndCAKeyRoutes(t *testing.T) {
	stub := newJoinStub()
	stub.renew = cluster.RenewCertResponse{NodeCert: "CERT"}
	stub.caKey = cluster.CAKeyResponse{CAKey: "KEY"}
	h := joinHandlers(t, stub)

	rr := httptest.NewRecorder()
	h.clusterInternalRenewCert(rr, internalReq(http.MethodPost, cluster.PublicInternalRenewCertPath, `{"csr":"CSR"}`, "wkr-1"))
	if rr.Code != http.StatusOK || stub.renewPeer != "wkr-1" || stub.renewCSR != "CSR" || !strings.Contains(rr.Body.String(), "CERT") {
		t.Fatalf("renew = %d %s", rr.Code, rr.Body.String())
	}
	for err, want := range map[error]int{cluster.ErrNoCASigner: 503, cluster.ErrNotAdmitted: 412, cluster.ErrJoinKeyRevoked: 403} {
		stub.renewErr = err
		rr = httptest.NewRecorder()
		h.clusterInternalRenewCert(rr, internalReq(http.MethodPost, "/", `{"csr":"CSR"}`, "wkr-1"))
		if rr.Code != want {
			t.Fatalf("renew with %v = %d, want %d", err, rr.Code, want)
		}
	}
	rr = httptest.NewRecorder()
	h.clusterInternalRenewCert(rr, internalReq(http.MethodPost, "/", `{`, "wkr-1"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("renew broken body = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.clusterInternalRenewCert(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("renew without mTLS = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.clusterInternalCAKey(rr, internalReq(http.MethodPost, cluster.PublicInternalCAKeyPath, `{}`, "srv-2"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "KEY") || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ca key = %d %s", rr.Code, rr.Body.String())
	}
	stub.caKeyErr = cluster.ErrPeerNotServer
	rr = httptest.NewRecorder()
	h.clusterInternalCAKey(rr, internalReq(http.MethodPost, "/", `{}`, "wkr-1"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("ca key to a worker = %d", rr.Code)
	}

	noop := joinHandlers(t, cluster.NewNoop("solo", "http://solo", ""))
	for name, fn := range map[string]http.HandlerFunc{"renew": noop.clusterInternalRenewCert, "ca key": noop.clusterInternalCAKey} {
		rr = httptest.NewRecorder()
		fn(rr, internalReq(http.MethodPost, "/", `{}`, "x"))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s under Noop = %d", name, rr.Code)
		}
	}
}

// The public API's internal routes refuse a tombstoned or unadmitted cert
// key, like the internal listener does.
func TestWithInternalMTLSRefusesRevokedKey(t *testing.T) {
	stub := newJoinStub()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(stub)
	calls := 0
	guarded := withInternalMTLS(Deps{Service: svc, Logger: logger}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/denied-nodes", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"node:wkr-r"}})
		rr := httptest.NewRecorder()
		guarded.ServeHTTP(rr, req)
		return rr
	}
	if rr := do(); rr.Code != http.StatusNoContent {
		t.Fatalf("admitted key = %d", rr.Code)
	}
	stub.keyErr = cluster.ErrPeerKeyRevoked
	if rr := do(); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "revoked") {
		t.Fatalf("revoked key = %d %s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d", calls)
	}
	if peerKeyRefused(Deps{}, httptest.NewRequest(http.MethodGet, "/", nil), "x") != nil {
		t.Fatal("no service refused a key")
	}
}
