package v1

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// settingsPeers makes a stub cluster a server that takes cluster-wide
// settings writes from the peers in servers, and the agent-sandbox API's
// warm depths also from the peers in gateways. Every other peer (a worker)
// is refused. A stub with neither set takes every peer, as before.
type settingsPeers struct{ servers, gateways map[string]bool }

func (s settingsPeers) IsSettingsWritePeer(peerID string, _ *x509.Certificate) bool {
	return s.servers == nil || s.servers[peerID]
}

func (s settingsPeers) IsKubeWarmWritePeer(peerID string, leaf *x509.Certificate) bool {
	return s.IsSettingsWritePeer(peerID, leaf) || s.gateways[peerID]
}

func (s settingsPeers) CheckIdentityWriter(peerID string, leaf *x509.Certificate, _ cluster.IdentityWriteRequest) error {
	if !s.IsSettingsWritePeer(peerID, leaf) {
		return fmt.Errorf("%w: test", cluster.ErrIdentityWriterRefused)
	}
	return nil
}

// Node certificates get only what their role needs: on a server, the
// internal settings writes come only from servers. A worker's and a
// gateway's are refused (403, or the identity route's writer_refused
// code) and write nothing; a gateway's one write of the agent-sandbox
// API's warm depths passes. A worker or gateway, which holds no Raft
// state, refuses them all (503) instead of sending a peer's write on as
// itself.
func TestInternalSettingsWritesComeFromServers(t *testing.T) {
	peers := settingsPeers{servers: map[string]bool{"srv-b": true}, gateways: map[string]bool{"gw-a": true}}
	profiles := &profileStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: peers}
	quotas := &quotaWriterCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: peers}
	pools := &warmPoolStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: peers}
	ident := &identityStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: peers}
	for _, tc := range []struct {
		name  string
		stub  cluster.Client
		route func(*handlers) http.HandlerFunc
		body  string
		wrote func() bool
		reset func()
	}{
		{"egress profile", profiles, func(h *handlers) http.HandlerFunc { return h.clusterInternalEgressProfileWrite },
			`{"profile":{"owner":"acct","name":"python"}}`, func() bool { return profiles.wrote.Profile.Name != "" },
			func() { profiles.wrote = cluster.EgressProfileWriteRequest{} }},
		{"team quota", quotas, func(h *handlers) http.HandlerFunc { return h.clusterInternalTeamQuotaWrite },
			`{"quota":{"team":"risk","max_sandboxes":2}}`, func() bool { return quotas.wrote.Quota.Team != "" },
			func() { quotas.wrote = cluster.TeamQuotaWriteRequest{} }},
		{"warm pool", pools, func(h *handlers) http.HandlerFunc { return h.clusterInternalWarmPoolWrite },
			`{"pool":{"image":"python:3.12","depth":2}}`, func() bool { return pools.wrote.Pool.Image != "" },
			func() { pools.wrote = cluster.WarmPoolWriteRequest{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOwnedRecoveryHandlers(t, tc.stub)
			for _, peer := range []string{"wrk-a", "gw-a"} {
				rr := httptest.NewRecorder()
				tc.route(h)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), peer))
				if rr.Code != http.StatusForbidden || tc.wrote() || !strings.Contains(rr.Body.String(), "only server nodes") {
					t.Fatalf("%s's write = %d %s (wrote %v)", peer, rr.Code, rr.Body.String(), tc.wrote())
				}
			}
			rr := httptest.NewRecorder()
			tc.route(h)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "srv-b"))
			if rr.Code != http.StatusOK || !tc.wrote() {
				t.Fatalf("server's write = %d %s", rr.Code, rr.Body.String())
			}
			tc.reset()
			// On a node that holds no Raft state the write is not relayed.
			agent := newOwnedRecoveryHandlers(t, cluster.NewNoop("wrk-b", "http://wrk-b", ""))
			rr = httptest.NewRecorder()
			tc.route(agent)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "srv-b"))
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("a node with no Raft state took a peer's write: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
	t.Run("the agent-sandbox API's warm depths from a gateway", func(t *testing.T) {
		h := newOwnedRecoveryHandlers(t, pools)
		kube := `{"kube":{"depths":[{"image":"alpine","runtime":"gvisor","depth":1}]}}`
		for peer, want := range map[string]int{"gw-a": http.StatusOK, "wrk-a": http.StatusForbidden} {
			rr := httptest.NewRecorder()
			h.clusterInternalWarmPoolWrite(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(kube)), peer))
			if rr.Code != want {
				t.Fatalf("%s's warm depths = %d %s, want %d", peer, rr.Code, rr.Body.String(), want)
			}
		}
		// Depths and an entry together are not the depths write.
		rr := httptest.NewRecorder()
		h.clusterInternalWarmPoolWrite(rr, withPeer(httptest.NewRequest(http.MethodPost, "/",
			strings.NewReader(`{"kube":{"depths":[]},"pool":{"image":"x","depth":9}}`)), "gw-a"))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("a gateway's depths plus an entry = %d", rr.Code)
		}
	})
	t.Run("identity", func(t *testing.T) {
		h := newOwnedRecoveryHandlers(t, ident)
		rr := httptest.NewRecorder()
		h.clusterInternalIdentityWrite(rr, withPeer(httptest.NewRequest(http.MethodPost, "/",
			strings.NewReader(`{"role":{"owner":"team:p","tag":"deploy","min_role":"runner"}}`)), "gw-a"))
		var out cluster.IdentityWriteResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != http.StatusOK || out.Code != "writer_refused" || out.Role != nil {
			t.Fatalf("gateway's role write = %d %s", rr.Code, rr.Body.String())
		}
	})
}

// forwardRecorder is a worker's or gateway's cluster: it records the calls
// sent on to a server.
type forwardRecorder struct {
	*cluster.Noop
	sent []string
}

func (f *forwardRecorder) ForwardToServer(w http.ResponseWriter, r *http.Request) {
	f.sent = append(f.sent, r.Method+" "+r.URL.Path)
	w.WriteHeader(http.StatusTeapot)
}

// The operator calls and settings writes a worker or gateway takes go on to
// a server with the caller's own credential; the same calls about this
// node, and every call on a server or mixed node, stay where they are.
func TestOperatorCallsGoToServersFromWorkersAndGateways(t *testing.T) {
	newHandlers := func(role string) (*handlers, *forwardRecorder) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true, NodeRole: role}, logger, nil, nil, nil, nil, nil, nil, nil)
		rec := &forwardRecorder{Noop: cluster.NewNoop("self-1", "http://self-1", "")}
		svc.AttachCluster(rec)
		return &handlers{deps: Deps{Service: svc, Logger: logger}}, rec
	}
	served := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	call := func(hd http.Handler, method, pattern, path, bearer string) int {
		mux := http.NewServeMux()
		mux.Handle(method+" "+pattern, hd)
		req := httptest.NewRequest(method, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	for _, tc := range []struct {
		role     string
		wrap     func(h *handlers) http.Handler
		path     string
		bearer   string
		wantSent bool
		want     int
	}{
		{config.NodeRoleWorker, func(h *handlers) http.Handler { return h.viaServers(nil, served) }, "/v1/cluster/nodes/n9", "pat", true, http.StatusTeapot},
		{config.NodeRoleIngress, func(h *handlers) http.Handler { return h.viaServers(nil, served) }, "/v1/cluster/nodes/n9", "pat", true, http.StatusTeapot},
		{config.NodeRoleServer, func(h *handlers) http.Handler { return h.viaServers(nil, served) }, "/v1/cluster/nodes/n9", "pat", false, http.StatusNoContent},
		{config.NodeRoleWorker, func(h *handlers) http.Handler { return h.viaServers(h.otherNode, served) }, "/v1/cluster/nodes/n9", "pat", true, http.StatusTeapot},
		{config.NodeRoleWorker, func(h *handlers) http.Handler { return h.viaServers(h.otherNode, served) }, "/v1/cluster/nodes/self-1", "pat", false, http.StatusNoContent},
		{config.NodeRoleWorker, func(h *handlers) http.Handler { return h.viaServers(nil, served) }, "/v1/cluster/nodes/n9", "", false, http.StatusBadRequest},
		{config.NodeRoleMixed, func(h *handlers) http.Handler { return h.viaServers(nil, served) }, "/v1/cluster/nodes/n9", "pat", false, http.StatusNoContent},
	} {
		h, rec := newHandlers(tc.role)
		got := call(tc.wrap(h), http.MethodPost, "/v1/cluster/nodes/{id}", tc.path, tc.bearer)
		if got != tc.want || (len(rec.sent) > 0) != tc.wantSent {
			t.Errorf("%s %s bearer=%q: status %d sent %v, want %d sent=%v", tc.role, tc.path, tc.bearer, got, rec.sent, tc.want, tc.wantSent)
		}
	}
	// A node with no way to a server answers 503, never serves it as itself.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("self-1", "", ""))
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	if got := call(h.viaServers(nil, served), http.MethodPost, "/v1/cluster/nodes/{id}", "/v1/cluster/nodes/n9", "pat"); got != http.StatusServiceUnavailable {
		t.Fatalf("no forwarder = %d", got)
	}
}

// The grants routes.go gives a worker's or gateway's certificate, each for
// the one call that needs it.
func TestNodeGrants(t *testing.T) {
	worker := controlplane.NodeAccess("wkr-1", controlplane.NodeRoleWorker)
	withID := func(raw, id string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, raw, nil)
		r.SetPathValue("id", id)
		return r
	}
	if !nodeGrantAny(withID("/", ""), worker) {
		t.Error("nodeGrantAny")
	}
	if !nodeGrantSelf(withID("/", "wkr-1"), worker) || nodeGrantSelf(withID("/", "gw-1"), worker) || nodeGrantSelf(withID("/", ""), controlplane.Access{}) {
		t.Error("nodeGrantSelf: only the calling node")
	}
	if !nodeGrantSandboxRow(withID("/v1/sandboxes/sb-1", "sb-1"), worker) || nodeGrantSandboxRow(withID("/v1/sandboxes/sb-1?include_env=true", "sb-1"), worker) {
		t.Error("nodeGrantSandboxRow: never with the env")
	}
	bridged := withID("/v1/sandboxes/sb-1/sessions", "sb-1")
	if nodeGrantSSHBridge(bridged, worker) {
		t.Error("a session without the gateway's marker was granted")
	}
	bridged = bridged.WithContext(auditlog.ContextWithSSHGatewayCall(bridged.Context(), auditlog.SSHGatewayCall{SandboxID: "sb-1"}))
	if !nodeGrantSSHBridge(bridged, worker) {
		t.Error("a bridged session was refused")
	}
	other := withID("/v1/sandboxes/sb-2/sessions", "sb-2")
	other = other.WithContext(auditlog.ContextWithSSHGatewayCall(other.Context(), auditlog.SSHGatewayCall{SandboxID: "sb-1"}))
	if nodeGrantSSHBridge(other, worker) {
		t.Error("a marker for one sandbox opened another")
	}
}

// asRolePeer is r from peer id over the internal routes (withPeer), with a
// verified certificate signed for role ("" names none).
func asRolePeer(r *http.Request, id, role string) *http.Request {
	names := []string{"node:" + id}
	if role != "" {
		names = append(names, "role:"+role)
	}
	cert := &x509.Certificate{DNSNames: names}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return withPeer(r, id)
}

// A WASM migration's export is a sandbox's whole memory: node certificates
// get only what their role needs, and only a server runs a migration as
// itself over HTTP (a worker or gateway sends the operator's on to one; a
// draining owner exports its own without a call). A worker's or gateway's
// request is refused and nothing is exported.
func TestWasmMigrateExportGoesOnlyToServers(t *testing.T) {
	h, _ := newV1WasmMigrateHarness(t, nil)
	for _, tc := range []struct {
		id, role string
		want     int
	}{
		{"wkr-b", cluster.JoinRoleWorker, http.StatusForbidden},
		{"gw-b", cluster.JoinRoleIngress, http.StatusForbidden},
		{"old-b", "", http.StatusForbidden},
		{"srv-a", cluster.JoinRoleServer, http.StatusOK},
	} {
		req := asRolePeer(httptest.NewRequest(http.MethodGet, cluster.PublicInternalWasmMigratePath+"sb-handoff/export", nil), tc.id, tc.role)
		req.SetPathValue("id", "sb-handoff")
		rr := httptest.NewRecorder()
		h.clusterInternalWasmMigrateExport(rr, req)
		if rr.Code != tc.want || (tc.want == http.StatusForbidden && rr.Header().Get(cluster.WasmMigrateCloneGenHeader) != "") {
			t.Fatalf("%s (%q) export = %d %s, want %d", tc.id, tc.role, rr.Code, rr.Body.String(), tc.want)
		}
	}
}

// A key write from a node that only keeps the keys (not a server) is
// opened and checked on the server that takes it: every key must be the
// one its record publishes (Service.CheckIdentityKeyRecords). This server
// holds no server key, so nothing opens and the write is refused; a
// server's own key write is not opened here.
func TestIdentityKeyWritesFromNonServersAreOpenedAndChecked(t *testing.T) {
	stub := &identityStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	body := `{"keys":{"expected_generation":0,"keys":[{"kid":"k1","sealed_private":"AAEC","public_jwk":{"kty":"RSA"},"created_unix_nano":1}]}}`
	for _, tc := range []struct {
		id, role string
		refused  bool
	}{
		{"wkr-a", cluster.JoinRoleWorker, true},
		{"gw-a", cluster.JoinRoleIngress, true},
		{"srv-b", cluster.JoinRoleServer, false},
	} {
		rr := httptest.NewRecorder()
		h.clusterInternalIdentityWrite(rr, asRolePeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), tc.id, tc.role))
		var out cluster.IdentityWriteResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if got := out.Code == "writer_refused"; got != tc.refused || rr.Code != http.StatusOK {
			t.Fatalf("%s key write = %d %s, refused %v want %v", tc.id, rr.Code, rr.Body.String(), got, tc.refused)
		}
	}
}

// Every operator call and settings write a worker or gateway takes goes on
// to a server (the route table in routes.go): the forwarder answers 418
// here, so a route that ran locally instead shows up. The same calls about
// this node (self-1) stay local.
func TestOperatorRoutesGoToServers(t *testing.T) {
	for _, role := range []string{config.NodeRoleWorker, config.NodeRoleIngress} {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := service.New(config.Config{EnableCluster: true, NodeRole: role}, logger, nil, nil, nil, nil, nil, nil, nil)
		rec := &forwardRecorder{Noop: cluster.NewNoop("self-1", "http://self-1", "")}
		svc.AttachCluster(rec)
		mux := http.NewServeMux()
		RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.OperatorAccess())))
			})
		}})
		for _, c := range []struct{ method, path string }{
			{http.MethodPost, "/v1/cluster/join-tokens"},
			{http.MethodGet, "/v1/cluster/join-tokens"},
			{http.MethodDelete, "/v1/cluster/join-tokens/abcdef"},
			{http.MethodDelete, "/v1/cluster/nodes/n9"},
			{http.MethodGet, "/v1/cluster/nodes/n9"},
			{http.MethodPost, "/v1/cluster/nodes/n9/drain"},
			{http.MethodPost, "/v1/cluster/nodes/n9/cordon"},
			{http.MethodPost, "/v1/cluster/nodes/n9/uncordon"},
			{http.MethodDelete, "/v1/cluster/members/n9"},
			{http.MethodPost, "/v1/cluster/nodes/n9/storage-retired"},
			{http.MethodDelete, "/v1/cluster/nodes/n9/storage-retired"},
			{http.MethodDelete, "/v1/cluster/orphans/sb-1"},
			{http.MethodPost, cluster.PublicWasmMigratePath},
			{http.MethodPost, "/v1/tokens"},
			{http.MethodDelete, "/v1/tokens/tok_aaaaaaaaaaaa"},
			{http.MethodPut, "/v1/identity/roles/deploy"},
			{http.MethodDelete, "/v1/identity/roles/deploy"},
			{http.MethodPost, "/v1/identity/keys/rotate"},
			{http.MethodPut, "/v1/egress-profiles/p"},
			{http.MethodDelete, "/v1/egress-profiles/p"},
			{http.MethodPut, "/v1/teams/t/quota"},
			{http.MethodDelete, "/v1/teams/t/quota"},
			{http.MethodPut, "/v1/warm-pools/alpine"},
			{http.MethodDelete, "/v1/warm-pools/alpine"},
		} {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer operator")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusTeapot {
				t.Errorf("%s %s %s: %d %s, want it sent to a server", role, c.method, c.path, rr.Code, rr.Body.String())
			}
		}
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/v1/cluster/nodes/self-1"},
			{http.MethodPost, "/v1/cluster/nodes/self-1/drain"},
			{http.MethodDelete, "/v1/cluster/members/self-1"},
		} {
			sent := len(rec.sent)
			req := httptest.NewRequest(c.method, c.path, nil)
			req.Header.Set("Authorization", "Bearer operator")
			rr, _ := func() (rr *httptest.ResponseRecorder, panicked bool) {
				rr = httptest.NewRecorder()
				defer func() { panicked = recover() != nil }()
				mux.ServeHTTP(rr, req)
				return rr, false
			}()
			if len(rec.sent) != sent || rr.Code == http.StatusTeapot {
				t.Errorf("%s %s %s about this node was sent to a server", role, c.method, c.path)
			}
		}
	}
}
