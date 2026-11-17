package v1

import (
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
// settings writes from every peer except those in refuse (a worker).
type settingsPeers struct{ refuse map[string]bool }

func (s settingsPeers) IsSettingsWritePeer(peerID string, _ *x509.Certificate) bool {
	return !s.refuse[peerID]
}

func (s settingsPeers) CheckIdentityWriter(peerID string, _ *x509.Certificate, _ cluster.IdentityWriteRequest) error {
	if s.refuse[peerID] {
		return fmt.Errorf("%w: test", cluster.ErrIdentityWriterRefused)
	}
	return nil
}

// Node certificates get only what their role needs: on a server, the
// internal settings writes refuse a worker (403, or the identity route's
// writer_refused code) and write nothing; a worker or gateway, which holds
// no Raft state, refuses them all (503) instead of sending a peer's write
// on as itself.
func TestInternalSettingsWritesComeFromServersAndGateways(t *testing.T) {
	refuse := settingsPeers{refuse: map[string]bool{"wrk-a": true}}
	profiles := &profileStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: refuse}
	quotas := &quotaWriterCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: refuse}
	pools := &warmPoolStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: refuse}
	ident := &identityStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), settingsPeers: refuse}
	for _, tc := range []struct {
		name  string
		stub  cluster.Client
		route func(*handlers) http.HandlerFunc
		body  string
		wrote func() bool
	}{
		{"egress profile", profiles, func(h *handlers) http.HandlerFunc { return h.clusterInternalEgressProfileWrite },
			`{"profile":{"owner":"acct","name":"python"}}`, func() bool { return profiles.wrote.Profile.Name != "" }},
		{"team quota", quotas, func(h *handlers) http.HandlerFunc { return h.clusterInternalTeamQuotaWrite },
			`{"quota":{"team":"risk","max_sandboxes":2}}`, func() bool { return quotas.wrote.Quota.Team != "" }},
		{"warm pool", pools, func(h *handlers) http.HandlerFunc { return h.clusterInternalWarmPoolWrite },
			`{"pool":{"image":"python:3.12","depth":2}}`, func() bool { return pools.wrote.Pool.Image != "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOwnedRecoveryHandlers(t, tc.stub)
			rr := httptest.NewRecorder()
			tc.route(h)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "wrk-a"))
			if rr.Code != http.StatusForbidden || tc.wrote() || !strings.Contains(rr.Body.String(), "only server and gateway nodes") {
				t.Fatalf("worker's write = %d %s (wrote %v)", rr.Code, rr.Body.String(), tc.wrote())
			}
			rr = httptest.NewRecorder()
			tc.route(h)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "gw-a"))
			if rr.Code != http.StatusOK || !tc.wrote() {
				t.Fatalf("gateway's write = %d %s", rr.Code, rr.Body.String())
			}
			// On a node that holds no Raft state the write is not relayed.
			agent := newOwnedRecoveryHandlers(t, cluster.NewNoop("wrk-b", "http://wrk-b", ""))
			rr = httptest.NewRecorder()
			tc.route(agent)(rr, withPeer(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), "gw-a"))
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("a node with no Raft state took a peer's write: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
	t.Run("identity", func(t *testing.T) {
		h := newOwnedRecoveryHandlers(t, ident)
		rr := httptest.NewRecorder()
		h.clusterInternalIdentityWrite(rr, withPeer(httptest.NewRequest(http.MethodPost, "/",
			strings.NewReader(`{"role":{"owner":"team:p","tag":"deploy","min_role":"runner"}}`)), "wrk-a"))
		var out cluster.IdentityWriteResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != http.StatusOK || out.Code != "writer_refused" || out.Role != nil {
			t.Fatalf("worker's role write = %d %s", rr.Code, rr.Body.String())
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

// The operator calls a worker or gateway takes go on to a server with the
// caller's own credential; the same calls about this node, and every call
// on a server, stay where they are. A worker also sends the cluster-wide
// settings writes on; a gateway writes those itself, as it does tokens.
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
		{config.NodeRoleWorker, func(h *handlers) http.Handler { return h.settingsViaServers(served) }, "/v1/cluster/nodes/n9", "pat", true, http.StatusTeapot},
		{config.NodeRoleIngress, func(h *handlers) http.Handler { return h.settingsViaServers(served) }, "/v1/cluster/nodes/n9", "pat", false, http.StatusNoContent},
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
