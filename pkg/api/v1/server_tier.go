package v1

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// Operator calls a worker or gateway takes are sent on to a server with the
// caller's own credential (node certificates get only what their role
// needs). Such a node holds no Raft state, and its own certificate reaches
// only the cluster routes its role needs, so it no longer makes these calls
// as itself: the server authenticates the caller, and its record names the
// caller with this node as the hop (Via).
//
//	the operator calls      join tokens; node delete; storage retirement;
//	                        orphan delete; WASM migration; member removal,
//	                        node detail, drain, cordon and uncordon of
//	                        another node
//	the settings writes     API tokens, identity roles and key rotation,
//	                        egress profiles, team quotas, warm pools: only a
//	                        server writes those (internal/cluster
//	                        settings_writers.go)
//	custom domains          an attach, and a create with custom_domains:
//	                        only a server binds a new name
//	                        (custom_domains_servers.go)
//
// The same calls about this node stay here: draining this node first moves
// its own WASM sandboxes, and a node's own tools use its node-local token,
// which no server knows.

// serverForwarder is a worker's or gateway's way to a server
// (cluster.Agent.ForwardToServer: pinned to a server's certificate and
// role, the caller's credential kept).
type serverForwarder interface {
	ForwardToServer(http.ResponseWriter, *http.Request)
}

// viaServers sends the call on to a server when this node holds no Raft
// state and when(r) says so; otherwise next serves it here.
func (h *handlers) viaServers(when func(*http.Request) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.deps.Service == nil || !h.deps.Service.SendsOperatorCallsToServers() || (when != nil && !when(r)) {
			next.ServeHTTP(w, r)
			return
		}
		h.sendToServer(w, r, "this call")
	})
}

// otherNode reports whether the route's {id} names a node other than this
// one: only those calls go to a server.
func (h *handlers) otherNode(r *http.Request) bool {
	id := strings.TrimSpace(r.PathValue("id"))
	c := h.deps.Service.Cluster()
	return c == nil || id != c.SelfNodeID()
}

// sendToServer forwards r, with the caller's own credential, to a server.
// A call that carries none (a node-local caller's credential is dropped on
// the way, cluster.StampForward) still goes: the server then sees this node
// and grants it only what its role needs. A call with no Authorization at
// all is refused here, never sent as this node.
func (h *handlers) sendToServer(w http.ResponseWriter, r *http.Request, what string) {
	h.sendToServerWith(w, r, what, false)
}

// serverOnceForwarder is the forward for a call not safe to run twice
// (cluster.Agent.ForwardToServerOnce): a 5xx is the caller's answer, not a
// reason to try the next server.
type serverOnceForwarder interface {
	ForwardToServerOnce(http.ResponseWriter, *http.Request)
}

// sendToServerWith is sendToServer; once sends a call that is not safe to
// run twice, such as a create with no Idempotency-Key.
func (h *handlers) sendToServerWith(w http.ResponseWriter, r *http.Request, what string, once bool) {
	if scheme, cred, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " "); !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(cred) == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "this node sends "+what+" on to a server with your own credential, and the call carries none: send it with an Authorization header, or to a server")
		return
	}
	c := h.deps.Service.Cluster()
	if fw, ok := c.(serverOnceForwarder); ok && once {
		fw.ForwardToServerOnce(w, r)
		return
	}
	fw, ok := c.(serverForwarder)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, cluster.ErrNoServerForward.Error())
		return
	}
	fw.ForwardToServer(w, r)
}

// settingsWritePeerChecker is a server's check of who may write cluster-wide
// settings on the internal write routes (cluster.Cluster). A worker or
// gateway does not implement it: it holds no Raft state, and it refuses a
// peer's write rather than send it on as itself.
type settingsWritePeerChecker interface {
	IsSettingsWritePeer(peerID string, leaf *x509.Certificate) bool
	IsKubeWarmWritePeer(peerID string, leaf *x509.Certificate) bool
}

// internalPeer is the peer withInternalMTLS verified, and its certificate.
func internalPeer(r *http.Request) (string, *x509.Certificate) {
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	var leaf *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
	}
	return peerID, leaf
}

// refuseSettingsWriter answers an egress profile, team quota or warm pool
// write this node may not take from this peer, and reports whether it did:
// 503 on a node with no Raft state (the writer tries a server), 403 from a
// peer that is not a server. kubeWarm marks the one write a gateway also
// sends as itself: the agent-sandbox API's warm depths.
func (h *handlers) refuseSettingsWriter(w http.ResponseWriter, r *http.Request, what string, kubeWarm bool) bool {
	checker, ok := h.deps.Service.Cluster().(settingsWritePeerChecker)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state; send "+what+" to a server")
		return true
	}
	peerID, leaf := internalPeer(r)
	if checker.IsSettingsWritePeer(peerID, leaf) || (kubeWarm && checker.IsKubeWarmWritePeer(peerID, leaf)) {
		return false
	}
	if h.deps.Logger != nil {
		h.deps.Logger.Warn("cluster: refused a settings write from a node that is not a server", "what", what, "peer", peerID)
	}
	apihttp.WriteError(w, http.StatusForbidden, fmt.Sprintf("cluster: only server nodes write %s: node %q is not one; send the caller's call to a server", what, peerID))
	return true
}
