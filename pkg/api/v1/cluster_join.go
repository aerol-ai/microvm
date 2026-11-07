package v1

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Operator and internal routes of the join service
// (plans/kubectl-style-cluster-ops.md §4, §4.2, §4.4). All are new paths;
// nothing existing changes (/v1 is soft-frozen). The three join paths a new
// machine calls are not here: they live on the join listener (:7003,
// internal/cluster/join_server.go), which no public route reaches.
//
//	POST   /v1/cluster/join-tokens            fleet.admin  make a token (secret shown once)
//	GET    /v1/cluster/join-tokens            fleet.admin  list (never a secret or hash)
//	DELETE /v1/cluster/join-tokens/{id}       fleet.admin  revoke (idempotent)
//	POST   /v1/cluster/adopt                  fleet.admin  sandboxd adopt's call, on a server
//
// A server token and adopt also refuse a caller whose mTLS cert names a
// node that is not a server (refuseNonServerNode).
//	POST   /v1/cluster/internal/join/write    peer, Raft servers only: a follower's write to the leader
//	POST   /v1/cluster/internal/renew-cert    peer: renew this caller's cert (admitted key)
//	POST   /v1/cluster/internal/ca-key        peer, servers only: the CA key for adopt

// joinWriteTimeout bounds a token write or an adopt: a Raft apply, and for
// adopt one TLS handshake per member.
const (
	joinWriteTimeout = 30 * time.Second
	adoptTimeout     = 2 * time.Minute
)

// joinTarget returns the cluster capability a join route needs, or answers
// 503 like every other cluster route under Noop.
func joinTarget[T any](h *handlers, w http.ResponseWriter, what string) (T, bool) {
	var zero T
	var c cluster.Client
	if h.deps.Service != nil {
		c = h.deps.Service.Cluster()
	}
	capable, ok := c.(T)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: "+what+" is not available on this node")
		return zero, false
	}
	return capable, true
}

func writeJoinError(w http.ResponseWriter, err error) {
	apihttp.WriteError(w, cluster.JoinErrorStatus(err), err.Error())
}

// joinTokenCreator is who made the token: the caller's principal, or, when
// a worker relays an operator's call over mTLS (a node principal), the
// principal that worker names in the body.
func joinTokenCreator(r *http.Request, claimed string) string {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok {
		return strings.TrimSpace(claimed)
	}
	if access.Principal.Kind == controlplane.PrincipalNode && strings.TrimSpace(claimed) != "" {
		return strings.TrimSpace(claimed)
	}
	return access.Principal.ID
}

// serverPeerChecker is the server-role binding (Cluster.IsJoinWritePeer):
// the node's admitted role, and Raft membership.
type serverPeerChecker interface {
	IsJoinWritePeer(peerID string) bool
}

// refuseNonServerNode stops a server-tier power (a server join token, or
// adopt) asked over a connection that proves a node identity, unless that
// node is a server. Such a call is a node acting for itself, or relaying
// an operator: a worker's own API sends token calls on with its own cert
// (agent_join.go), and a forward carries the edge's cert. Every joined
// node holds the PAT (the join answer carries it), so without this a
// leaked worker token becomes a worker cert plus the PAT, then a server
// token, then the CA key and a Raft seat, which the plan promises a
// worker token never gives (§8). An operator calling with the PAT and no
// node cert is not affected. It reports whether it answered.
func (h *handlers) refuseNonServerNode(w http.ResponseWriter, r *http.Request, what string) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return false
	}
	peer, err := cluster.AuthenticatedPeerNodeID(r)
	checker, ok := h.deps.Service.Cluster().(serverPeerChecker)
	if err == nil && ok && checker.IsJoinWritePeer(peer) {
		return false
	}
	if h.deps.Logger != nil {
		h.deps.Logger.Warn("cluster: refused a server-only join call from a node that is not a server", "what", what, "peer", peer)
	}
	writeJoinError(w, fmt.Errorf("%w: %s asked by node %q, which is not an admitted server; run it on a server node with the operator token", cluster.ErrPeerNotServer, what, peer))
	return true
}

func (h *handlers) clusterCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	mgr, ok := joinTarget[cluster.JoinTokenManager](h, w, "join tokens")
	if !ok {
		return
	}
	var req cluster.JoinTokenCreateRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.EqualFold(strings.TrimSpace(req.Role), cluster.JoinRoleServer) && h.refuseNonServerNode(w, r, "a server join token") {
		return
	}
	req.CreatedBy = joinTokenCreator(r, req.CreatedBy)
	ctx, cancel := context.WithTimeout(r.Context(), joinWriteTimeout)
	defer cancel()
	created, err := mgr.CreateJoinToken(ctx, req)
	if err != nil {
		writeJoinError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, created)
}

func (h *handlers) clusterListJoinTokens(w http.ResponseWriter, r *http.Request) {
	mgr, ok := joinTarget[cluster.JoinTokenManager](h, w, "join tokens")
	if !ok {
		return
	}
	list, err := mgr.ListJoinTokens(r.Context())
	if err != nil {
		writeJoinError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, list)
}

// joinTokenRevoked answers a revoke.
type joinTokenRevoked struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

func (h *handlers) clusterRevokeJoinToken(w http.ResponseWriter, r *http.Request) {
	mgr, ok := joinTarget[cluster.JoinTokenManager](h, w, "join tokens")
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), joinWriteTimeout)
	defer cancel()
	if err := mgr.RevokeJoinToken(ctx, id); err != nil {
		writeJoinError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, joinTokenRevoked{ID: id, Revoked: true})
}

// joinAdopter is the server-only adopt capability.
type joinAdopter interface {
	Adopt(ctx context.Context, req cluster.AdoptRequest) (cluster.AdoptResponse, error)
}

func (h *handlers) clusterAdopt(w http.ResponseWriter, r *http.Request) {
	adopter, ok := joinTarget[joinAdopter](h, w, "adopt (run it on a server node)")
	if !ok {
		return
	}
	if h.refuseNonServerNode(w, r, "adopt") {
		return
	}
	var req cluster.AdoptRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), adoptTimeout)
	defer cancel()
	res, err := adopter.Adopt(ctx, req)
	if err != nil {
		writeJoinError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, res)
}

// joinWriter is the leader's half of a follower's join write.
type joinWriter interface {
	WriteJoin(ctx context.Context, req cluster.JoinWriteRequest) (cluster.JoinWriteResponse, error)
	IsJoinWritePeer(peerID string) bool
}

// clusterInternalJoinWrite takes a follower's join write. Only a Raft
// server (by admitted role) may send one: a worker never proposes join
// state, so a compromised one can't admit a key as a server.
func (h *handlers) clusterInternalJoinWrite(w http.ResponseWriter, r *http.Request) {
	writer, ok := joinTarget[joinWriter](h, w, "join writes")
	if !ok {
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if !writer.IsJoinWritePeer(peerID) {
		writeJoinError(w, cluster.ErrPeerNotServer)
		return
	}
	var req cluster.JoinWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := writer.WriteJoin(r.Context(), req)
	if err != nil {
		if out := cluster.JoinWriteOutcome(err); out.Code != "" {
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: join write failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// certRenewer signs a peer's renewal.
type certRenewer interface {
	RenewNodeCert(ctx context.Context, peerID string, leaf *x509.Certificate, csrPEM []byte) (cluster.RenewCertResponse, error)
}

// clusterInternalRenewCert renews the calling node's cert. withInternalMTLS
// has already refused a deleted node, a tombstoned key and a key other than
// the admitted one; a server with no CA key answers 503 so the caller tries
// the next server.
func (h *handlers) clusterInternalRenewCert(w http.ResponseWriter, r *http.Request) {
	renewer, ok := joinTarget[certRenewer](h, w, "cert renewal")
	if !ok {
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		apihttp.WriteError(w, http.StatusForbidden, "cluster internal endpoint requires mTLS")
		return
	}
	var req cluster.RenewCertRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), joinWriteTimeout)
	defer cancel()
	resp, err := renewer.RenewNodeCert(ctx, peerID, r.TLS.PeerCertificates[0], []byte(req.CSR))
	if err != nil {
		writeJoinError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// caKeyServer hands the CA key to an adopting server.
type caKeyServer interface {
	CAKeyForPeer(peerID string) (cluster.CAKeyResponse, error)
}

func (h *handlers) clusterInternalCAKey(w http.ResponseWriter, r *http.Request) {
	srv, ok := joinTarget[caKeyServer](h, w, "the CA key")
	if !ok {
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	resp, err := srv.CAKeyForPeer(peerID)
	if err != nil {
		writeJoinError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// peerKeyRefused runs the cluster's cert-key check for the public API's
// internal routes (cluster.RefusePeerKey).
func peerKeyRefused(d Deps, r *http.Request, peerID string) error {
	if d.Service == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return cluster.RefusePeerKey(d.Service.Cluster(), peerID, r.TLS.PeerCertificates[0])
}
