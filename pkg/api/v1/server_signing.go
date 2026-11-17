package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
)

// The node-to-node routes of signing only servers do (least privilege;
// internal/service/server_signing.go). Each answers on a server; another
// node answers 503, and the caller tries a server.

// clusterInternalSigningKeys is the feed of public keys every node checks
// sandbox tokens with.
func (h *handlers) clusterInternalSigningKeys(w http.ResponseWriter, r *http.Request) {
	feed, err := h.deps.Service.SigningKeysFeed()
	if err != nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, feed)
}

// clusterInternalSandboxTokenSign signs a sandbox token for the sandbox's
// owner node.
func (h *handlers) clusterInternalSandboxTokenSign(w http.ResponseWriter, r *http.Request) {
	var req cluster.SandboxTokenSignRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	peerID, leaf := internalPeer(r)
	server := cluster.PeerRole(h.deps.Service.Cluster(), peerID, leaf) == cluster.JoinRoleServer
	resp, err := h.deps.Service.SignSandboxTokenFor(r.Context(), peerID, server, req.Claims)
	if err != nil {
		apihttp.WriteError(w, signStatus(err), err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalIdentityTokenSign signs a cloud-identity token for the
// sandbox's owner node.
func (h *handlers) clusterInternalIdentityTokenSign(w http.ResponseWriter, r *http.Request) {
	var req cluster.IdentityTokenSignRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	peerID, leaf := internalPeer(r)
	server := cluster.PeerRole(h.deps.Service.Cluster(), peerID, leaf) == cluster.JoinRoleServer
	resp, err := h.deps.Service.SignIdentityTokenFor(r.Context(), peerID, server, req)
	if err != nil {
		apihttp.WriteError(w, signStatus(err), err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// signStatus maps a refused signature: 403 for a node that does not own the
// sandbox, 404 for a sandbox that is gone, 400 for claims this server would
// not give, 503 for anything a retry on another server may fix.
func signStatus(err error) int {
	switch {
	case errors.Is(err, service.ErrSignNotOwner):
		return http.StatusForbidden
	case errors.Is(err, store.ErrNotFound), errors.Is(err, service.ErrIdentityNotOnSandbox), errors.Is(err, service.ErrIdentityDisabled):
		return http.StatusNotFound
	case errors.Is(err, service.ErrIdentityRoleRemoved):
		return http.StatusGone
	case errors.Is(err, service.ErrSandboxTokenInvalid), errors.Is(err, service.ErrIdentityInvalid):
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

// identityCreateGoesToServer reports whether a create this node received
// asks for a cloud identity once servers sign: a server places it then,
// because only a server puts an identity into a placement's spec
// (cluster/peer_proposals.go), and a server signs the sandbox's tokens from
// it. A create a server already placed and sent here (the create target
// header) stays. The body is read once and put back for the handler.
func (h *handlers) identityCreateGoesToServer(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get(clustercreate.HeaderTarget)) != "" || !h.deps.Service.ServerSigningOn() {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, apihttp.MaxJSONBodyBytes+1))
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var probe struct {
		Identity json.RawMessage `json:"identity"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	return len(probe.Identity) > 0 && string(probe.Identity) != "null"
}
