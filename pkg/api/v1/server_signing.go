package v1

import (
	"errors"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
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

// clusterServerSigning answers whether only servers sign yet, and serves
// the operator's two calls on it (upgradewire.ClusterUpgradeSigningPath),
// on the leader: the gate reads the leader's view of the members, and only
// the leader writes the record. The calls are audited as upgrade calls.
func (h *handlers) clusterServerSigning(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.onLeader(w, r); !ok {
		return
	}
	svc := h.deps.Service
	var err error
	route := ""
	switch r.URL.Path {
	case upgradewire.ClusterUpgradeSigningStartPath:
		route = "signing-start"
		_, err = svc.StartServerSigning(r.Context())
	case upgradewire.ClusterUpgradeSigningEndOldTokensPath:
		route = "signing-end-old-tokens"
		_, err = svc.EndOldSandboxTokens(r.Context())
	}
	if route != "" {
		h.auditUpgrade(r, route, "", err)
	}
	if errors.Is(err, service.ErrServerSigningOff) {
		writeUpgradeError(w, http.StatusConflict, "server_signing_off", "servers do not sign yet: there are no old tokens to end", "aerolvm upgrade signing")
		return
	}
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	rec, g, on, err := svc.ServerSigningStatus()
	if err != nil {
		writeRolloutError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, serverSigningStatusView(rec, g, on))
}

// serverSigningStatusView renders the record and the gate.
func serverSigningStatusView(rec cluster.ServerSigning, g cluster.ServerSigningGate, on bool) upgradewire.ServerSigningStatus {
	out := upgradewire.ServerSigningStatus{On: on, ActiveFSMOpsVersion: g.ActiveFV, NeedsFSMOpsVersion: cluster.ServerSigningFSMOpsVersion, Waiting: g.Waiting}
	at := func(n int64) *time.Time {
		if n <= 0 {
			return nil
		}
		t := time.Unix(0, n).UTC()
		return &t
	}
	if on {
		out.Since, out.OldTokensEnd = at(rec.SinceUnixNano), at(rec.OldTokensEndUnixNano)
	} else if !g.Allowed {
		out.Blocked = g.Reason
	}
	return out
}
