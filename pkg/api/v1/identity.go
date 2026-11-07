package v1

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Cloud identity per sandbox (plans/sandbox-cloud-identity.md section 3).
// The role routes are not sandbox-scoped, so no owner forwarding: in a
// cluster the service writes them through Raft. There is deliberately no
// route that returns a token: only the sandbox receives one.

// putIdentityRole is PUT /v1/identity/roles/{tag}?team=. Idempotent: the
// same body twice changes nothing.
func (h *handlers) putIdentityRole(w http.ResponseWriter, r *http.Request) {
	var req models.IdentityRoleRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	role, err := h.deps.Service.PutIdentityRole(r.Context(), r.URL.Query().Get("team"), r.PathValue("tag"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, role)
}

// listIdentityRoles is GET /v1/identity/roles?team=&cursor=&limit=.
func (h *handlers) listIdentityRoles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			apihttp.WriteError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = n
	}
	page, err := h.deps.Service.ListIdentityRoles(r.Context(), q.Get("team"), q.Get("cursor"), limit)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, page)
}

// deleteIdentityRole is DELETE /v1/identity/roles/{tag}?team=. A tag already
// gone answers 204 too, so a retried DELETE converges.
func (h *handlers) deleteIdentityRole(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteIdentityRole(r.Context(), r.URL.Query().Get("team"), r.PathValue("tag")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// identityKeyRotateRequest is the optional body of the rotate route.
type identityKeyRotateRequest struct {
	// IfActiveKeyID makes a retried rotate a no-op: it rotates only while
	// this key still signs.
	IfActiveKeyID string `json:"if_active_key_id,omitempty"`
}

// rotateIdentityKey is POST /v1/identity/keys/rotate (operator). It answers
// key ids only, never key material.
func (h *handlers) rotateIdentityKey(w http.ResponseWriter, r *http.Request) {
	var req identityKeyRotateRequest
	if r.ContentLength != 0 {
		if err := apihttp.DecodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	out, err := h.deps.Service.RotateIdentityKey(r.Context(), req.IfActiveKeyID)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

// clusterInternalIdentityWrite takes an identity write from a peer (a
// follower forwarding to the leader, or a worker). FSM refusals answer 200
// with a code so the sentinel survives every hop; 503 means retry elsewhere.
func (h *handlers) clusterInternalIdentityWrite(w http.ResponseWriter, r *http.Request) {
	writer, ok := h.deps.Service.Cluster().(interface {
		WriteIdentity(context.Context, cluster.IdentityWriteRequest) (cluster.IdentityWriteResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.IdentityWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := writer.WriteIdentity(r.Context(), req)
	if err != nil {
		if out := cluster.IdentityWriteOutcome(err); out.Code != "" {
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: identity write failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalIdentityRead answers a peer's identity read from this
// server's FSM. The key set it returns holds sealed private keys: the route
// is cluster.internal (a node's PAT over mTLS), and only nodes holding the
// shared server key can open them.
func (h *handlers) clusterInternalIdentityRead(w http.ResponseWriter, r *http.Request) {
	reader, ok := h.deps.Service.Cluster().(interface {
		ReadIdentity(context.Context, cluster.IdentityReadRequest) (cluster.IdentityReadResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.IdentityReadRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := reader.ReadIdentity(r.Context(), req)
	if err != nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}
