package v1

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Scoped API tokens (plans/identity-and-access.md §5.4). Not sandbox-scoped,
// so never owner-forwarded: in a cluster the service writes through Raft
// from whichever node took the request.
//
//	POST   /v1/tokens       token.write  201 {token once, id, …}; name taken → 409
//	GET    /v1/tokens       token.read   200 {tokens: […]}, never a hash
//	DELETE /v1/tokens/{id}  token.write  204, also when already gone

// createToken mints a token. The plaintext is in this response only.
func (h *handlers) createToken(w http.ResponseWriter, r *http.Request) {
	if h.refuseNodeTokenWrite(w, r, "an API token create") || h.forwardTokenWrite(w, r) {
		return
	}
	var req models.CreateAPITokenRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	created, err := h.deps.Service.CreateAPIToken(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// The call's api record names the token it minted and what it can do,
	// never the secret (plans/identity-and-access.md §5.9).
	auditlog.NoteCreatedToken(r.Context(), created.ID, created.Role, created.Team)
	// The body holds a credential: never cache it anywhere on the way.
	w.Header().Set("Cache-Control", "no-store")
	apihttp.WriteJSON(w, http.StatusCreated, created)
}

func (h *handlers) listTokens(w http.ResponseWriter, r *http.Request) {
	list, err := h.deps.Service.ListAPITokens(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, list)
}

// revokeToken deletes a token. A malformed id is a 400, so a mistyped id is
// never silently "revoked"; a well-formed one that is gone is a 204.
func (h *handlers) revokeToken(w http.ResponseWriter, r *http.Request) {
	if h.refuseNodeTokenWrite(w, r, "an API token revoke") || h.forwardTokenWrite(w, r) {
		return
	}
	if err := h.deps.Service.RevokeAPIToken(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tokenWritePeerChecker is the role binding for token writes
// (Cluster.IsTokenWritePeer): servers and ingress (gateway) nodes.
type tokenWritePeerChecker interface {
	IsTokenWritePeer(peerID string) bool
}

// refuseNodeTokenWrite answers a token write a node makes on its own behalf
// (a node principal: its certificate, or the PAT over mTLS) unless the node
// is a server or a gateway: token writes come only from those (defense in
// depth). A caller's own credential that a worker forwarded is that caller,
// not the node, and passes. It reports whether it answered.
func (h *handlers) refuseNodeTokenWrite(w http.ResponseWriter, r *http.Request, what string) bool {
	access, ok := controlplane.AccessFromContext(r.Context())
	if !ok || access.Principal.Kind != controlplane.PrincipalNode {
		return false
	}
	peer := strings.TrimPrefix(access.Principal.ID, "node:")
	if checker, ok := h.deps.Service.Cluster().(tokenWritePeerChecker); ok && checker.IsTokenWritePeer(peer) {
		return false
	}
	if h.deps.Logger != nil {
		h.deps.Logger.Warn("cluster: refused a token write a node made for itself", "what", what, "peer", peer)
	}
	apihttp.WriteError(w, http.StatusForbidden, fmt.Sprintf("%s by node %q: a node's own identity cannot write tokens here, only a server's or a gateway's; send the call with an operator token or a user token", what, peer))
	return true
}

// tokenServerForwarder is a worker's way to a server (Agent.ForwardToServer).
type tokenServerForwarder interface {
	ForwardToServer(http.ResponseWriter, *http.Request)
}

// forwardTokenWrite sends a caller's token create or revoke on to a server
// when this node does not write tokens (a worker), so a cluster whose API
// address reaches only workers can still create and revoke them. Only with
// the caller's own credential: the server authenticates the caller itself,
// and a call that carries none is refused here, never sent as this node.
// It reports whether it answered.
func (h *handlers) forwardTokenWrite(w http.ResponseWriter, r *http.Request) bool {
	if !h.deps.Service.ForwardsAPITokenWrites() {
		return false
	}
	if scheme, cred, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " "); !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(cred) == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "this worker node sends token writes on to a server with your own credential, and this call carries none: send it with an Authorization header, or to a server or gateway")
		return true
	}
	fw, ok := h.deps.Service.Cluster().(tokenServerForwarder)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, cluster.ErrNoServerForward.Error())
		return true
	}
	fw.ForwardToServer(w, r)
	return true
}

// clusterInternalAPITokenWrite applies a peer's token write on the leader,
// or forwards it one hop there. FSM verdicts travel in a 200 body so they
// survive the hops; anything else is a 503 the caller retries elsewhere.
// Only a server or a gateway may send one (IsTokenWritePeer). Every write
// is recorded here with the sending node and the record's created_by, a
// refused one at most once a minute per node (RecordInternalTokenWrite):
// the cluster.internal routes are otherwise never recorded (api_audit.go).
func (h *handlers) clusterInternalAPITokenWrite(w http.ResponseWriter, r *http.Request) {
	writer, ok := h.deps.Service.Cluster().(interface {
		WriteAPIToken(context.Context, cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error)
	})
	if !ok || !servesTokenState(h) {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.APITokenWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	checker, ok := h.deps.Service.Cluster().(tokenWritePeerChecker)
	if !ok || !checker.IsTokenWritePeer(peerID) {
		if h.deps.Logger != nil {
			h.deps.Logger.Warn("cluster: refused an API token write from a node that may not send one", "peer", peerID,
				"token_id", tokenWriteID(req), "created_by", req.Token.CreatedBy)
		}
		h.deps.Service.RecordInternalTokenWrite(r.Context(), peerID, req, http.StatusForbidden, true)
		apihttp.WriteJSON(w, http.StatusOK, cluster.APITokenWriteOutcome(
			fmt.Errorf("%w: node %q is not a server or an ingress node", cluster.ErrAPITokenWriterRefused, peerID)))
		return
	}
	resp, err := writer.WriteAPIToken(r.Context(), req)
	if err != nil {
		if out := cluster.APITokenWriteOutcome(err); out.Code != "" {
			h.deps.Service.RecordInternalTokenWrite(r.Context(), peerID, req, http.StatusConflict, false)
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		h.deps.Service.RecordInternalTokenWrite(r.Context(), peerID, req, http.StatusServiceUnavailable, false)
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: API token write failed: "+err.Error())
		return
	}
	h.deps.Service.RecordInternalTokenWrite(r.Context(), peerID, req, http.StatusOK, false)
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// tokenWriteID is the token a write names: the record's for a create, the
// id for a revoke.
func tokenWriteID(req cluster.APITokenWriteRequest) string {
	if req.Delete {
		return req.ID
	}
	return req.Token.ID
}

// apiTokenFeed is what a Raft server serves its peers' token mirrors from.
type apiTokenFeed interface {
	APITokenChanges(since uint64) (identity.TokenChanges, bool)
	APITokenPage(after string, limit int) identity.TokenPage
}

// servesTokenState reports whether this node holds the token FSM (a Raft
// server). A worker answering the feed would hand out its own empty view.
func servesTokenState(h *handlers) bool {
	_, ok := h.deps.Service.Cluster().(apiTokenFeed)
	return ok
}

// clusterInternalAPITokenChanges is a mirror's poll. A current cursor is a
// 304 with no body: one compare under a read lock, so 2,000 mirrors polling
// every 5 s cost the server tier next to nothing.
func (h *handlers) clusterInternalAPITokenChanges(w http.ResponseWriter, r *http.Request) {
	feed, ok := h.deps.Service.Cluster().(apiTokenFeed)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: API token feed not served by this node")
		return
	}
	var since uint64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "since must be an unsigned integer")
			return
		}
		since = v
	}
	resp, changed := feed.APITokenChanges(since)
	if !changed {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalAPITokenPage is one page of a mirror's page walk.
func (h *handlers) clusterInternalAPITokenPage(w http.ResponseWriter, r *http.Request) {
	feed, ok := h.deps.Service.Cluster().(apiTokenFeed)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: API token feed not served by this node")
		return
	}
	q := r.URL.Query()
	limit := 0
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			apihttp.WriteError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = v
	}
	apihttp.WriteJSON(w, http.StatusOK, feed.APITokenPage(strings.TrimSpace(q.Get("after")), limit))
}
