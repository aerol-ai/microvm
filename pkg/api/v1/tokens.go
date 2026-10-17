package v1

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
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
	if err := h.deps.Service.RevokeAPIToken(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterInternalAPITokenWrite applies a peer's token write on the leader,
// or forwards it one hop there. FSM verdicts travel in a 200 body so they
// survive the hops; anything else is a 503 the caller retries elsewhere.
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
	resp, err := writer.WriteAPIToken(r.Context(), req)
	if err != nil {
		if out := cluster.APITokenWriteOutcome(err); out.Code != "" {
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: API token write failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
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
