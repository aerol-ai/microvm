package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// clusterEvacuateLeaderHeader marks an evacuate already forwarded to the
// leader, so a leader change mid-forward answers 503 instead of looping.
const clusterEvacuateLeaderHeader = "X-Cluster-Evacuate-Leader"

// evacuateTimeout bounds one pass: up to maxEvacuateMoves moves side by
// side, each a pre-pull (cluster.prepareMoveTimeout) then a release.
const evacuateTimeout = 5 * time.Minute

// clusterEvacuateNode runs one decommission pass over {id} (C9,
// internal/cluster/decommission.go). The leader runs it; any other server
// forwards it there. Idempotent: the operator calls it until done.
func (h *handlers) clusterEvacuateNode(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil || h.deps.Service.Cluster() == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return
	}
	if ev, isServer := c.(cluster.NodeEvacuator); isServer && c.Leader() == c.SelfNodeID() {
		var req cluster.EvacuateRequest
		if r.ContentLength != 0 {
			if err := apihttp.DecodeJSON(w, r, &req); err != nil {
				apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), evacuateTimeout)
		defer cancel()
		res, err := ev.EvacuateNode(ctx, id, req)
		switch {
		case errors.Is(err, cluster.ErrNodeNotDrained), errors.Is(err, cluster.ErrNodeNotAlive):
			apihttp.WriteError(w, http.StatusConflict, err.Error())
		case errors.Is(err, cluster.ErrNotLeader):
			w.Header().Set("Retry-After", "1")
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
		case err != nil:
			apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		default:
			apihttp.WriteJSON(w, http.StatusOK, res)
		}
		return
	}
	if r.Header.Get(clusterEvacuateLeaderHeader) == "1" {
		w.Header().Set("Retry-After", "1")
		apihttp.WriteError(w, http.StatusServiceUnavailable, "the leader changed while this call was forwarded; retry")
		return
	}
	if !h.forwardTemplateToLeader(w, r, c, clusterEvacuateLeaderHeader) {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: this node is not a cluster server")
	}
}

// clusterNodeMove is the worker's half of a decommission (the internal
// route the leader calls): release a sandbox for a move, stop one at the
// deadline, tell owners, or pull an image ahead. Only the current leader
// may ask, and only for this node: a stop here is not something any other
// peer may order.
func (h *handlers) clusterNodeMove(w http.ResponseWriter, r *http.Request) {
	if h.deps.Service == nil || h.deps.Service.Cluster() == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return
	}
	c := h.deps.Service.Cluster()
	if id := strings.TrimSpace(r.PathValue("id")); id != c.SelfNodeID() {
		apihttp.WriteError(w, http.StatusMisdirectedRequest, "cluster: this is not node "+id)
		return
	}
	peerID, _ := r.Context().Value(clusterPeerNodeIDContextKey{}).(string)
	if strings.TrimSpace(peerID) == "" || peerID != c.Leader() {
		apihttp.WriteError(w, http.StatusForbidden, "cluster: only the leader moves sandboxes")
		return
	}
	var a cluster.MoveAction
	if err := apihttp.DecodeJSON(w, r, &a); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	out, err := cluster.RunMoveAction(r.Context(), h.deps.Service, a)
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}
