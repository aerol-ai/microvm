package v1

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

// Per-node operator routes for `aerolvm get/describe/cordon/drain/delete
// node` (plans/kubectl-style-cluster-ops.md §3.2, §5). All are new paths:
// /v1 is soft-frozen, so DELETE /v1/cluster/members/{id} keeps answering
// 404 for a worker and the any-role delete lives here.

// nodeDeleteTimeout bounds one delete: a deny record, a drain mark, one
// reassign per failover-recreate sandbox and an orphan, each a Raft apply.
const nodeDeleteTimeout = 30 * time.Second

// clusterGetNode returns one node: its member record, drain mark and the
// sandbox counts `aerolvm drain` waits on, so the CLI never pages the whole
// sandbox index. ?sandboxes=N also lists up to N owned sandbox IDs.
func (h *handlers) clusterGetNode(w http.ResponseWriter, r *http.Request) {
	id, detailer, ok := clusterNodeTarget[cluster.NodeDetailer](h, w, r)
	if !ok {
		return
	}
	detail, err := detailer.NodeDetail(r.Context(), id, parsePositiveIntQuery(r, "sandboxes"))
	if err != nil {
		writeNodeError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, detail)
}

// clusterDeleteNode removes a node of any role (cluster.Cluster.DeleteNode).
// Idempotent: a retry finishes what an earlier call left, and a node that is
// already gone answers 404, which the CLI reads as done.
func (h *handlers) clusterDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, deleter, ok := clusterNodeTarget[cluster.NodeDeleter](h, w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeDeleteTimeout)
	defer cancel()
	res, err := deleter.DeleteNode(ctx, id, parseBoolQuery(r, "force"))
	if err != nil {
		writeNodeError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, res)
}

// clusterNodeTarget reads {id} and the cluster capability a node route
// needs. Single-node mode (Noop) has neither, so it answers 503 like the
// other cluster routes.
func clusterNodeTarget[T any](h *handlers, w http.ResponseWriter, r *http.Request) (string, T, bool) {
	var zero T
	var c cluster.Client
	if h.deps.Service != nil {
		c = h.deps.Service.Cluster()
	}
	capable, ok := c.(T)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not enabled on this node")
		return "", zero, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "node id required")
		return "", zero, false
	}
	return id, capable, true
}

func writeNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cluster.ErrNotCaughtUp):
		clusterroute.WriteNotCaughtUp(w, apihttp.WriteError)
	case errors.Is(err, cluster.ErrNotLeader):
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: not leader")
	case errors.Is(err, cluster.ErrUnknownNode), errors.Is(err, cluster.ErrUnknownMember):
		apihttp.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, cluster.ErrNodeStillServing), errors.Is(err, cluster.ErrMemberStillAlive),
		errors.Is(err, cluster.ErrLastVoter), errors.Is(err, cluster.ErrClusterVersion):
		apihttp.WriteError(w, http.StatusConflict, err.Error())
	default:
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
	}
}

// clusterInternalDeniedNodes serves the deny set to a worker's mirror: 304
// while its cursor is current. Only a server holds the set; a worker asked
// answers 404, which the mirror reads as "none here".
func (h *handlers) clusterInternalDeniedNodes(w http.ResponseWriter, r *http.Request) {
	var c cluster.Client
	if h.deps.Service != nil {
		c = h.deps.Service.Cluster()
	}
	src, ok := c.(cluster.DeniedNodesSource)
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "cluster: this node holds no deny set")
		return
	}
	since, _ := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("since")), 10, 64)
	resp, changed := src.DeniedNodes(since)
	if !changed {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// peerDenied reports a deleted peer on the public API's internal routes.
func peerDenied(d Deps, peerID string) bool {
	if d.Service == nil {
		return false
	}
	return cluster.IsDeniedPeer(d.Service.Cluster(), peerID)
}
