package v1

import (
	"context"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Team quotas (plan item P2). Thin handlers: decode, service call, encode.
// PUT and DELETE are idempotent: the same body twice changes nothing, and a
// DELETE of a quota already gone answers 204.

func (h *handlers) putTeamQuota(w http.ResponseWriter, r *http.Request) {
	var req models.TeamQuotaRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	q, err := h.deps.Service.PutTeamQuota(r.Context(), r.PathValue("team"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, q)
}

func (h *handlers) getTeamQuota(w http.ResponseWriter, r *http.Request) {
	q, err := h.deps.Service.GetTeamQuota(r.Context(), r.PathValue("team"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, q)
}

func (h *handlers) deleteTeamQuota(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteTeamQuota(r.Context(), r.PathValue("team")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterInternalTeamQuotaWrite applies a quota write on the leader (or
// forwards it one hop there) for a peer or a worker.
func (h *handlers) clusterInternalTeamQuotaWrite(w http.ResponseWriter, r *http.Request) {
	writer, ok := h.deps.Service.Cluster().(interface {
		WriteTeamQuota(context.Context, cluster.TeamQuotaWriteRequest) (cluster.TeamQuotaWriteResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.TeamQuotaWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := writer.WriteTeamQuota(r.Context(), req)
	if err != nil {
		if out := cluster.TeamQuotaWriteOutcome(err); out.Code != "" {
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: team quota write failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalTeamQuotaRead answers a worker's quota read from this
// server's FSM.
func (h *handlers) clusterInternalTeamQuotaRead(w http.ResponseWriter, r *http.Request) {
	reader, ok := h.deps.Service.Cluster().(interface {
		ReadTeamQuota(context.Context, cluster.TeamQuotaReadRequest) (cluster.TeamQuotaReadResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.TeamQuotaReadRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := reader.ReadTeamQuota(r.Context(), req)
	if err != nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: team quota read failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}
