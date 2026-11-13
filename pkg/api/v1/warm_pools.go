package v1

import (
	"context"
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Warm pools as an API object (plans/agent-sandbox-feature-parity.md W1).
// The image is the rest of the path, slashes included, so an image such as
// ghcr.io/acme/agent:1 needs no escaping (an escaped one works too).

// putWarmPool creates or replaces an image's entry. The body is a full
// replace, so the same body twice is a no-op.
func (h *handlers) putWarmPool(w http.ResponseWriter, r *http.Request) {
	var req models.WarmPoolRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	p, err := h.deps.Service.PutWarmPool(r.Context(), r.PathValue("image"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, p)
}

func (h *handlers) getWarmPool(w http.ResponseWriter, r *http.Request) {
	p, err := h.deps.Service.GetWarmPool(r.Context(), r.PathValue("image"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, p)
}

func (h *handlers) listWarmPools(w http.ResponseWriter, r *http.Request) {
	list, err := h.deps.Service.ListWarmPools(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, list)
}

// deleteWarmPool removes an image's entry; one that is already gone counts
// as deleted.
func (h *handlers) deleteWarmPool(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteWarmPool(r.Context(), r.PathValue("image")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterInternalWarmPoolWrite applies a peer's entry write on this server:
// the leader applies it, a follower forwards it one hop. The FSM's refusals
// travel as a 200 body with an outcome code so they survive the hops.
func (h *handlers) clusterInternalWarmPoolWrite(w http.ResponseWriter, r *http.Request) {
	writer, ok := h.deps.Service.Cluster().(interface {
		WriteWarmPool(context.Context, cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.WarmPoolWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := writer.WriteWarmPool(r.Context(), req)
	if err != nil {
		if out := cluster.WarmPoolWriteOutcome(err); out.Code != "" {
			apihttp.WriteJSON(w, http.StatusOK, out)
			return
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: warm pool write failed: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalWarmPoolRead answers a worker's poll from this server's
// FSM.
func (h *handlers) clusterInternalWarmPoolRead(w http.ResponseWriter, r *http.Request) {
	reader, ok := h.deps.Service.Cluster().(interface {
		ReadWarmPools(context.Context, cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.WarmPoolReadRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resp, err := reader.ReadWarmPools(r.Context(), req)
	if err != nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// clusterInternalRunStates records an owner's run-state batch on this
// server: the leader applies it, a follower forwards it one hop
// (cluster.SetRunStates).
func (h *handlers) clusterInternalRunStates(w http.ResponseWriter, r *http.Request) {
	writer, ok := h.deps.Service.Cluster().(cluster.RunStatePublisher)
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: node holds no placement state")
		return
	}
	var req cluster.RunStateWriteRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	applied, err := writer.SetRunStates(r.Context(), req.Reports)
	if errors.Is(err, cluster.ErrBadRunStateBatch) {
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: run states: "+err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.RunStateWriteResponse{Applied: applied})
}
