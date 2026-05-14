package v1

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// handlers carries Deps so each handler method has access to the service,
// logger, and shared response helpers without threading them through every
// signature. Handlers are intentionally thin — wire decode → service call →
// wire encode — so the v1/v2 boundary stays at this layer.
type handlers struct {
	deps Deps
}

func (h *handlers) reconcile(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.Reconcile(r.Context()); err != nil {
		h.deps.Logger.Warn("reconcile failed", "error", err)
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *handlers) capacity(w http.ResponseWriter, r *http.Request) {
	apihttp.WriteJSON(w, http.StatusOK, h.deps.Service.Capacity())
}

func (h *handlers) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	response, err := h.deps.Service.CreateSandbox(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, response)
}

func (h *handlers) listSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context())
	if err != nil {
		h.deps.Logger.Warn("list sandboxes failed", "error", err)
		apihttp.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandboxes)
}

func (h *handlers) getSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) startSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.StartSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) stopSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.StopSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxSnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	response, err := h.deps.Service.CreateSnapshot(r.Context(), r.PathValue("id"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, response)
}

func (h *handlers) destroySandbox(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DestroySandbox(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) resizeSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.ResizeSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sandbox, err := h.deps.Service.ResizeSandbox(r.Context(), r.PathValue("id"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) updateLifecycle(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sandbox, err := h.deps.Service.UpdateLifecycle(r.Context(), r.PathValue("id"), req.Lifecycle)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) exposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}
	// Body is optional — legacy callers POST with no body and get HTTP routing.
	// New callers send {"protocol":"tcp"} or {"protocol":"tls"} to choose a
	// caddy-l4 path. ContentLength == 0 is the unambiguous "no body" signal;
	// we intentionally don't strict-decode an empty stream so old SDKs keep
	// working unchanged.
	var req models.ExposePortRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	resp, err := h.deps.Service.ExposePort(r.Context(), r.PathValue("id"), port, req.Protocol)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

func (h *handlers) unexposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if err := h.deps.Service.UnexposePort(r.Context(), r.PathValue("id"), port); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listMounts(w http.ResponseWriter, r *http.Request) {
	mounts, err := h.deps.Service.ListMounts(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"mounts": mounts})
}

func (h *handlers) getNetworkUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := h.deps.Service.GetNetworkUsage(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, usage)
}

func (h *handlers) updateNetworkLimits(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateNetworkLimitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	// Pointer-nil ⇒ "leave alone"; pointer-to-zero ⇒ "set to unlimited".
	// Read the existing limits when only one direction is supplied so the
	// other direction round-trips unchanged.
	current, err := h.deps.Service.GetNetworkUsage(r.Context(), id)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	in := current.BytesInLimit
	if req.NetworkBytesInLimit != nil {
		in = *req.NetworkBytesInLimit
	}
	out := current.BytesOutLimit
	if req.NetworkBytesOutLimit != nil {
		out = *req.NetworkBytesOutLimit
	}
	usage, err := h.deps.Service.SetNetworkLimits(r.Context(), id, in, out)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, usage)
}
