package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// WASM module catalogue handlers mirror /v1/templates but resolve synchronously.

func (h *handlers) createWasmModule(w http.ResponseWriter, r *http.Request) {
	var req models.CreateWasmModuleRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	mod, err := h.deps.Service.CreateWasmModule(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, mod)
}

// pushWasmModule is a stateless proxy: it accepts a raw .wasm body
// (application/octet-stream) with the target repo as ?name=<repo>&tag=<tag>,
// validates and forwards it to the registry under the caller's own PAT (from
// request headers), and returns the oci:// ref. The daemon stores nothing.
func (h *handlers) pushWasmModule(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tag := r.URL.Query().Get("tag")
	username := r.Header.Get("X-Registry-Username")
	token := r.Header.Get("X-Registry-Token")
	resp, err := h.deps.Service.PushWasmModule(r.Context(), name, tag, username, token, r.Body)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, resp)
}

func (h *handlers) listWasmModules(w http.ResponseWriter, r *http.Request) {
	mods, err := h.deps.Service.ListWasmModules(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, mods)
}

func (h *handlers) getWasmModule(w http.ResponseWriter, r *http.Request) {
	mod, err := h.deps.Service.GetWasmModule(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, mod)
}

func (h *handlers) deleteWasmModule(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteWasmModule(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
