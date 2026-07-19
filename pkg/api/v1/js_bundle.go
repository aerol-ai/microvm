package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// JS-bundle catalogue handlers (plans/isolate-runtime.md §8) — the isolate
// runtime's "no image, no registry" upload path. Thin: decode → service →
// encode, with WriteStoreAwareError mapping ErrNotFound/ErrJSBundleInUse to the
// right status. EXPERIMENTAL until the §10.1 demand checkpoint.

func (h *handlers) createJSBundle(w http.ResponseWriter, r *http.Request) {
	var req models.CreateJSBundleRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ctx := r.Context()
	// A cluster peer replicating an uploaded bundle marks the request so the
	// service stores it under the original owner (carried in the header) and
	// does not fan it out again (loop guard).
	if r.Header.Get(models.HeaderJSBundleReplicated) == "1" {
		ctx = service.WithReplicatedJSBundleOwner(ctx, r.Header.Get(models.HeaderJSBundleOwner))
	}
	bundle, err := h.deps.Service.CreateJSBundle(ctx, req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, bundle)
}

func (h *handlers) listJSBundles(w http.ResponseWriter, r *http.Request) {
	bundles, err := h.deps.Service.ListJSBundles(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, bundles)
}

func (h *handlers) getJSBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := h.deps.Service.GetJSBundle(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, bundle)
}

func (h *handlers) deleteJSBundle(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteJSBundle(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
