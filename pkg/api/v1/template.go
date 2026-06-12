package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Template handlers — POST/GET/LIST/DELETE for the Firecracker template
// pipeline (plans/snapshot-clone-fast-boot.md Phase 2). These routes are
// per-host: a template's rootfs.ext4 lives on the node it was built on,
// so we deliberately skip clusterForwardWrap. A Phase 6 follow-up will
// add cross-node fan-out for list and ownership-based routing for the
// per-id paths once template distribution is in scope.

// createTemplate accepts an OCI image reference and persists a PENDING
// row, returning 202. The actual skopeo+umoci+mkfs.ext4 pipeline runs
// in a background goroutine inside the service layer; callers poll GET
// /v1/templates/{id} to observe READY (or FAILED with last_error).
func (h *handlers) createTemplate(w http.ResponseWriter, r *http.Request) {
	var req models.CreateTemplateRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	template, err := h.deps.Service.CreateTemplate(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusAccepted, template)
}

func (h *handlers) listTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := h.deps.Service.ListTemplates(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, templates)
}

func (h *handlers) getTemplate(w http.ResponseWriter, r *http.Request) {
	template, err := h.deps.Service.GetTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, template)
}

func (h *handlers) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteTemplate(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rebuildTemplate is the operator-triggered snapshot rebuild
// (plans/snapshot-clone-fast-boot.md Phase 6 follow-up). Idempotent under
// concurrent retry: the CAS in MarkSnapshotCorrupt ensures N parallel
// callers against the same ready template collapse to one rebuild kick.
// 202 mirrors the create-template shape so SDK callers reuse their
// existing "poll status until ready" code path.
func (h *handlers) rebuildTemplate(w http.ResponseWriter, r *http.Request) {
	tpl, err := h.deps.Service.RequestTemplateRebuild(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusAccepted, tpl)
}
