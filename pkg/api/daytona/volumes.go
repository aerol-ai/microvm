package daytona

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// volumeResponse is the Daytona-shaped view of a platform volume. The SDK's
// Volume model carries id/name/state/createdAt; "ready" is the only state we
// expose because the backing prefix exists implicitly on first attach.
type volumeResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	CreatedAt string `json:"createdAt"`
}

type createVolumeRequest struct {
	Name string `json:"name"`
}

func toVolumeResponse(v *models.Volume) volumeResponse {
	return volumeResponse{
		ID:        v.ID,
		Name:      v.Name,
		State:     "ready",
		CreatedAt: v.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// createVolume handles POST /volumes — get-or-create the named volume for the
// caller's tenant.
func (h *handlers) createVolume(w http.ResponseWriter, r *http.Request) {
	var req createVolumeRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	vol, err := h.deps.Service.CreatePlatformVolume(r.Context(), req.Name)
	if err != nil {
		writeVolumeError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, toVolumeResponse(vol))
}

// listVolumes handles GET /volumes.
func (h *handlers) listVolumes(w http.ResponseWriter, r *http.Request) {
	vols, err := h.deps.Service.ListPlatformVolumes(r.Context())
	if err != nil {
		writeVolumeError(w, err)
		return
	}
	out := make([]volumeResponse, 0, len(vols))
	for i := range vols {
		out = append(out, toVolumeResponse(&vols[i]))
	}
	apihttp.WriteJSON(w, http.StatusOK, out)
}

// getVolume handles GET /volumes/{volumeId}.
func (h *handlers) getVolume(w http.ResponseWriter, r *http.Request) {
	vol, err := h.deps.Service.GetPlatformVolume(r.Context(), r.PathValue("volumeId"))
	if err != nil {
		writeVolumeError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, toVolumeResponse(vol))
}

// getVolumeByName handles GET /volumes/by-name/{name}.
func (h *handlers) getVolumeByName(w http.ResponseWriter, r *http.Request) {
	vol, err := h.deps.Service.GetPlatformVolumeByName(r.Context(), r.PathValue("name"))
	if err != nil {
		writeVolumeError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, toVolumeResponse(vol))
}

// deleteVolume handles DELETE /volumes/{volumeId}. Reference-aware: a volume
// still attached to a live sandbox returns 409.
func (h *handlers) deleteVolume(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeletePlatformVolume(r.Context(), r.PathValue("volumeId")); err != nil {
		writeVolumeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeVolumeError maps the volume sentinels to Daytona HTTP codes: 412 when the
// feature is off, 409 for in-use/quota conflicts, 404 for a missing volume, 400
// for a bad name, and 400 as the catch-all for other validation errors.
func writeVolumeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, models.ErrPlatformVolumesDisabled):
		apihttp.WriteError(w, http.StatusPreconditionFailed, err.Error())
	case errors.Is(err, models.ErrPlatformVolumeInUse), errors.Is(err, models.ErrPlatformVolumeQuota):
		apihttp.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrNotFound):
		apihttp.WriteError(w, http.StatusNotFound, "volume not found")
	default:
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
	}
}
