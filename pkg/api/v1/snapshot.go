package v1

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// registerSnapshotRequest is the v1-native shape for POST /v1/snapshots.
// Exactly one of Image (pre-built registry reference) or DockerfileContent
// (build inputs) must be set. The remaining fields configure the resource
// hints clients get back when they later look the snapshot up by name.
type registerSnapshotRequest struct {
	Name              string   `json:"name"`
	Image             string   `json:"image,omitempty"`
	DockerfileContent string   `json:"dockerfile_content,omitempty"`
	ContextHashes     []string `json:"context_hashes,omitempty"`
	Entrypoint        []string `json:"entrypoint,omitempty"`
	RegionID          string   `json:"region_id,omitempty"`
	CPU               float64  `json:"cpu,omitempty"`
	GPU               float64  `json:"gpu,omitempty"`
	MemoryMB          int      `json:"memory_mb,omitempty"`
	DiskGB            int      `json:"disk_gb,omitempty"`
}

// registerSnapshot is the v1-native equivalent of POST /daytona/snapshots.
// It persists a snapshot row pointing at either a caller-supplied image
// reference or a freshly built tag from a Dockerfile.
//
// Image-resolution paths:
//
//  1. Image — trust the caller; the runtime's docker pull at sandbox-create
//     time will fail loudly if the image doesn't exist.
//  2. DockerfileContent — content-addressed build through Builder.BuildImage.
//     A single-line `FROM <image>` short-circuits without a build, matching
//     the daytona facade and the existing v1 build endpoint behavior.
//
// ContextHashes is gated behind SB_IMAGE_BUILD_CONTEXT_ENABLED; the
// daemon-side context resolver is not yet wired, so requests with
// non-empty ContextHashes return 501 today.
func (h *handlers) registerSnapshot(w http.ResponseWriter, r *http.Request) {
	var req registerSnapshotRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	image := strings.TrimSpace(req.Image)
	dockerfile := strings.TrimSpace(req.DockerfileContent)
	switch {
	case image == "" && dockerfile == "":
		apihttp.WriteError(w, http.StatusBadRequest, "image or dockerfile_content is required")
		return
	case image != "" && dockerfile != "":
		apihttp.WriteError(w, http.StatusBadRequest, "image and dockerfile_content are mutually exclusive")
		return
	}

	snapshot := &models.SandboxSnapshot{
		Name:       name,
		Image:      image,
		Entrypoint: append([]string{}, req.Entrypoint...),
		RegionID:   strings.TrimSpace(req.RegionID),
		CPU:        req.CPU,
		GPU:        req.GPU,
		MemoryMB:   req.MemoryMB,
		DiskGB:     req.DiskGB,
	}

	var registered *models.SandboxSnapshot
	var err error
	if dockerfile != "" {
		registered, err = h.deps.Service.RegisterSnapshotFromDockerfile(r.Context(), snapshot, service.BuildImageRequest{Dockerfile: dockerfile, ContextHashes: req.ContextHashes})
	} else {
		registered, err = h.deps.Service.RegisterSnapshot(r.Context(), snapshot)
	}
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, registered)
}
