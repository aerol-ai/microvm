package v1

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
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

// snapshotListResponse is the v1-native page shape for GET /v1/snapshots. It
// pages in the store (keyset by name), so a list costs one bounded range scan
// however large the catalogue is — never a whole-table read.
type snapshotListResponse struct {
	Snapshots []*models.SandboxSnapshot `json:"snapshots"`
	HasMore   bool                      `json:"has_more"`
}

// listSnapshots is GET /v1/snapshots — one name-ordered page of the caller's
// snapshots. starting_after is the exclusive name cursor; limit caps the page.
func (h *handlers) listSnapshots(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			apihttp.WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	limit = min(limit, clusterlist.MaxPageLimit)
	after := strings.TrimSpace(r.URL.Query().Get("starting_after"))

	// Read one extra row to decide has_more without a second count query.
	rows, err := h.deps.Service.ListSnapshotPage(r.Context(), "", "", after, limit+1)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	snapshots := make([]*models.SandboxSnapshot, 0, len(rows))
	for _, row := range rows {
		snapshots = append(snapshots, row.Snapshot)
	}
	apihttp.WriteJSON(w, http.StatusOK, snapshotListResponse{Snapshots: snapshots, HasMore: hasMore})
}

// getSnapshot is GET /v1/snapshots/{id} — a snapshot looked up by name (or
// image id). The route is wrapped so a cluster request reaches the node that
// holds the image (B6); on a single node it reads the local store.
func (h *handlers) getSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := h.deps.Service.GetSnapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, snapshot)
}

// deleteSnapshot is DELETE /v1/snapshots/{id}. Deleting a missing snapshot is a
// 404 (via ErrNotFound); a successful delete is 204. Wrapped for home-node
// routing so the image is removed on the node that holds it (B6).
func (h *handlers) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.DeleteSnapshot(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// snapshotForwardWrap routes a v1 snapshot-by-id request to the node holding the
// image (B6). A v1 snapshot id is its name, so the resolver is the path value.
func (h *handlers) snapshotForwardWrap(local http.Handler) http.Handler {
	return clusterroute.WrapSnapshot(h.deps.Service, func(r *http.Request) string {
		return r.PathValue("id")
	}, apihttp.WriteError, local)
}
