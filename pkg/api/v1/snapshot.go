package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/docker"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	resolvedImage := image
	var freshlyBuiltTag string
	if dockerfile != "" {
		resolved, built, err := h.resolveSnapshotImage(r.Context(), dockerfile, req.ContextHashes)
		if err != nil {
			h.writeBuildError(w, err)
			return
		}
		resolvedImage = resolved
		freshlyBuiltTag = built
	}

	snapshot := &models.SandboxSnapshot{
		Name:       name,
		Image:      resolvedImage,
		Entrypoint: append([]string{}, req.Entrypoint...),
		RegionID:   strings.TrimSpace(req.RegionID),
		CPU:        req.CPU,
		GPU:        req.GPU,
		MemoryMB:   req.MemoryMB,
		DiskGB:     req.DiskGB,
	}

	registered, err := h.deps.Service.RegisterSnapshot(r.Context(), snapshot)
	if err != nil {
		// Roll back a freshly built tag — if we don't, the built-image
		// janitor would leak the layer because no snapshot row points at it.
		if freshlyBuiltTag != "" && h.deps.Builder != nil {
			if rbErr := h.deps.Builder.RemoveImage(r.Context(), freshlyBuiltTag); rbErr != nil && h.deps.Logger != nil {
				h.deps.Logger.Warn("v1 snapshot rollback failed", "tag", freshlyBuiltTag, "error", rbErr)
			}
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, registered)
}

// resolveSnapshotImage turns a Dockerfile (+ optional context hashes) into
// a runnable local image tag. Mirrors daytona.resolveBuildInfo without
// pulling the daytona package into v1.
func (h *handlers) resolveSnapshotImage(ctx context.Context, dockerfile string, contextHashes []string) (string, string, error) {
	if base, ok := singleLineFROM(dockerfile); ok && len(contextHashes) == 0 {
		return base, "", nil
	}
	if len(contextHashes) > 0 {
		if !h.deps.Build.ContextEnabled {
			return "", "", errors.New("context_hashes requires operator-side context upload support (set SB_IMAGE_BUILD_CONTEXT_ENABLED=true)")
		}
		// The hash → blob resolver lives in object-storage wiring that
		// hasn't landed yet. Fail loud so the COPY/ADD steps don't
		// silently no-op.
		return "", "", errBuildNotImplemented
	}
	if h.deps.Builder == nil {
		return "", "", errors.New("multi-line dockerfile_content requires an image builder; daemon was started without one")
	}

	tag := docker.BuildTagFor(dockerfile, contextHashes)
	exists, err := h.deps.Builder.ImageExists(ctx, tag)
	if err != nil {
		return "", "", fmt.Errorf("%w: check built image cache: %v", errBuildOperationalV1, err)
	}
	logger := h.deps.Logger
	if exists {
		if rtErr := h.deps.Builder.RefreshTag(ctx, tag); rtErr != nil && logger != nil {
			logger.Warn("v1 snapshot build cache refresh-tag failed", "tag", tag, "error", rtErr)
		}
		return tag, "", nil
	}

	buildCtx, cancel := buildContextWithTimeout(ctx, h.deps.Build.Timeout)
	defer cancel()
	err = h.deps.Builder.BuildImage(buildCtx, docker.BuildImageRequest{
		Tag:               tag,
		DockerfileContent: dockerfile,
		OnLog: func(line string) {
			if logger != nil {
				logger.Debug("v1 snapshot build", "tag", tag, "line", line)
			}
		},
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", "", fmt.Errorf("%w: %v", errBuildTimeoutV1, err)
		}
		return "", "", fmt.Errorf("%w: build image: %v", errBuildOperationalV1, err)
	}
	return tag, tag, nil
}

// writeBuildError maps the sentinel errors from resolveSnapshotImage to the
// appropriate HTTP code. Validation errors (bad payload, flag disabled,
// missing builder) → 400 / 501; daemon failures → 502 / 504.
func (h *handlers) writeBuildError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBuildTimeoutV1):
		apihttp.WriteError(w, http.StatusGatewayTimeout, err.Error())
	case errors.Is(err, errBuildOperationalV1):
		apihttp.WriteError(w, http.StatusBadGateway, err.Error())
	case errors.Is(err, errBuildNotImplemented):
		apihttp.WriteError(w, http.StatusNotImplemented, err.Error())
	default:
		apihttp.WriteError(w, http.StatusBadRequest, err.Error())
	}
}

// Sentinel errors so writeBuildError can classify without string-matching.
var (
	errBuildOperationalV1  = errors.New("v1 build operational error")
	errBuildTimeoutV1      = errors.New("v1 build exceeded timeout")
	errBuildNotImplemented = errors.New("context_hashes is enabled but no context resolver is configured on this daemon")
)

// singleLineFROM detects the legacy `FROM <image>` shape and returns the
// base image when matched. Comments and blank lines are ignored.
// Mirrors daytona.singleLineFromImage.
func singleLineFROM(dockerfile string) (string, bool) {
	lines := make([]string, 0, 4)
	for _, line := range strings.Split(dockerfile, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	if len(lines) != 1 {
		return "", false
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "FROM") {
		return "", false
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}
