package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/docker"
)

func buildContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

type handlers struct {
	deps Deps
}

type buildImageRequest struct {
	DockerfileContent string   `json:"dockerfile_content"`
	ContextHashes     []string `json:"context_hashes,omitempty"`
}

type buildImageResponse struct {
	Image string `json:"image"`
}

func (h *handlers) buildImage(w http.ResponseWriter, r *http.Request) {
	var req buildImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	dockerfile := strings.TrimSpace(req.DockerfileContent)
	if dockerfile == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "dockerfile_content is required")
		return
	}
	if h.deps.Builder == nil {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "image builder is not configured on this daemon")
		return
	}
	if len(req.ContextHashes) > 0 {
		if !h.deps.Build.ContextEnabled {
			apihttp.WriteError(w, http.StatusBadRequest, "context_hashes requires operator-side context upload support (set SB_IMAGE_BUILD_CONTEXT_ENABLED=true)")
			return
		}
		apihttp.WriteError(w, http.StatusNotImplemented, "context_hashes is enabled but no context resolver is configured on this daemon")
		return
	}

	tag := docker.BuildTagFor(dockerfile, req.ContextHashes)
	exists, err := h.deps.Builder.ImageExists(r.Context(), tag)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("check built image cache: %v", err))
		return
	}
	if exists {
		apihttp.WriteJSON(w, http.StatusOK, buildImageResponse{Image: tag})
		return
	}

	buildCtx, cancel := buildContextWithTimeout(r.Context(), h.deps.Build.Timeout)
	defer cancel()
	logger := h.deps.Logger
	err = h.deps.Builder.BuildImage(buildCtx, docker.BuildImageRequest{
		Tag:               tag,
		DockerfileContent: dockerfile,
		OnLog: func(line string) {
			if logger != nil {
				logger.Debug("v2 image build", "tag", tag, "line", line)
			}
		},
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			apihttp.WriteError(w, http.StatusGatewayTimeout, fmt.Sprintf("image build exceeded timeout: %v", err))
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("build image: %v", err))
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, buildImageResponse{Image: tag})
}
