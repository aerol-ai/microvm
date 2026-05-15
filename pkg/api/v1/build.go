package v1

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
	"github.com/aerol-ai/microvm/pkg/models"
)

// buildContextWithTimeout returns a child context with the configured build
// timeout. A timeout of zero falls back to plain cancel — the parent's
// deadline (if any) still applies.
func buildContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

type buildImageRequest struct {
	DockerfileContent string              `json:"dockerfile_content"`
	ContextHashes     []string            `json:"context_hashes,omitempty"`
	Push              *buildImagePushSpec `json:"push,omitempty"`
}

// buildImagePushSpec is the per-request push directive. Credentials live
// only on this struct for the duration of one HTTP request: they are
// forwarded straight to the docker daemon as X-Registry-Auth and never
// written to disk or service config.
type buildImagePushSpec struct {
	Registry string `json:"registry"`
	Tag      string `json:"tag,omitempty"`
	Server   string `json:"server,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type buildImageResponse struct {
	Image  string `json:"image"`
	Pushed string `json:"pushed,omitempty"`
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

	if req.Push != nil {
		if strings.TrimSpace(req.Push.Registry) == "" {
			apihttp.WriteError(w, http.StatusBadRequest, "push.registry is required when push is set")
			return
		}
		if req.Push.Username == "" || req.Push.Password == "" {
			apihttp.WriteError(w, http.StatusBadRequest, "push.username and push.password are required when push is set")
			return
		}
	}

	tag := docker.BuildTagFor(dockerfile, req.ContextHashes)
	exists, err := h.deps.Builder.ImageExists(r.Context(), tag)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("check built image cache: %v", err))
		return
	}
	logger := h.deps.Logger
	if exists {
		// Bump LastTagTime so the built-image janitor doesn't GC a tag we
		// just handed out from the cache. Best-effort: a refresh failure
		// only narrows the GC window for this tag, so we log and continue.
		if err := h.deps.Builder.RefreshTag(r.Context(), tag); err != nil && logger != nil {
			logger.Warn("v1 image cache refresh-tag failed", "tag", tag, "error", err)
		}
	}
	if !exists {
		buildCtx, cancel := buildContextWithTimeout(r.Context(), h.deps.Build.Timeout)
		err = h.deps.Builder.BuildImage(buildCtx, docker.BuildImageRequest{
			Tag:               tag,
			DockerfileContent: dockerfile,
			OnLog: func(line string) {
				if logger != nil {
					logger.Debug("v1 image build output received", "tag", tag)
				}
			},
		})
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				apihttp.WriteError(w, http.StatusGatewayTimeout, fmt.Sprintf("image build exceeded timeout: %v", err))
				return
			}
			apihttp.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("build image: %v", err))
			return
		}
	}

	resp := buildImageResponse{Image: tag}
	if req.Push != nil {
		dest := strings.TrimSpace(req.Push.Registry)
		if t := strings.TrimSpace(req.Push.Tag); t != "" {
			dest = dest + ":" + t
		}
		pushCtx, cancel := buildContextWithTimeout(r.Context(), h.deps.Build.Timeout)
		pushed, pushErr := h.deps.Builder.PushImage(pushCtx, docker.PushImageRequest{
			SourceTag: tag,
			DestRef:   dest,
			Auth: models.RegistryAuth{
				Server:   req.Push.Server,
				Username: req.Push.Username,
				Password: req.Push.Password,
			},
			OnLog: func(line string) {
				if logger != nil {
					logger.Debug("v1 image push", "tag", tag, "dest", dest, "line", line)
				}
			},
		})
		cancel()
		if pushErr != nil {
			if errors.Is(pushErr, context.DeadlineExceeded) {
				apihttp.WriteError(w, http.StatusGatewayTimeout, fmt.Sprintf("image push exceeded timeout: %v", pushErr))
				return
			}
			apihttp.WriteError(w, http.StatusBadGateway, fmt.Sprintf("push image: %v", pushErr))
			return
		}
		resp.Pushed = pushed
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}
