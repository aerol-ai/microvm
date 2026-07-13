package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterImageBuildFanoutHeader = "X-Cluster-Image-Build-Fanout"

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

func (h *handlers) clusterBuildImageWrap(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(clusterImageBuildFanoutHeader) == "1" {
		h.buildImage(w, r)
		return
	}
	if h.deps.Service == nil {
		h.buildImage(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.buildImage(w, r)
		return
	}

	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var parsed buildImageRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))

	// Explicit push/context builds have their own distribution semantics. The
	// fanout is for the SDK CreateWithImage path, which returns a local-only
	// aerolvm-build/* tag and immediately creates a Docker sandbox from it.
	if parsed.Push != nil || len(parsed.ContextHashes) > 0 {
		h.buildImage(w, r)
		return
	}
	if clusterSelfCanOwnSandbox(c) {
		h.buildImage(w, r)
		return
	}

	type target struct {
		member cluster.Member
		self   bool
	}
	selfID := c.SelfNodeID()
	targets := make([]target, 0)
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == "" || c.IsNodeDrained(m.NodeID) {
			continue
		}
		if !clusterMemberCanOwnSandbox(m.Role) || !clusterMemberSupportsRuntime(m, models.RuntimeDocker) {
			continue
		}
		isSelf := m.NodeID == selfID
		if !isSelf && m.APIURL == "" {
			continue
		}
		targets = append(targets, target{member: m, self: isSelf})
	}
	if len(targets) == 0 || (len(targets) == 1 && targets[0].self) {
		h.buildImage(w, r)
		return
	}

	var firstStatus int
	var firstHeader http.Header
	var firstBody []byte
	for _, t := range targets {
		status, header, body, err := h.runImageBuildOnTarget(r, raw, t.member, t.self)
		if err != nil {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("cluster image build fanout failed", "node", t.member.NodeID, "err", err)
			}
			apihttp.WriteError(w, http.StatusBadGateway, "cluster image build failed on "+t.member.NodeID+": "+err.Error())
			return
		}
		if status != http.StatusOK {
			apihttp.WriteError(w, http.StatusBadGateway, "cluster image build failed on "+t.member.NodeID+": "+strings.TrimSpace(string(body)))
			return
		}
		if firstStatus == 0 {
			firstStatus = status
			firstHeader = header
			firstBody = body
		}
	}
	copyHeaderValues(w.Header(), firstHeader)
	w.WriteHeader(firstStatus)
	_, _ = w.Write(firstBody)
}

func (h *handlers) runImageBuildOnTarget(parent *http.Request, raw []byte, m cluster.Member, self bool) (int, http.Header, []byte, error) {
	if self {
		req := parent.Clone(parent.Context())
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		req.Header = parent.Header.Clone()
		req.Header.Set(clusterImageBuildFanoutHeader, "1")
		rr := httptest.NewRecorder()
		h.buildImage(rr, req)
		return rr.Code, rr.Header(), rr.Body.Bytes(), nil
	}
	req, err := http.NewRequestWithContext(parent.Context(), http.MethodPost,
		clusterPeerURL(m.APIURL, PathPrefix+"/images/build"), bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set(clusterImageBuildFanoutHeader, "1")
	if auth := parent.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if ct := parent.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header.Clone(), body, nil
}

func (h *handlers) buildImage(w http.ResponseWriter, r *http.Request) {
	var req buildImageRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
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
