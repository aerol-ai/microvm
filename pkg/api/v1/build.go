package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterImageBuildRoutedHeader = "X-Cluster-Image-Build-Routed"

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
	if r.Header.Get(clusterImageBuildRoutedHeader) == "1" {
		h.buildImage(w, r)
		return
	}
	if h.deps.Service == nil {
		h.buildImage(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil || !h.deps.Service.ClusterEnabled() {
		h.buildImage(w, r)
		return
	}

	raw, err := apihttp.ReadJSONBody(w, r)
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

	// A built image is local to one worker. Select that worker once and encode
	// its identity in the returned tag; the follow-up create request decodes the
	// affinity and routes back to the same worker. This keeps one SDK build at
	// O(1) work instead of broadcasting it to every Docker worker.
	target, err := c.SelectPlacement(capacity.Request{
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB,
		DiskGB: models.DefaultDiskGB, Runtime: models.RuntimeDocker,
	})
	if err != nil || target.NodeID == "" {
		if err == nil {
			err = cluster.ErrNoPlacementTarget
		}
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster image build placement: "+err.Error())
		return
	}
	if target.IsSelf {
		h.buildImage(w, r)
		return
	}
	member := cluster.Member{
		NodeID: target.NodeID, APIURL: target.APIURL, InternalURL: target.InternalURL,
	}
	status, header, body, err := h.runImageBuildOnTarget(c, r, raw, member, false)
	if err != nil {
		if h.deps.Logger != nil {
			h.deps.Logger.Warn("cluster image build failed", "node", target.NodeID, "err", err)
		}
		apihttp.WriteError(w, http.StatusBadGateway, "cluster image build failed on "+target.NodeID+": "+err.Error())
		return
	}
	if status != http.StatusOK {
		apihttp.WriteError(w, http.StatusBadGateway, "cluster image build failed on "+target.NodeID+": "+strings.TrimSpace(string(body)))
		return
	}
	var built buildImageResponse
	if err := json.Unmarshal(body, &built); err != nil {
		apihttp.WriteError(w, http.StatusBadGateway, "cluster image build returned an invalid response")
		return
	}
	if owner, ok := docker.BuiltImagePlacementNode(built.Image); !ok || owner != target.NodeID {
		apihttp.WriteError(w, http.StatusBadGateway, "cluster image build returned an unbound image tag")
		return
	}
	copyHeaderValues(w.Header(), header)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (h *handlers) runImageBuildOnTarget(c cluster.Client, parent *http.Request, raw []byte, m cluster.Member, self bool) (int, http.Header, []byte, error) {
	if self {
		req := parent.Clone(parent.Context())
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		req.Header = parent.Header.Clone()
		req.Header.Set(clusterImageBuildRoutedHeader, "1")
		rr := httptest.NewRecorder()
		h.buildImage(rr, req)
		return rr.Code, rr.Header(), rr.Body.Bytes(), nil
	}
	client, base, err := dialClusterPeer(c, m)
	if err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequestWithContext(parent.Context(), http.MethodPost,
		base+PathPrefix+"/images/build", bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set(clusterImageBuildRoutedHeader, "1")
	cluster.SetPeerNodeIDHeader(req, c.SelfNodeID())
	if auth := parent.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if ct := parent.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := client.Do(req)
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

// buildImage builds through the service (Service.BuildImage), the one build
// path every surface shares: owner-scoped, node-bound tags, a forced pull
// for tenant builds, and one set of errors.
func (h *handlers) buildImage(w http.ResponseWriter, r *http.Request) {
	var req buildImageRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	build := service.BuildImageRequest{Dockerfile: req.DockerfileContent, ContextHashes: req.ContextHashes}
	if req.Push != nil {
		build.Push = &service.ImagePush{
			Registry: req.Push.Registry,
			Tag:      req.Push.Tag,
			Auth:     models.RegistryAuth{Server: req.Push.Server, Username: req.Push.Username, Password: req.Push.Password},
		}
	}
	built, err := h.deps.Service.BuildImage(r.Context(), build)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, buildImageResponse{Image: built.Image, Pushed: built.Pushed})
}
