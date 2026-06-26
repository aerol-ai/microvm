package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterTemplateForwardedHeader = "X-Cluster-Template-Forwarded"

// Template handlers — POST/GET/LIST/DELETE for the Firecracker template
// pipeline (plans/snapshot-clone-fast-boot.md Phase 2). Template artifacts
// live on the worker that built them, so cluster mode routes creates to a
// Firecracker-capable worker and fans reads/mutations across those workers.

func (h *handlers) clusterCreateTemplateWrap(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(clusterTemplateForwardedHeader) == "1" {
		h.createTemplate(w, r)
		return
	}
	if h.deps.Service == nil {
		h.createTemplate(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.createTemplate(w, r)
		return
	}
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))

	target, err := c.SelectPlacement(capacity.Request{
		CPU:      models.DefaultCPU,
		MemoryMB: models.DefaultMemoryMB,
		DiskGB:   models.DefaultDiskGB,
		Runtime:  models.RuntimeFirecracker,
	})
	if err != nil {
		if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, "placement: "+err.Error())
		return
	}
	if target.IsSelf {
		h.createTemplate(w, r)
		return
	}
	r.Header.Set(clusterTemplateForwardedHeader, "1")
	c.ForwardHTTP(cluster.Endpoint{InternalURL: target.InternalURL, APIURL: target.APIURL}, w, r)
}

func (h *handlers) clusterListTemplatesWrap(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(clusterTemplateForwardedHeader) == "1" {
		h.listTemplates(w, r)
		return
	}
	if h.deps.Service == nil {
		h.listTemplates(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.listTemplates(w, r)
		return
	}
	peers := clusterTemplatePeers(c)
	if len(peers) > clusterListMaxFanoutPeers {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster template list fanout exceeds safe peer cap")
		return
	}

	local, localErr := h.deps.Service.ListTemplates(r.Context())
	if localErr != nil && h.deps.Logger != nil {
		h.deps.Logger.Warn("cluster templates: local list failed", "err", localErr)
	}
	merged := make([]*models.Template, 0, len(local))
	seen := map[string]struct{}{}
	for _, tpl := range local {
		if tpl == nil {
			continue
		}
		seen[tpl.ID] = struct{}{}
		merged = append(merged, tpl)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, peer := range peers {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
			clusterPeerURL(peer.APIURL, r.URL.RequestURI()), nil)
		if err != nil {
			continue
		}
		req.Header.Set(clusterTemplateForwardedHeader, "1")
		if auth := r.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("cluster templates: peer list failed", "peer", peer.NodeID, "err", err)
			}
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				if h.deps.Logger != nil {
					h.deps.Logger.Warn("cluster templates: peer list returned error",
						"peer", peer.NodeID, "status", resp.StatusCode, "body", strings.TrimSpace(string(body)))
				}
				return
			}
			var rows []*models.Template
			if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
				if h.deps.Logger != nil {
					h.deps.Logger.Warn("cluster templates: decode peer list failed", "peer", peer.NodeID, "err", err)
				}
				return
			}
			for _, tpl := range rows {
				if tpl == nil {
					continue
				}
				if _, ok := seen[tpl.ID]; ok {
					continue
				}
				seen[tpl.ID] = struct{}{}
				merged = append(merged, tpl)
			}
		}()
	}
	if localErr != nil && len(merged) == 0 {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, localErr)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, merged)
}

func (h *handlers) clusterTemplateItemWrap(local http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(clusterTemplateForwardedHeader) == "1" {
			local.ServeHTTP(w, r)
			return
		}
		if h.deps.Service == nil {
			local.ServeHTTP(w, r)
			return
		}
		c := h.deps.Service.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		for _, peer := range clusterTemplatePeers(c) {
			status, header, body, err := templatePeerRequest(r, raw, peer)
			if err != nil {
				if h.deps.Logger != nil {
					h.deps.Logger.Warn("cluster templates: peer request failed",
						"peer", peer.NodeID, "method", r.Method, "path", r.URL.Path, "err", err)
				}
				continue
			}
			if status == http.StatusNotFound {
				continue
			}
			copyHeaderValues(w.Header(), header)
			w.WriteHeader(status)
			_, _ = w.Write(body)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		local.ServeHTTP(w, r)
	}
}

func clusterTemplatePeers(c cluster.Client) []cluster.Member {
	if c == nil {
		return nil
	}
	selfID := c.SelfNodeID()
	out := make([]cluster.Member, 0)
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == "" || m.NodeID == selfID || m.APIURL == "" {
			continue
		}
		if !clusterMemberCanOwnSandbox(m.Role) || !clusterMemberSupportsRuntime(m, models.RuntimeFirecracker) {
			continue
		}
		if c.IsNodeDrained(m.NodeID) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func templatePeerRequest(parent *http.Request, raw []byte, peer cluster.Member) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(parent.Context(), parent.Method,
		clusterPeerURL(peer.APIURL, parent.URL.RequestURI()), bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set(clusterTemplateForwardedHeader, "1")
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
