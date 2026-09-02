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
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterTemplateForwardedHeader = "X-Cluster-Template-Forwarded"

const (
	clusterTemplateListConcurrency = 64
	clusterTemplateListMaxBytes    = 16 << 20
	clusterTemplatePeerTimeout     = 5 * time.Second
)

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
	raw, err := apihttp.ReadJSONBody(w, r)
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
	c.ForwardHTTP(cluster.Endpoint{NodeID: target.NodeID, InternalURL: target.InternalURL, APIURL: target.APIURL}, w, r)
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

	failedPeers := 0
	for result := range listTemplatesFromPeers(r, c, peers) {
		if result.err != nil {
			failedPeers++
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("cluster templates: peer list failed", "peer", result.peerID, "err", result.err)
			}
			continue
		}
		for _, tpl := range result.rows {
			if tpl == nil {
				continue
			}
			if _, ok := seen[tpl.ID]; ok {
				continue
			}
			seen[tpl.ID] = struct{}{}
			merged = append(merged, tpl)
		}
	}
	if localErr != nil && len(merged) == 0 {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, localErr)
		return
	}
	if failedPeers > 0 {
		w.Header().Set("X-Aerol-Partial", "true")
		w.Header().Set("X-Aerol-Missing-Template-Peers", fmt.Sprint(failedPeers))
	}
	apihttp.WriteJSON(w, http.StatusOK, merged)
}

type templateListPeerResult struct {
	peerID string
	rows   []*models.Template
	err    error
}

func listTemplatesFromPeers(parent *http.Request, c cluster.Client, peers []cluster.Member) <-chan templateListPeerResult {
	results := make(chan templateListPeerResult, len(peers))
	if len(peers) == 0 {
		close(results)
		return results
	}
	workers := min(clusterTemplateListConcurrency, len(peers))
	jobs := make(chan cluster.Member)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for peer := range jobs {
				rows, err := listTemplatesFromPeer(parent, c, peer)
				results <- templateListPeerResult{peerID: peer.NodeID, rows: rows, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, peer := range peers {
			select {
			case jobs <- peer:
			case <-parent.Context().Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func listTemplatesFromPeer(parent *http.Request, c cluster.Client, peer cluster.Member) ([]*models.Template, error) {
	client, base, err := dialClusterPeer(c, peer)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent.Context(), clusterTemplatePeerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+parent.URL.RequestURI(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(clusterTemplateForwardedHeader, "1")
	cluster.SetPeerNodeIDHeader(req, c.SelfNodeID())
	if auth := parent.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rows []*models.Template
	dec := json.NewDecoder(io.LimitReader(resp.Body, clusterTemplateListMaxBytes+1))
	if err := dec.Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
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
		raw, err := apihttp.ReadJSONBody(w, r)
		_ = r.Body.Close()
		if err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		// Check local state first. The common owner-worker path remains O(1).
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		localReq := r.Clone(r.Context())
		localReq.Body = io.NopCloser(bytes.NewReader(raw))
		localReq.ContentLength = int64(len(raw))
		localRR := httptest.NewRecorder()
		local.ServeHTTP(localRR, localReq)
		if localRR.Code != http.StatusNotFound {
			copyHeaderValues(w.Header(), localRR.Header())
			w.WriteHeader(localRR.Code)
			_, _ = w.Write(localRR.Body.Bytes())
			return
		}

		// IDs are currently worker-local, so discover a remote owner with bounded
		// concurrency instead of serially multiplying the per-peer timeout by the
		// fleet size. The first non-404 response wins and cancels outstanding RPCs.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		type result struct {
			status int
			header http.Header
			body   []byte
			peer   string
			err    error
		}
		peers := clusterTemplatePeers(c)
		results := make(chan result, len(peers))
		jobs := make(chan cluster.Member)
		workers := min(clusterTemplateListConcurrency, len(peers))
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				for peer := range jobs {
					req := r.Clone(ctx)
					status, header, body, err := templatePeerRequest(c, req, raw, peer)
					results <- result{status: status, header: header, body: body, peer: peer.NodeID, err: err}
				}
			}()
		}
		go func() {
			defer close(jobs)
			for _, peer := range peers {
				select {
				case jobs <- peer:
				case <-ctx.Done():
					return
				}
			}
		}()
		go func() { wg.Wait(); close(results) }()
		for result := range results {
			if result.err != nil {
				if h.deps.Logger != nil && !errors.Is(result.err, context.Canceled) {
					h.deps.Logger.Warn("cluster templates: peer request failed", "peer", result.peer, "err", result.err)
				}
				continue
			}
			if result.status == http.StatusNotFound {
				continue
			}
			cancel()
			copyHeaderValues(w.Header(), result.header)
			w.WriteHeader(result.status)
			_, _ = w.Write(result.body)
			return
		}
		copyHeaderValues(w.Header(), localRR.Header())
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(localRR.Body.Bytes())
	}
}

func clusterTemplatePeers(c cluster.Client) []cluster.Member {
	if c == nil {
		return nil
	}
	selfID := c.SelfNodeID()
	out := make([]cluster.Member, 0)
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == "" || m.NodeID == selfID || m.InternalURL == "" {
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

func templatePeerRequest(c cluster.Client, parent *http.Request, raw []byte, peer cluster.Member) (int, http.Header, []byte, error) {
	client, base, err := dialClusterPeer(c, peer)
	if err != nil {
		return 0, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent.Context(), clusterTemplatePeerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, parent.Method,
		base+parent.URL.RequestURI(), bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set(clusterTemplateForwardedHeader, "1")
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
