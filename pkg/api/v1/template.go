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
	"golang.org/x/sync/singleflight"
)

const (
	clusterTemplateForwardedHeader  = "X-Cluster-Template-Forwarded"
	clusterTemplateAggregateHeader  = "X-Cluster-Template-Aggregate"
	clusterTemplateItemLeaderHeader = "X-Cluster-Template-Item-Leader"
)

const (
	clusterTemplateListConcurrency  = 64
	clusterTemplateListMaxBytes     = 16 << 20
	clusterTemplatePeerTimeout      = 5 * time.Second
	clusterTemplateAggregateTimeout = 10 * time.Second
	clusterTemplateListCacheTTL     = 2 * time.Second
)

// Template handlers — POST/GET/LIST/DELETE for the Firecracker template
// pipeline (plans/snapshot-clone-fast-boot.md Phase 2). Template artifacts
// are global operator-managed infrastructure and live on the worker that built
// them. Cluster mode routes creates to a Firecracker-capable worker, routes
// item operations from advertised inventory, and coalesces cluster-wide lists
// on the Raft leader.

type templateListAggregate struct {
	rows        []*models.Template
	failedPeers int
}

type templateListCache struct {
	mu      sync.RWMutex
	expires time.Time
	value   templateListAggregate
	group   singleflight.Group
}

func (c *templateListCache) get(now time.Time) (templateListAggregate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.expires.IsZero() || !now.Before(c.expires) {
		return templateListAggregate{}, false
	}
	return c.value, true
}

func (c *templateListCache) put(now time.Time, value templateListAggregate) {
	c.mu.Lock()
	c.value = value
	c.expires = now.Add(clusterTemplateListCacheTTL)
	c.mu.Unlock()
}

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
	if r.Header.Get(clusterTemplateAggregateHeader) != "1" && h.forwardTemplateToLeader(w, r, c, clusterTemplateAggregateHeader) {
		return
	}

	aggregate, err := h.cachedTemplateList(r, c)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if aggregate.failedPeers > 0 {
		w.Header().Set("X-Aerol-Partial", "true")
		w.Header().Set("X-Aerol-Missing-Template-Peers", fmt.Sprint(aggregate.failedPeers))
	}
	apihttp.WriteJSON(w, http.StatusOK, aggregate.rows)
}

func (h *handlers) forwardTemplateToLeader(w http.ResponseWriter, r *http.Request, c cluster.Client, routedHeader string) bool {
	leaderID := strings.TrimSpace(c.Leader())
	if leaderID == "" {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster leader unavailable")
		return true
	}
	if leaderID == c.SelfNodeID() {
		return false
	}
	member, found := templateMemberByID(c, leaderID)
	if !found {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster leader not present in membership")
		return true
	}
	if !member.Alive || strings.TrimSpace(member.InternalURL) == "" {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster leader internal endpoint unavailable")
		return true
	}
	r.Header.Set(routedHeader, "1")
	c.ForwardHTTP(cluster.Endpoint{
		NodeID: member.NodeID, InternalURL: member.InternalURL, APIURL: member.APIURL,
	}, w, r)
	return true
}

// templateMemberByID uses the O(1) gossip index exposed by production cluster
// clients. The Members fallback supports small test/custom clients only; both
// Cluster and Agent implement LookupMember.
func templateMemberByID(c cluster.Client, nodeID string) (cluster.Member, bool) {
	if lookup, ok := c.(interface {
		LookupMember(string) (cluster.Member, bool)
	}); ok {
		if member, found := lookup.LookupMember(nodeID); found {
			return member, true
		}
	}
	for _, member := range c.Members() {
		if member.NodeID == nodeID {
			return member, true
		}
	}
	return cluster.Member{}, false
}

func (h *handlers) cachedTemplateList(r *http.Request, c cluster.Client) (templateListAggregate, error) {
	if cached, ok := h.templateLists.get(time.Now()); ok {
		return cached, nil
	}
	value, err, _ := h.templateLists.group.Do("all", func() (any, error) {
		if cached, ok := h.templateLists.get(time.Now()); ok {
			return cached, nil
		}
		// Finish the bounded aggregate even if the first ingress caller leaves;
		// other concurrent callers share this work through singleflight.
		ctx, cancel := context.WithTimeout(context.Background(), clusterTemplateAggregateTimeout)
		defer cancel()
		request := r.Clone(ctx)
		request.Header = r.Header.Clone()
		aggregate, err := h.aggregateTemplateList(request, c)
		if err != nil {
			return templateListAggregate{}, err
		}
		h.templateLists.put(time.Now(), aggregate)
		return aggregate, nil
	})
	if err != nil {
		return templateListAggregate{}, err
	}
	return value.(templateListAggregate), nil
}

func (h *handlers) aggregateTemplateList(r *http.Request, c cluster.Client) (templateListAggregate, error) {
	peers := clusterTemplatePeers(c)
	unavailablePeers := clusterTemplateUnavailablePeerCount(c)

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

	successfulPeers := 0
	for result := range listTemplatesFromPeers(r, c, peers) {
		if result.err != nil {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("cluster templates: peer list failed", "peer", result.peerID, "err", result.err)
			}
			continue
		}
		successfulPeers++
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
		return templateListAggregate{}, localErr
	}
	// The aggregate context may expire before every peer is dispatched. Count
	// every peer without a successful response as missing so a partial response
	// can never under-report its coverage gap.
	failedPeers := unavailablePeers + len(peers) - successfulPeers
	if localErr != nil {
		failedPeers++
	}
	return templateListAggregate{rows: merged, failedPeers: failedPeers}, nil
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
		if r.Header.Get(clusterTemplateItemLeaderHeader) != "1" && h.forwardTemplateToLeader(w, r, c, clusterTemplateItemLeaderHeader) {
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

		peer, inventoryUnknown, ok := templateOwnerFromInventory(c, r.PathValue("id"))
		if !ok {
			if inventoryUnknown {
				apihttp.WriteError(w, http.StatusServiceUnavailable, "template inventory has not converged")
				return
			}
			copyHeaderValues(w.Header(), localRR.Header())
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(localRR.Body.Bytes())
			return
		}
		if !peer.Alive || strings.TrimSpace(peer.InternalURL) == "" {
			apihttp.WriteError(w, http.StatusServiceUnavailable, "template owner is unavailable")
			return
		}
		status, header, body, err := templatePeerRequest(c, r, raw, peer)
		if err != nil {
			if h.deps.Logger != nil {
				h.deps.Logger.Warn("cluster templates: owner request failed", "peer", peer.NodeID, "err", err)
			}
			apihttp.WriteError(w, http.StatusBadGateway, "template owner unavailable")
			return
		}
		copyHeaderValues(w.Header(), header)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func templateOwnerFromInventory(c cluster.Client, templateID string) (cluster.Member, bool, bool) {
	var owner cluster.Member
	unknown := false
	if c == nil {
		return owner, false, false
	}
	for _, member := range c.Members() {
		if !clusterTemplateMemberEligible(c, member) {
			continue
		}
		if !member.Capacity.LocalTemplateCatalogInventoryKnown {
			unknown = true
			continue
		}
		for _, id := range member.Capacity.LocalTemplateCatalogIDs {
			if id == templateID && (owner.NodeID == "" || member.NodeID < owner.NodeID) {
				owner = member
			}
		}
	}
	return owner, unknown, owner.NodeID != ""
}

func clusterTemplatePeers(c cluster.Client) []cluster.Member {
	if c == nil {
		return nil
	}
	out := make([]cluster.Member, 0)
	for _, m := range c.Members() {
		if !clusterTemplateMemberEligible(c, m) || !m.Alive || strings.TrimSpace(m.InternalURL) == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func clusterTemplateUnavailablePeerCount(c cluster.Client) int {
	if c == nil {
		return 0
	}
	count := 0
	for _, member := range c.Members() {
		if !clusterTemplateMemberEligible(c, member) {
			continue
		}
		if !member.Alive || strings.TrimSpace(member.InternalURL) == "" {
			count++
		}
	}
	return count
}

// clusterTemplateMemberEligible identifies workers whose template inventory
// belongs in the cluster control-plane view. Drain state intentionally does not
// apply: draining prevents new sandbox placement, not administration of
// artifacts already owned by that worker.
func clusterTemplateMemberEligible(c cluster.Client, member cluster.Member) bool {
	return c != nil && member.NodeID != "" && member.NodeID != c.SelfNodeID() &&
		clusterMemberCanOwnSandbox(member.Role) &&
		clusterMemberSupportsRuntime(member, models.RuntimeFirecracker)
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
