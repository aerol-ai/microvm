package v1

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	clusterTemplateForwardedHeader  = "X-Cluster-Template-Forwarded"
	clusterTemplateAggregateHeader  = "X-Cluster-Template-Aggregate"
	clusterTemplateItemLeaderHeader = "X-Cluster-Template-Item-Leader"
)

const clusterTemplatePeerTimeout = clusterListPeerTimeout

// Template handlers — POST/GET/LIST/DELETE for the Firecracker template
// pipeline (plans/snapshot-clone-fast-boot.md Phase 2). Template artifacts
// are global operator-managed infrastructure and live on the worker that built
// them. Cluster mode routes creates to a Firecracker-capable worker, routes
// item operations from advertised inventory, and coalesces cluster-wide lists
// on the Raft leader.

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

	aggregate, err := h.templateLists.cached(r, func(req *http.Request) (clusterListAggregate[*models.Template], error) {
		local, localErr := h.deps.Service.ListTemplates(req.Context())
		// Register this node's slice of the catalogue from the rows already
		// read, so the fleet converges off the fan-out instead of staying on
		// it. Debounced; a steady inventory writes nothing.
		h.deps.Service.PublishTemplateCatalogRows(req.Context(), local)
		return clusterListSweep(req, c, models.RuntimeFirecracker, clusterTemplateForwardedHeader,
			local, localErr, templateListKey, h.deps.Logger, "templates", clusterTemplateLocationIndex,
			h.templateCatalogReader())
	})
	if err != nil {
		writeClusterListError(h.deps.Logger, w, err)
		return
	}
	writeClusterListCoverage(w, aggregate.failedPeers, "X-Aerol-Missing-Template-Peers")
	apihttp.WriteJSON(w, http.StatusOK, aggregate.rows)
}

// templateCatalogReader reads the replicated template metadata. Templates are
// not tenant-scoped, so the catalogue key carries the empty tenant.
func (h *handlers) templateCatalogReader() clusterArtifactCatalog[*models.Template] {
	return func(req *http.Request) ([]*models.Template, []string, bool) {
		return readClusterArtifactCatalog[*models.Template](req, h.deps.Service, cluster.ArtifactKindTemplate, "")
	}
}

func templateListKey(tpl *models.Template) string {
	if tpl == nil {
		return ""
	}
	return tpl.ID
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

// clusterTemplateMemberEligible identifies workers whose template inventory
// belongs in the cluster control-plane view (cluster_list.go for the rule).
func clusterTemplateMemberEligible(c cluster.Client, member cluster.Member) bool {
	return clusterRuntimeMemberEligible(c, member, models.RuntimeFirecracker)
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
	// This is also the path a peer's sweep hits, so it is where a node that
	// is still being asked directly registers its slice of the replicated
	// catalogue and stops being asked.
	h.deps.Service.PublishTemplateCatalogRows(r.Context(), templates)
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
