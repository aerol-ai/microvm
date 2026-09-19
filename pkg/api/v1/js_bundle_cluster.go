package v1

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// clusterJSBundleForwardedHeader marks a list re-issued to one worker for
	// its local slice; the worker must answer locally and never fan out.
	clusterJSBundleForwardedHeader = "X-Cluster-JSBundle-Forwarded"
	// clusterJSBundleAggregateHeader marks an ingress list routed to the
	// leader for aggregation.
	clusterJSBundleAggregateHeader = "X-Cluster-JSBundle-Aggregate"
	clusterJSBundleMissingHeader   = "X-Aerol-Missing-JSBundle-Peers"
)

// clusterListJSBundlesWrap makes GET /v1/js-bundles complete in cluster mode.
// A bundle lives only on the isolate worker that received its upload (the
// node-bound module_ref), so a plain local list on an ingress node is empty.
// The wrapper is the shared per-worker catalogue shape (cluster_list.go):
// leader-coalesced, cached, bounded fan-out to isolate-capable workers only,
// merged by digest with local rows winning, partial coverage in headers.
// Nothing here copies bundle bytes; only metadata moves, at list time.
func (h *handlers) clusterListJSBundlesWrap(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(clusterJSBundleForwardedHeader) == "1" || h.deps.Service == nil || !h.deps.Service.ClusterEnabled() {
		h.listJSBundles(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	if c == nil {
		h.listJSBundles(w, r)
		return
	}
	if r.Header.Get(clusterJSBundleAggregateHeader) != "1" && h.forwardListToLeader(w, r, c, clusterJSBundleAggregateHeader) {
		return
	}
	aggregate, err := h.jsBundleLists.cached(r, func(req *http.Request) (clusterListAggregate[*models.JSBundle], error) {
		local, localErr := h.deps.Service.ListJSBundles(req.Context())
		// Still no gossip location index for isolate bundles, on purpose: the
		// catalogue's key is a content digest, and gossip reaches every node,
		// so a node-wide digest list would let any peer infer the existence
		// and byte-equality of other tenants' code. The replicated catalogue
		// below is the narrowing instead — it is keyed BY TENANT and lives in
		// the server tier, which already holds every tenant's placements.
		return clusterListSweep(req, c, models.RuntimeIsolate, clusterJSBundleForwardedHeader,
			local, localErr, jsBundleListKey, h.deps.Logger, "js-bundles", nil,
			h.jsBundleCatalogReader())
	})
	if err != nil {
		writeClusterListError(h.deps.Logger, w, err)
		return
	}
	writeClusterListCoverage(w, aggregate.failedPeers, clusterJSBundleMissingHeader)
	apihttp.WriteJSON(w, http.StatusOK, aggregate.rows)
}

// jsBundleCatalogReader reads the replicated bundle metadata for the calling
// tenant only.
func (h *handlers) jsBundleCatalogReader() clusterArtifactCatalog[*models.JSBundle] {
	return func(req *http.Request) ([]*models.JSBundle, []string, bool) {
		return readClusterArtifactCatalog[*models.JSBundle](req, h.deps.Service, cluster.ArtifactKindJSBundle, clusterlist.OwnerRefFromContext(req.Context()))
	}
}

// jsBundleListKey dedupes by content digest: the same bytes uploaded to two
// workers are one bundle to the caller, whichever worker's ref they hold.
func jsBundleListKey(b *models.JSBundle) string {
	if b == nil {
		return ""
	}
	return b.Digest
}

// writeJSBundleOwnerUnavailable is the machine-readable answer when the one
// worker holding a bundle is gone. Bundles are single-copy by design (no
// fleet replication; see plans/isolate-runtime.md, "Bundle durability"), and
// the client keeps the source, so the recovery is a re-upload — the code lets
// an SDK do that without parsing prose.
func writeJSBundleOwnerUnavailable(w http.ResponseWriter, nodeID string) {
	apihttp.WriteErrorCode(w, http.StatusServiceUnavailable, models.ErrorCodeArtifactNodeUnavailable,
		"cluster: the worker holding this js-bundle ("+nodeID+") is unavailable; bundles are single-copy — re-upload to obtain a new module_ref")
}

var _ = cluster.ErrArtifactNodeUnavailable
