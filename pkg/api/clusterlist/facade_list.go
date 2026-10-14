package clusterlist

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// FacadeListOptions configures FacadeListPage for one facade.
type FacadeListOptions struct {
	// Path is the facade's list route the peer hop GETs (e.g. "/e2b/sandboxes").
	Path string
	// AuthHeader / APIKeyHeader are the caller's credentials to forward to the
	// peer so it scopes to the same tenant; a facade passes whichever its
	// inbound auth accepts (E2B accepts X-API-KEY).
	AuthHeader   string
	APIKeyHeader string
	// Warn logs a peer that failed to answer, if non-nil.
	Warn func(msg, peer string, err error)
}

// ListMode reports whether a list should fan out across the cluster: a real
// cluster client is attached (not the standalone Noop) and this is not itself a
// forwarded peer hop. It is the single definition E2B, Daytona and Runloop used
// to each copy (the per-facade clusterListMode).
func ListMode(c cluster.Client, r *http.Request) bool {
	if c == nil || r == nil || r.Header.Get("X-Cluster-Forwarded") == "1" {
		return false
	}
	if _, ok := c.(*cluster.Noop); ok {
		return false
	}
	return true
}

// FacadeListPage merges one owner-scoped page of a facade's sandbox list across
// the cluster: it selects the peers that hold this page, filters the local rows
// to it, forwards the caller's credential, and returns (items, coverage,
// next-cursor, ok). ok == false means the placement view is not ready and the
// caller should answer 503. With no cluster — or on a forwarded peer hop — it
// returns local unchanged. idFn extracts an item's sandbox id.
//
// This is the glue E2B and Daytona each copied verbatim (listFacadeClusterItems),
// differing only in the element type, the id accessor, and the route path (D12).
func FacadeListPage[T any](r *http.Request, c cluster.Client, local []T, idFn func(T) string, opts FacadeListOptions) ([]T, Coverage, string, bool) {
	cov := Coverage{Answered: []string{"local"}, PlacementViewReady: true}
	if !ListMode(c, r) {
		return local, cov, "", true
	}
	ownerRef := OwnerRefFromContext(r.Context())
	limit, pageToken := ParsePageParams(r.URL)
	peers, placements, next, viewReady, missingOwners := SelectPeersForPage(c, ownerRef, pageToken, limit)
	if !viewReady {
		cov.PlacementViewReady = false
		cov.Partial = true
		return nil, cov, "", false
	}
	local = filterLocalToPage(local, placements, pageToken, idFn)
	items, cov := MergeJSON(r.Context(), peers, local, idFn, Options{
		OwnerRef:   ownerRef,
		AuthHeader: opts.AuthHeader,
		// Peers must not re-apply the facade's page/limit — the ingress node
		// paginates after the merge.
		APIKeyHeader: opts.APIKeyHeader,
		RawQuery:     StripFacadePagination(r.URL.RawQuery),
		Path:         opts.Path,
		Transport:    TransportFromCluster(c),
		SelfNodeID:   c.SelfNodeID(),
		WantIDs:      PlacementWantIDs(placements),
		Warn:         opts.Warn,
	})
	cov.PlacementViewReady = viewReady
	if len(missingOwners) > 0 {
		cov.Missing = append(cov.Missing, missingOwners...)
		cov.Partial = true
	}
	return items, cov, next, true
}

// filterLocalToPage keeps only the local rows belonging to this placement page.
// A nil placements slice means the cluster did not scope the page (fall back to
// all local rows, unless a page cursor says we are past the local page).
func filterLocalToPage[T any](local []T, placements []cluster.Placement, pageToken string, idFn func(T) string) []T {
	if placements == nil {
		if strings.TrimSpace(pageToken) != "" {
			return nil
		}
		return local
	}
	want := PlacementWantIDs(placements)
	out := make([]T, 0, len(local))
	for _, it := range local {
		if id := idFn(it); id != "" {
			if _, ok := want[id]; ok {
				out = append(out, it)
			}
		}
	}
	return out
}
