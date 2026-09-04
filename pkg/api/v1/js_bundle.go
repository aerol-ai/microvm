package v1

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// JS-bundle catalogue handlers (plans/isolate-runtime.md §8) — the isolate
// runtime's "no image, no registry" upload path. Thin: decode → service →
// encode, with WriteStoreAwareError mapping ErrNotFound/ErrJSBundleInUse to the
// right status. EXPERIMENTAL until the §10.1 demand checkpoint.

func (h *handlers) createJSBundle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Cluster-Forwarded") == "1" || h.deps.Service == nil || !h.deps.Service.ClusterEnabled() || h.deps.Service.Cluster() == nil {
		h.createJSBundleLocal(w, r)
		return
	}
	c := h.deps.Service.Cluster()
	target, err := c.SelectPlacement(capacity.Request{
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB,
		Runtime: models.RuntimeIsolate,
	})
	if err != nil {
		if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apihttp.WriteError(w, http.StatusInternalServerError, "placement: "+err.Error())
		return
	}
	if target.IsSelf {
		h.createJSBundleLocal(w, r)
		return
	}
	c.ForwardHTTP(cluster.Endpoint{
		NodeID: target.NodeID, InternalURL: target.InternalURL, APIURL: target.APIURL,
	}, w, r)
}

func (h *handlers) createJSBundleLocal(w http.ResponseWriter, r *http.Request) {
	var req models.CreateJSBundleRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	bundle, err := h.deps.Service.CreateJSBundle(r.Context(), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, bundle)
}

func (h *handlers) listJSBundles(w http.ResponseWriter, r *http.Request) {
	bundles, err := h.deps.Service.ListJSBundles(r.Context())
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, bundles)
}

func (h *handlers) getJSBundle(w http.ResponseWriter, r *http.Request) {
	if h.forwardBoundJSBundle(w, r) {
		return
	}
	bundle, err := h.deps.Service.GetJSBundle(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, bundle)
}

func (h *handlers) deleteJSBundle(w http.ResponseWriter, r *http.Request) {
	if h.forwardBoundJSBundle(w, r) {
		return
	}
	if err := h.deps.Service.DeleteJSBundle(r.Context(), r.PathValue("id")); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// forwardBoundJSBundle routes item operations to the worker named by the
// node-bound module_ref returned from POST /v1/js-bundles. It deliberately
// does not scan the fleet: a GET or DELETE remains O(1) at 2,000 workers.
func (h *handlers) forwardBoundJSBundle(w http.ResponseWriter, r *http.Request) bool {
	if h.deps.Service == nil || !h.deps.Service.ClusterEnabled() || r.Header.Get("X-Cluster-Forwarded") == "1" {
		return false
	}
	nodeID, _, ok := models.ParseJSBundleNodeRef(r.PathValue("id"))
	if !ok {
		return false
	}
	c := h.deps.Service.Cluster()
	if c == nil || nodeID == c.SelfNodeID() {
		return false
	}
	lookup, ok := c.(interface {
		LookupMember(string) (cluster.Member, bool)
	})
	if !ok {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: bundle owner lookup unavailable")
		return true
	}
	member, found := lookup.LookupMember(nodeID)
	if !found || !member.Alive || strings.TrimSpace(member.InternalURL) == "" {
		apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: bundle owner is unavailable")
		return true
	}
	c.ForwardHTTP(cluster.Endpoint{
		NodeID: member.NodeID, InternalURL: member.InternalURL, APIURL: member.APIURL,
	}, w, r)
	return true
}
