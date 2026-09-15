package e2b

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
)

func (h *handlers) clusterForwardWrap(local http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.deps.Service == nil {
			local.ServeHTTP(w, r)
			return
		}
		c := h.deps.Service.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}

		owner, err := c.OwnerOf(strings.TrimSpace(r.PathValue("id")))
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			local.ServeHTTP(w, r)
			return
		}
		if errors.Is(err, cluster.ErrOrphaned) {
			WriteError(w, http.StatusGone, err.Error())
			return
		}
		if err != nil {
			WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if owner.IsSelf {
			local.ServeHTTP(w, r)
			return
		}
		if owner.APIURL == "" && owner.InternalURL == "" {
			service.RecordRouteMiss()
			WriteError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
			return
		}
		if r.Header.Get("X-Cluster-Forwarded") == "1" {
			cluster.RecordOwnerForwardStale()
			WriteError(w, http.StatusMisdirectedRequest, "cluster: forwarding loop detected")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{NodeID: owner.NodeID, InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}
