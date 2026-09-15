package daytona

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

func (h *handlers) clusterForwardWrap(pathKey string, local http.Handler) http.Handler {
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

		owner, err := c.OwnerOf(strings.TrimSpace(r.PathValue(pathKey)))
		if errors.Is(err, cluster.ErrUnknownSandbox) && pathKey == "idOrName" {
			_, owner, err = c.OwnerOfName(r.PathValue(pathKey))
		}
		if errors.Is(err, cluster.ErrUnknownSandbox) {
			local.ServeHTTP(w, r)
			return
		}
		if errors.Is(err, cluster.ErrOrphaned) {
			apihttp.WriteError(w, http.StatusGone, err.Error())
			return
		}
		if err != nil {
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if owner.IsSelf {
			local.ServeHTTP(w, r)
			return
		}
		if owner.APIURL == "" && owner.InternalURL == "" {
			service.RecordRouteMiss()
			apihttp.WriteError(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
			return
		}
		if r.Header.Get("X-Cluster-Forwarded") == "1" {
			cluster.RecordOwnerForwardStale()
			apihttp.WriteError(w, http.StatusMisdirectedRequest, "cluster: forwarding loop detected")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{NodeID: owner.NodeID, InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}
