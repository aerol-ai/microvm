package daytona

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// A volume's create and delete are tenant rows only servers write (least
// privilege; cluster volume_proposals.go). On a worker or gateway they go on
// to a server with the caller's own credential, which the server checks and
// scopes the row by, as v1's operator calls do (v1 server_tier.go); reads
// stay on the node that got them. They go once every member runs a build
// that does this (servers sign); until then the node writes them as before.
// The server needs the platform-volume settings the workers have.

type serverForwarder interface {
	ForwardToServer(http.ResponseWriter, *http.Request)
}

// volumeWritesViaServers wraps a volume write.
func (h *handlers) volumeWritesViaServers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.deps.Service == nil || !h.deps.Service.SendsOperatorCallsToServers() || !h.deps.Service.ServerSigningOn() {
			next.ServeHTTP(w, r)
			return
		}
		if scheme, cred, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " "); !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(cred) == "" {
			apihttp.WriteError(w, http.StatusBadRequest, "this node sends volume writes on to a server with your own credential, and the call carries none: send it with an Authorization header, or to a server")
			return
		}
		fw, ok := h.deps.Service.Cluster().(serverForwarder)
		if !ok {
			apihttp.WriteError(w, http.StatusServiceUnavailable, cluster.ErrNoServerForward.Error())
			return
		}
		fw.ForwardToServer(w, r)
	})
}
