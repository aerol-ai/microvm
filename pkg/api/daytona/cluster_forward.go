package daytona

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

func (h *handlers) clusterForwardWrap(pathKey string, local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		PathKey:     pathKey,
		ResolveName: pathKey == "idOrName",
		WriteError:  apihttp.WriteError,
	}, local)
}

// snapshotForwardWrap routes a snapshot-by-id request to the node holding the
// snapshot's image (B6). A Daytona snapshot's id is its name — the same string
// a create-from-snapshot passes back — so the name resolver is the path value
// directly, with no local store read.
func (h *handlers) snapshotForwardWrap(local http.Handler) http.Handler {
	return clusterroute.WrapSnapshot(h.deps.Service, func(r *http.Request) string {
		return r.PathValue("id")
	}, apihttp.WriteError, local)
}
