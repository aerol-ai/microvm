package daytona

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

// clusterForwardWrap routes a sandbox request by id or per-owner name to the
// node that owns the sandbox.
func (h *handlers) clusterForwardWrap(pathKey string, local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		PathKey:     pathKey,
		ResolveName: pathKey == "idOrName",
		WriteError:  apihttp.WriteError,
	}, local)
}

// clusterDestroyForwardWrap is clusterForwardWrap for the sandbox DELETE, as
// v1 and E2B have: a sandbox left on a node an operator deleted is deleted
// by a server instead of forwarded (clusterroute abandoned.go). The server
// holds no row for it, so destroySandbox resolves the id or name and builds
// its answer from the placement (destroyAbandonedSandbox).
func (h *handlers) clusterDestroyForwardWrap(local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{
		PathKey:     "idOrName",
		ResolveName: true,
		WriteError:  apihttp.WriteError,
		Destroy:     true,
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
