package daytona

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

// clusterForwardWrap routes a sandbox request by id or per-owner name to the
// node that owns the sandbox.
//
// The sandbox DELETE does not set clusterroute.Options.Destroy, as v1 and
// E2B do, so a sandbox left on a deleted node still answers 503 or 410
// here. The server that would take that delete holds no row for it, and
// destroySandbox needs the row: to resolve a name, and to build the
// Daytona Sandbox it answers with, which the Daytona SDKs parse. With
// Destroy set it would answer 404 and leave the placement (TODOS.md).
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
