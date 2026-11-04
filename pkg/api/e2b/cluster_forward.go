package e2b

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

func (h *handlers) clusterForwardWrap(local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{WriteError: WriteError}, local)
}

// snapshotForwardWrap routes a template(snapshot)-by-id DELETE to the node
// holding the snapshot's image (B6). The E2B id is a reversible encoding of the
// snapshot name for snapshots without a custom alias; those route. An id that is
// a custom alias cannot be mapped to a name without the local alias row, so the
// resolver returns "" and the request serves locally (the pre-index behaviour —
// a miss then answers 404, unchanged).
func (h *handlers) snapshotForwardWrap(local http.Handler) http.Handler {
	return clusterroute.WrapSnapshot(h.deps.Service, func(r *http.Request) string {
		if name, ok := snapshotNameFromID(r.PathValue("id")); ok {
			return name
		}
		return ""
	}, WriteError, local)
}
