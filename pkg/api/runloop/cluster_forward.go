package runloop

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/clusterroute"
)

// clusterForwardWrap sends a devbox-scoped request to the node that owns the
// devbox. Exec, file, and snapshot calls all dial the sandbox's toolbox or
// runtime, which only exist on the owner, so serving them locally on a
// non-owner would 404 or hit the wrong host.
func (h *handlers) clusterForwardWrap(local http.Handler) http.Handler {
	return clusterroute.Wrap(h.deps.Service, clusterroute.Options{WriteError: WriteError}, local)
}

// forwardToNode serves r on nodeID: locally when that is this node (or
// there is no cluster), otherwise by forwarding. It is for state bound to
// a node rather than to a devbox's current owner — a snapshot stays where
// it was taken. A node that is not a member any more took that state with
// it, which is a permanent 503 the SDK should not retry; an unreachable
// member is a transient one.
func (h *handlers) forwardToNode(w http.ResponseWriter, r *http.Request, nodeID string, local http.HandlerFunc) {
	c := h.clusterClient()
	if c == nil || nodeID == c.SelfNodeID() {
		local(w, r)
		return
	}
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		cluster.RecordOwnerForwardStale()
		WriteError(w, http.StatusMisdirectedRequest, "cluster: forwarding loop detected")
		return
	}
	for _, m := range c.Members() {
		if m.NodeID != nodeID {
			continue
		}
		if !m.Alive || (m.APIURL == "" && m.InternalURL == "") {
			service.RecordRouteMiss()
			WriteError(w, http.StatusServiceUnavailable, "cluster: node "+nodeID+" is unavailable")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{NodeID: m.NodeID, InternalURL: m.InternalURL, APIURL: m.APIURL}, w, r)
		return
	}
	w.Header().Set("x-should-retry", "false")
	WriteError(w, http.StatusServiceUnavailable, "the node holding this snapshot ("+nodeID+") has left the cluster; the snapshot went with it")
}
