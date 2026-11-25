package clusterroute

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// A sandbox left on a node an operator deleted (internal/cluster
// abandoned_placement.go). Its placement either still names the node (the
// moment between the node's deny record and the leader handing its
// sandboxes off) or was orphaned from it. Either way no node runs it, and
// the deleted node is refused as a peer and drops out of gossip, so a
// forward to it can only fail: with no InternalURL the mTLS rule refuses it
// (503), which is what every DELETE of such a sandbox used to answer.
//
// So the router never forwards there. A DELETE is run by a server, which
// deletes the placement (service.deleteAbandonedPlacement); any other call
// for a sandbox still named on the deleted node answers 503 with
// Retry-After until the hand-off lands, and is then routed by what it finds.

// serverForwarder is cluster.Agent's call to the server tier, with the
// caller's own credential.
type serverForwarder interface {
	ForwardToServer(http.ResponseWriter, *http.Request)
}

// destroyAbandoned serves a DELETE of a sandbox left on a deleted node: on a
// server, the local handler, whose service deletes the placement; on a
// worker or gateway, which may not write another node's placement, a
// server. It returns false and leaves the answer to the caller when the
// sandbox is not left on a deleted node after all (an orphan of a node that
// only died keeps its 410), or when no server can take the call.
func destroyAbandoned(c cluster.Client, id string, w http.ResponseWriter, r *http.Request, serveLocal func(string)) bool {
	p, ok := c.PlacementOf(id)
	if !ok || !cluster.PlacementAbandoned(c, p) {
		return false
	}
	if _, server := c.(cluster.AbandonedPlacementDeleter); server {
		serveLocal(id)
		return true
	}
	// A forwarded call is already a hop from another node: a second hop
	// would only bounce. A call with no credential of its own would reach
	// the server as this node, which may not delete sandboxes.
	fw, ok := c.(serverForwarder)
	if !ok || r.Header.Get(cluster.HeaderForwarded) == "1" || !(hasBearer(r) || kubernetesCaller(r)) {
		return false
	}
	fw.ForwardToServer(w, r)
	return true
}

// hasBearer reports whether r carries a bearer credential of its own.
func hasBearer(r *http.Request) bool {
	scheme, cred, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	return strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(cred) != ""
}

// kubernetesCaller reports whether r is the agent-sandbox API's in-process
// call for a Kubernetes user (pkg/api KubeBackend). It has no credential, but
// the forward names the user and its owner (cluster.StampForward), and the
// server grants the call only that owner's runner access, never this node's
// own. The server then checks the owner again before it deletes.
func kubernetesCaller(r *http.Request) bool {
	access, ok := controlplane.AccessFromContext(r.Context())
	return ok && access.Principal.Kind == controlplane.PrincipalKubernetes
}

// writeOwnerDeleted answers a call for a sandbox whose placement still names
// a deleted node. The leader is handing that node's sandboxes off; once it
// has, a retry finds the new owner, the orphan, or no sandbox.
func writeOwnerDeleted(w http.ResponseWriter, write ErrorWriter) {
	w.Header().Set("Retry-After", "5")
	write(w, http.StatusServiceUnavailable, "cluster: the node that ran this sandbox was deleted; its sandboxes are being handed off, retry")
}
