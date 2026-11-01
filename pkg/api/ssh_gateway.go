package api

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/sshgateway"
)

// SSH gateway attribution (UC-287 on a cluster; auditlog.SSHGatewayCall
// says why). A session the SSH gateway bridges to a sandbox another node
// owns reaches this API as operator-token calls on the sandbox's sessions
// routes. The edge decides here, once per request, whether such a call is
// really the gateway acting for the sandbox key holder; withAuth then puts
// the answer on the context, StampForward carries it to the owner, and the
// owner's records name sandbox_key:<id> via the gateway's node instead of
// the operator.
//
//	hop                       honoured when
//	gateway → its own node    sshgateway.TakeBridgedCall: a MAC under a key
//	                          only this process holds, for the path's sandbox
//	edge → owner              X-Cluster-Ssh-Gateway on a forward from a
//	                          verified mTLS peer, for the path's sandbox
//
// Both also require the operator token (the gateway's loopback credential:
// a call made with any other credential is never re-attributed) and one of
// the sessions routes (a forged or leaked marker cannot relabel a delete or
// an exec). The authorization the call gets is unchanged: only the record
// names someone else.

// sshGatewayRoutes are the routes the gateway bridges a session through
// (pkg/sshgateway forward.go), as the mux matched them.
var sshGatewayRoutes = map[string]bool{
	apiv1.PathPrefix + "/sandboxes/{id}/sessions":           true,
	apiv1.PathPrefix + "/sandboxes/{id}/sessions/{path...}": true,
}

// sshGatewayCall reports whether r is a call the SSH gateway bridged for
// the holder of a sandbox's key, and which. It always removes the
// gateway's loopback headers from r, whatever they hold, so they never
// travel on to a peer or into the sandbox's toolbox.
func sshGatewayCall(r *http.Request, access controlplane.Access) (auditlog.SSHGatewayCall, bool) {
	sandboxID := strings.TrimSpace(r.PathValue("id"))
	local, attested := sshgateway.TakeBridgedCall(r.Header, sandboxID)
	if access.Principal.Kind != controlplane.PrincipalOperator || sandboxID == "" || !sshGatewayRoutes[routePattern(r)] {
		return auditlog.SSHGatewayCall{}, false
	}
	if !isForwarded(r) {
		return local, attested
	}
	// clusterControlHeaderGuard already refused X-Cluster-* from anyone but
	// a live peer; the verified certificate is checked again here because
	// this is what turns the header into an identity.
	if _, ok := mtlsPeer(r); !ok {
		return auditlog.SSHGatewayCall{}, false
	}
	call, ok := auditlog.ParseSSHGatewayCall(r.Header.Get(cluster.HeaderSSHGateway))
	if !ok || call.SandboxID != sandboxID {
		return auditlog.SSHGatewayCall{}, false
	}
	return call, true
}

// routePattern is the pattern the mux matched, without its method.
func routePattern(r *http.Request) string {
	pattern := r.Pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:]
	}
	return pattern
}
