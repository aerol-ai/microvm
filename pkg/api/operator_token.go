package api

import (
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// The Kubernetes operator's own API token (identitywire.OperatorTokenPrefix)
// is an admin credential it sends only to servers: the API Service, or a
// port-forward to a server pod. So it works only there, and a copy taken
// anywhere else is refused wherever it is sent:
//
//	on a server, sent to it directly          taken
//	on a server, forwarded by another server  taken (a call the leader serves)
//	on a gateway or a worker                  refused
//	on the public socket (Caddy's upstream)   refused
//	forwarded by a gateway or a worker        refused, whatever that node runs:
//	                                          a forward keeps Authorization,
//	                                          and an older node does not check
//
// This is the one entry point every surface authenticates through (v1, the
// E2B X-API-KEY, Runloop and /mcp), so the rule covers each. A single node
// is its own server. The refusal is a 401 with the surface's fixed text;
// the auth_denied record and aerolvm_auth_failures_total say servers_only.

// errOperatorTokenPlace refuses the operator's token outside a server.
var errOperatorTokenPlace = errors.New("operator API token refused: it works only on a server")

// operatorTokenPlace refuses a, an authenticated credential, when it is the
// operator's own token and r did not reach a server directly or through
// another server. Every other credential passes.
func (s *Server) operatorTokenPlace(r *http.Request, a controlplane.Access) error {
	if a.Principal.Kind != controlplane.PrincipalToken || !identitywire.IsOperatorTokenName(a.Principal.Name) {
		return nil
	}
	if !s.takesOperatorTokens || onPublicSocket(r) {
		return errOperatorTokenPlace
	}
	// A request another node sent here (a forward, or a call over the
	// cluster's mTLS) counts only from a server, named by its verified
	// certificate and admitted role, never by a header.
	peer, viaPeer := mtlsPeer(r)
	if (viaPeer || isForwarded(r)) && (!viaPeer || s.nodeRole(r, peer) != cluster.JoinRoleServer) {
		return errOperatorTokenPlace
	}
	return nil
}
