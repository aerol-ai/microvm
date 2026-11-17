package api

import (
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// customDomainsBound is what the server that forwarded r bound for it
// (cluster.HeaderCustomDomainsBound): the custom hostnames it checked the
// caller's DNS proof for and bound to the sandbox, so the owner does not
// look them up again. Honoured only on a forward over a verified mTLS
// connection from a server: a worker or gateway binds no name (the leader
// takes from it only names a sandbox holds), so the marker from it would
// skip a proof nothing else checked.
func (s *Server) customDomainsBound(r *http.Request) (cluster.CustomDomainsBound, bool) {
	v := r.Header.Get(cluster.HeaderCustomDomainsBound)
	if v == "" || !isForwarded(r) {
		return cluster.CustomDomainsBound{}, false
	}
	peer, ok := mtlsPeer(r)
	if !ok || s.nodeRole(r, peer) != cluster.JoinRoleServer {
		return cluster.CustomDomainsBound{}, false
	}
	return cluster.ParseCustomDomainsBound(v)
}
