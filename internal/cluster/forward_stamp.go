package cluster

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Headers a forward of a user's request carries to the peer that will run it
// (plans/identity-and-access.md §5.2, eng review finding 1.2 and E6).
const (
	// HeaderForwarded marks a request a peer forwarded on a user's behalf.
	// The receiver runs it locally instead of routing it again, and the
	// auth edge names a forwarded PAT caller "operator via <edge>" instead
	// of "node:<edge>". Like every X-Cluster-* header it is honoured only
	// from a live mTLS peer (pkg/api's clusterControlHeaderGuard).
	HeaderForwarded = "X-Cluster-Forwarded"
	// HeaderTeam selects which of a credential's teams a request acts for
	// (CEO review D13); pkg/api.HeaderTeam is this constant.
	HeaderTeam = "X-AerolVM-Team"
	// HeaderCorrelationID ties the records one API call writes on every
	// node together (H3).
	HeaderCorrelationID = "X-Correlation-ID"
)

// StampForward marks out, an outbound request that carries a user's request
// to a peer, as a forward, and copies what the peer needs to treat it as the
// same call. Every path that forwards a user's request calls it: the
// reverse-proxy Director behind ForwardHTTP (clusterroute, clustercreate,
// the runloop forwardToNode, js-bundle and template routing) and every
// fan-out client that builds a fresh request (the clusterlist merge, image
// build routing, template item routing, the per-worker catalogue lists). A
// call-site test in pkg/api fails the build on a new peer request that
// skips it.
//
// It never supplies an identity. The peer re-authenticates the original
// credential, which travels with the request, and everything stamped here
// only narrows or annotates what that credential already allows:
//
//   - HeaderForwarded, so the peer runs the request locally and records the
//     edge as Via (from the verified mTLS peer, not from this header).
//   - HeaderTeam, for a team-bound credential (an avm_ token or an OIDC
//     token): the team the edge resolved, taken from the verified access
//     rather than copied from the raw header. A fresh fan-out request
//     dropped the header, so a multi-team caller's list was answered for its
//     first team on every peer (E6). The peer re-applies the selection and
//     refuses a team the credential is not bound to.
//   - HeaderCorrelationID, from the request context the API edge filled, so
//     the peer's records share the edge's id instead of minting their own.
//
// It also marks the edge's api record as forwarded (auditlog.MarkForwarded):
// only the node that runs the handler records the call, so the peer writes
// the one record and the edge writes none (§5.9, "Forwarding").
//
// Later tasks add their markers here (X-Cluster-PAT-Origin, T10;
// X-Cluster-Surface, T13), so no forward path can miss them.
func StampForward(out *http.Request, access controlplane.Access) {
	if out == nil {
		return
	}
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	out.Header.Set(HeaderForwarded, "1")
	if team := forwardTeam(access); team != "" {
		out.Header.Set(HeaderTeam, team)
	}
	if id := auditlog.CorrelationIDFromContext(out.Context()); id != "" {
		out.Header.Set(HeaderCorrelationID, id)
	}
	auditlog.MarkForwarded(out.Context())
}

// stampForwardFromContext is StampForward for the reverse-proxy Director,
// which has only the outbound request; its context is the inbound one.
func stampForwardFromContext(out *http.Request) {
	access, _ := controlplane.AccessFromContext(out.Context())
	StampForward(out, access)
}

// forwardTeam is the team a forward must name: only credentials that select
// among team bindings carry one. The PAT, a node and a managed account have
// no team to select (their header is ignored by the peer), and a fleet
// binding's "*" is not a team name.
func forwardTeam(access controlplane.Access) string {
	switch access.Principal.Kind {
	case controlplane.PrincipalToken, controlplane.PrincipalOIDC:
	default:
		return ""
	}
	if access.Fleet {
		return ""
	}
	return access.Team()
}
