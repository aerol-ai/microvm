package cluster

import (
	"context"
	"net/http"
)

// Peer calls by node cert alone (plans/kubectl-style-cluster-ops.md §8).
//
// Every node used to hold the operator PAT and send it on each call to a
// peer, and the PAT plus a node cert made the caller "node:<id>". A worker
// or ingress node does not need an admin credential that also works from
// anywhere, so the join service now joins them without it (join.go), and
// such a node calls its peers with its cert alone:
//
//	caller                   bearer   internal listener says   API edge decides
//	node with the PAT        PAT      live peer <id>           node:<id> (as before)
//	node without the PAT     none     live peer <id>           node:<id>
//	anyone else              none     (TLS refused)            -
//
// The internal listener already refuses a connection without a cluster
// cert, then a deleted, re-keyed or unknown node (authorizePeerRequest).
// Only after those checks does it mark the request with the peer's ID
// (ContextWithInternalPeer), and pkg/api accepts a request with no bearer
// only when that mark is there. A context value cannot be sent over the
// network, so nothing on the public listener can claim it.
//
// A node that holds the PAT keeps sending it, so a cluster in the middle
// of a rolling upgrade works as it always did; the join service leaves the
// PAT out only once every member accepts a cert-only call (PATFreeJoin).

// peerCertAuthFSMOpsVersion: a build at this version accepts a peer's call
// that carries its node cert and no bearer. No FSM op: the version gates
// the join answer that leaves the PAT out, because an older peer would
// refuse every call such a node makes.
const peerCertAuthFSMOpsVersion = 15

// Headers for a forward of a request this node accepted from a local tool
// with its node-local token (pkg/api): that token means nothing on the
// peer, so StampForward drops the request's credential and the edge vouches
// for the call as itself.
const (
	// HeaderCaller says who a forward speaks for when it carries no user
	// credential. Its one value is CallerNode: the edge node itself. Like
	// every X-Cluster-* header it is honoured only from a live mTLS peer.
	HeaderCaller = "X-Cluster-Caller"
	CallerNode   = "node"
)

type internalPeerCtxKey struct{}

// ContextWithInternalPeer marks ctx as a request the internal listener
// took from the live, admitted peer nodeID. Only the internal listener
// calls it, after authorizePeerRequest.
func ContextWithInternalPeer(ctx context.Context, nodeID string) context.Context {
	return context.WithValue(ctx, internalPeerCtxKey{}, nodeID)
}

// InternalPeerFromContext is the peer ContextWithInternalPeer recorded.
func InternalPeerFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(internalPeerCtxKey{}).(string)
	return id, ok && id != ""
}

type localCallerCtxKey struct{}

// ContextWithLocalCaller marks a request this node accepted with its
// node-local token, so a forward of it carries no credential (StampForward).
func ContextWithLocalCaller(ctx context.Context) context.Context {
	return context.WithValue(ctx, localCallerCtxKey{}, true)
}

// LocalCallerFromContext reports whether ContextWithLocalCaller marked ctx.
func LocalCallerFromContext(ctx context.Context) bool {
	local, _ := ctx.Value(localCallerCtxKey{}).(bool)
	return local
}

// stampCaller is StampForward's credential step. A request a local tool
// made with this node's own token loses its credential, which no peer would
// accept, and says the edge node speaks for it. Any other forward keeps the
// user's credential and never carries the marker, so an edge that dropped a
// credential by mistake gets a 401 from the peer, not node powers.
func stampCaller(out *http.Request) {
	if !LocalCallerFromContext(out.Context()) {
		out.Header.Del(HeaderCaller)
		return
	}
	out.Header.Del("Authorization")
	out.Header.Del("X-API-KEY")
	out.Header.Set(HeaderCaller, CallerNode)
}
