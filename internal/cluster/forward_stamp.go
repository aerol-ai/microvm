package cluster

import (
	"context"
	"net/http"
	"strconv"
	"strings"

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
	// HeaderPATOrigin says where the edge accepted a forwarded operator
	// token: PATOriginHost (a loopback peer, or a cluster peer acting for
	// itself) or PATOriginPublic (anything else). An owner under
	// SB_PAT_SCOPE=host refuses a forwarded PAT unless it says host, so one
	// node left on scope "any" cannot launder a remote PAT through a
	// forward (plans/identity-and-access.md §5.11). Like every X-Cluster-*
	// header it is honoured only from a live mTLS peer.
	HeaderPATOrigin = "X-Cluster-PAT-Origin"
	// HeaderSurface marks a forward of a remote MCP tool's inner API call
	// (§5.14). Its one value is auditlog.SurfaceMCP. On that forward, and
	// only there, the owner also accepts the caller's MCP-only access token
	// (an mcp_audiences audience), and records the call with surface mcp.
	// Like every X-Cluster-* header it is honoured only from a live mTLS
	// peer, and it widens where a verified credential is accepted; it never
	// supplies an identity.
	HeaderSurface = "X-Cluster-Surface"
	// HeaderSSHGateway marks a forward of a call the SSH gateway bridged
	// for the holder of a sandbox's key (auditlog.SSHGatewayCall.Encode:
	// the sandbox id, plus the open marker on the session's first call).
	// The owner then names sandbox_key:<id> as the caller, via the edge,
	// instead of the operator whose token the gateway's loopback hop
	// carries, and writes the session's ssh record. Like every X-Cluster-*
	// header it is honoured only from a live mTLS peer, and pkg/api honours
	// it only with the operator token, on the sandbox's sessions routes,
	// for the sandbox the path names.
	HeaderSSHGateway = "X-Cluster-Ssh-Gateway"
	// HeaderRouteHint marks a forward whose target came from the edge's
	// owner cache (owner_cache.go), not from a lookup the edge just made. Its
	// value is a random token the edge made for this one request. The
	// receiver serves the request only when its own lookup says it owns the
	// sandbox; otherwise it answers 421 with HeaderNotOwner set to the same
	// token. Like every X-Cluster-* header it is honoured only from a live
	// mTLS peer, and StampForward sets it only from the request context
	// (ContextWithRouteHint), never from a header that came in.
	HeaderRouteHint = "X-Cluster-Route-Hint"
	// HeaderNotOwner is the response header of that 421 ("not here"). It
	// echoes the request's HeaderRouteHint token. The edge routes the call
	// again only on a 421 carrying its own token, so a 421 from anything
	// else (the sandbox's own server behind a toolbox route, a node on an
	// older build) reaches the caller as it is and never causes a second
	// send. The receiver drops the hint header before any handler runs, so
	// nothing behind it can learn the token.
	HeaderNotOwner = "X-Cluster-Not-Owner"
	// HeaderOwnerEpoch carries the placement's OwnerEpoch the edge read when
	// it chose the target (invariant I2, plan C4 part 4): from a lookup it
	// just made, or from its owner-cache entry. The owner compares it with
	// its own reading and turns down a cache-routed forward that is older
	// (HeaderNotOwner). Like every X-Cluster-* header it is honoured only
	// from a live mTLS peer, and StampForward sets it only from the request
	// context (ContextWithOwnerEpoch).
	HeaderOwnerEpoch = "X-Cluster-Owner-Epoch"
)

type ownerEpochCtxKey struct{}

// ContextWithOwnerEpoch records the owner epoch the edge read for the
// forwards made under ctx. 0 records nothing.
func ContextWithOwnerEpoch(ctx context.Context, epoch uint64) context.Context {
	if epoch == 0 {
		return ctx
	}
	return context.WithValue(ctx, ownerEpochCtxKey{}, epoch)
}

// OwnerEpochFromContext is the epoch ContextWithOwnerEpoch recorded, or 0.
func OwnerEpochFromContext(ctx context.Context) uint64 {
	epoch, _ := ctx.Value(ownerEpochCtxKey{}).(uint64)
	return epoch
}

// ForwardedOwnerEpoch reads HeaderOwnerEpoch from a forward. 0: absent or
// malformed (an edge on an older build), which the owner treats as unknown.
func ForwardedOwnerEpoch(h http.Header) uint64 {
	epoch, err := strconv.ParseUint(strings.TrimSpace(h.Get(HeaderOwnerEpoch)), 10, 64)
	if err != nil {
		return 0
	}
	return epoch
}

type routeHintCtxKey struct{}

// ContextWithRouteHint marks the forwards made under ctx as routed from the
// owner cache, with token as the request's HeaderRouteHint.
func ContextWithRouteHint(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, routeHintCtxKey{}, token)
}

// RouteHintFromContext is the token ContextWithRouteHint recorded, or "".
func RouteHintFromContext(ctx context.Context) string {
	token, _ := ctx.Value(routeHintCtxKey{}).(string)
	return token
}

// PAT origins carried in HeaderPATOrigin.
const (
	PATOriginHost   = "host"
	PATOriginPublic = "public"
)

type patOriginCtxKey struct{}

// ContextWithPATOrigin records where the API edge accepted the operator
// token of this request, for StampForward to carry to the peer.
func ContextWithPATOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, patOriginCtxKey{}, origin)
}

// PATOriginFromContext is the origin ContextWithPATOrigin recorded, or "".
func PATOriginFromContext(ctx context.Context) string {
	origin, _ := ctx.Value(patOriginCtxKey{}).(string)
	return origin
}

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
//   - HeaderPATOrigin, for an operator-token caller: where the edge accepted
//     the PAT, from ContextWithPATOrigin. A PAT forward with no recorded
//     origin says public, the value an owner under host scope refuses: an
//     unknown origin must never pass as the host.
//   - HeaderSurface, when the request is a remote MCP tool's inner call
//     (the in-process transport marked its context with auditlog.SurfaceMCP;
//     nothing on the wire can). Without it the owner would refuse an
//     MCP-only access token and record the call without surface mcp. Any
//     other request has the header removed, so the marker always follows
//     the context and never a header that came in with the request.
//   - HeaderSSHGateway, when the API edge found the request to be a call
//     the SSH gateway bridged for a sandbox key holder (the context carries
//     auditlog.SSHGatewayCall). Removed from every other request, the same
//     way as HeaderSurface.
//   - HeaderRouteHint, when the edge routed the request from its owner
//     cache (ContextWithRouteHint). Removed from every other request, the
//     same way as HeaderSurface.
//   - HeaderOwnerEpoch, the owner epoch the edge read for its target
//     (ContextWithOwnerEpoch). Removed from every other request.
//
// It also marks the edge's api record as forwarded (auditlog.MarkForwarded):
// only the node that runs the handler records the call, so the peer writes
// the one record and the edge writes none (§5.9, "Forwarding").
//
// A new forward marker is added here, so no forward path can miss it.
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
	switch access.Principal.Kind {
	case controlplane.PrincipalOperator, controlplane.PrincipalNode:
		origin := PATOriginPublic
		if PATOriginFromContext(out.Context()) == PATOriginHost {
			origin = PATOriginHost
		}
		out.Header.Set(HeaderPATOrigin, origin)
	default:
		// Only the PAT has an origin rule; a stale marker copied from the
		// inbound request must not ride along on another credential.
		out.Header.Del(HeaderPATOrigin)
	}
	if id := auditlog.CorrelationIDFromContext(out.Context()); id != "" {
		out.Header.Set(HeaderCorrelationID, id)
	}
	if auditlog.SurfaceFromContext(out.Context()) == auditlog.SurfaceMCP {
		out.Header.Set(HeaderSurface, auditlog.SurfaceMCP)
	} else {
		out.Header.Del(HeaderSurface)
	}
	if call, ok := auditlog.SSHGatewayCallFromContext(out.Context()); ok {
		out.Header.Set(HeaderSSHGateway, call.Encode())
	} else {
		out.Header.Del(HeaderSSHGateway)
	}
	if token := RouteHintFromContext(out.Context()); token != "" {
		out.Header.Set(HeaderRouteHint, token)
	} else {
		out.Header.Del(HeaderRouteHint)
	}
	if epoch := OwnerEpochFromContext(out.Context()); epoch != 0 {
		out.Header.Set(HeaderOwnerEpoch, strconv.FormatUint(epoch, 10))
	} else {
		out.Header.Del(HeaderOwnerEpoch)
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
