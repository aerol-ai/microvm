package remotemcp

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The Access hand-off (plans/identity-and-access.md §5.14, CEO review D10).
// /mcp authenticates once. Each tool's inner API call then carries the Access
// that authentication resolved, under a context key only inProcessTransport
// sets, and the API edge uses it instead of checking the bearer again. So an
// OAuth access token for an mcp_audiences audience never has to be valid on
// /v1, and /v1 still refuses one that arrives from outside.
//
// The inner call keeps the caller's own bearer, for one reason: a call on a
// sandbox another node owns is forwarded, and the owner verifies that bearer
// offline (L2). The hand-off never travels to a peer; a Go context does not
// cross the wire.
//
// An inner call that reaches the edge without the hand-off is a bug (eng
// review finding 2.5). The edge answers 500 and never falls back to the
// bearer, which would hold an /mcp token to /v1's rules, or act as whatever
// the bearer is on /v1.

type handoffKey struct{}

// handoff is the value under handoffKey. Its presence marks an inner call;
// ok says whether the outer /mcp request had an Access to hand over.
type handoff struct {
	access controlplane.Access
	ok     bool
}

func contextWithHandoff(ctx context.Context, access controlplane.Access, ok bool) context.Context {
	return context.WithValue(ctx, handoffKey{}, handoff{access: access, ok: ok})
}

// Handoff reports whether ctx belongs to a remote MCP tool's in-process inner
// call (inner) and, if so, the Access the outer /mcp request authenticated
// (ok). inner && !ok must never happen: the edge answers it with 500.
func Handoff(ctx context.Context) (access controlplane.Access, inner, ok bool) {
	if ctx == nil {
		return controlplane.Access{}, false, false
	}
	h, inner := ctx.Value(handoffKey{}).(handoff)
	return h.access, inner, h.ok
}
