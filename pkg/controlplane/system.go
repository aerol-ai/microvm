package controlplane

import (
	"context"
	"strings"
)

// System callers name the daemon subsystem behind work no request asked for:
// boot restore, reconcile, lifecycle, failover recreate, image GC
// (plans/identity-and-access.md §5.8). An audit record written by such work
// says caller system:<subsystem> instead of nothing, so "who deleted this
// sandbox" always has an answer.
//
// A system caller is deliberately NOT an Access. Owner scoping reads "no
// Access in context" as unscoped, and operator-only capability checks treat
// it as an internal call; attaching an Access to background work would
// change both. It is attribution only.

type systemCallerKey struct{}

// SystemPrincipalPrefix starts every system principal id.
const SystemPrincipalPrefix = string(PrincipalSystem) + ":"

// SystemPrincipal is the principal for subsystem: kind system, id
// system:<subsystem>. An empty subsystem names the daemon as a whole.
func SystemPrincipal(subsystem string) Principal {
	subsystem = strings.TrimSpace(subsystem)
	if subsystem == "" {
		subsystem = SystemDaemon
	}
	return Principal{Kind: PrincipalSystem, ID: SystemPrincipalPrefix + subsystem}
}

// SystemDaemon is the subsystem an audit record names when background work
// reached it through an entry point nobody tagged. Seeing it in a record
// means an entry point should be given its own name.
const SystemDaemon = "daemon"

// ContextWithSystemCaller marks ctx as background work done by subsystem. A
// request's caller always wins over it: SystemCallerFromContext is consulted
// only when ctx carries no Access, so tagging a shared helper can never
// re-attribute an API call to the daemon.
func ContextWithSystemCaller(ctx context.Context, subsystem string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, systemCallerKey{}, SystemPrincipal(subsystem))
}

// SystemCallerFromContext returns the system principal ContextWithSystemCaller
// attached, if any.
func SystemCallerFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	p, ok := ctx.Value(systemCallerKey{}).(Principal)
	return p, ok
}
