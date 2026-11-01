// Package clusterroute holds the one cluster owner-forwarding wrapper every
// API surface shares. Each facade used to carry its own near-identical copy
// (plan D2): the copies disagreed on the lookup-error status (v1 500, the
// facades 503) and on whether to check the forwarding-loop header, and only
// Daytona resolved a per-owner name. One wrapper ends the drift; a facade
// supplies only its own error envelope and, when its routes are keyed by
// something other than "id", the key.
package clusterroute

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// ErrorWriter renders one error in the calling facade's envelope.
type ErrorWriter func(w http.ResponseWriter, status int, message string)

// Options configures Wrap for one facade.
type Options struct {
	// PathKey is the request path value holding the sandbox id. "" means "id".
	PathKey string
	// ResolveName also looks the key up as a per-owner sandbox name when it
	// is not a known id (Daytona's idOrName routes). Names are unique per
	// owner, resolved in the caller's namespace.
	ResolveName bool
	// ID overrides where the sandbox id comes from. Default: the PathKey
	// path value. /e2b/runtime carries it in a header, so it sets this.
	ID func(*http.Request) string
	// WriteError renders an error in the facade's envelope. Required.
	WriteError ErrorWriter
}

// Wrap routes a per-sandbox request to the node that owns the sandbox,
// serving it locally when this node owns it (or when there is no cluster).
// It is the single owner-forward path for v1 and every facade. A nil svc
// (daemon started without one) serves locally.
func Wrap(svc *service.Service, opts Options, local http.Handler) http.Handler {
	key := opts.PathKey
	if key == "" {
		key = "id"
	}
	write := opts.WriteError
	idFrom := opts.ID
	if idFrom == nil {
		idFrom = func(r *http.Request) string { return r.PathValue(key) }
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(idFrom(r))
		if id == "" || svc == nil {
			local.ServeHTTP(w, r)
			return
		}
		c := svc.Cluster()
		if c == nil {
			local.ServeHTTP(w, r)
			return
		}
		// An owner-scoped (validated user-token) caller must not learn that
		// another tenant's sandbox exists through the routing states below — a
		// 410 (owner died) or a 503 naming the owner node, versus a plain 404
		// for an unknown id, is an existence oracle (#15). When the global
		// placement says this id belongs to a different tenant, hand it to the
		// local handler, which answers 404 via owner scoping, exactly as it
		// would for an id that does not exist. Operator/unscoped callers
		// (empty owner) route fleet-wide as before; name-based routes are
		// already resolved in the caller's own namespace (OwnerOfName).
		if callerOwner := strings.TrimSpace(service.OwnerRefForCreate(r.Context())); callerOwner != "" {
			if p, ok := c.PlacementOf(id); ok && strings.TrimSpace(p.OwnerRef) != callerOwner {
				local.ServeHTTP(w, r)
				return
			}
		}
		// serveLocal hands the request to the local handler, whose answer
		// for an id with no local row is 404. While this node's placement
		// view is catching up after a restart that 404 is a guess: the
		// placement (or the move away from this node) may simply not have
		// been applied here yet. Serve a row this node holds; for one it
		// does not, answer 503 + Retry-After instead of a false "gone".
		serveLocal := func(localID string) {
			if !cluster.CaughtUp(c) && !svc.HasLocalSandbox(r.Context(), localID) {
				WriteNotCaughtUp(w, write)
				return
			}
			local.ServeHTTP(w, r)
		}
		localID := id
		owner, err := c.OwnerOf(id)
		if errors.Is(err, cluster.ErrUnknownSandbox) && opts.ResolveName {
			// Per-owner name, resolved in the caller's namespace — the same
			// one the owner node's resolver uses.
			var resolved string
			resolved, owner, err = c.OwnerOfName(service.OwnerRefForCreate(r.Context()), id)
			if err == nil && strings.TrimSpace(resolved) != "" {
				localID = resolved
			}
		}
		switch {
		case errors.Is(err, cluster.ErrUnknownSandbox):
			// Not a cluster-known sandbox: let the local handler answer
			// (it decides 404, or serves a local-only row).
			serveLocal(localID)
			return
		case errors.Is(err, cluster.ErrOrphaned):
			// The owner died and was evicted; the placement points nowhere.
			write(w, http.StatusGone, "sandbox owner died; placement orphaned (manual recovery required)")
			return
		case err != nil:
			// A transient lookup failure: retryable, so 503 (v1 used to
			// return 500 here).
			write(w, http.StatusServiceUnavailable, "cluster lookup: "+err.Error())
			return
		}
		if owner.IsSelf {
			serveLocal(localID)
			return
		}
		if owner.APIURL == "" && owner.InternalURL == "" {
			// Placement says a peer owns it, but no forwarding URL has
			// surfaced yet (gossip lag, peer mid-boot).
			service.RecordRouteMiss()
			write(w, http.StatusServiceUnavailable, "cluster: owner "+owner.NodeID+" URL unknown")
			return
		}
		if r.Header.Get("X-Cluster-Forwarded") == "1" {
			// Already forwarded once and landed here again: a loop, not a
			// second hop.
			cluster.RecordOwnerForwardStale()
			write(w, http.StatusMisdirectedRequest, "cluster: forwarding loop detected")
			return
		}
		c.ForwardHTTP(cluster.Endpoint{NodeID: owner.NodeID, InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}

// WriteNotCaughtUp answers a request whose truthful answer this node cannot
// give yet: its placement view is catching up after a restart, so "not
// found" would be a guess (cluster.ErrNotCaughtUp). 503 + Retry-After from
// the shared classification, in the caller's error envelope.
func WriteNotCaughtUp(w http.ResponseWriter, write ErrorWriter) {
	cluster.RecordNotCaughtUpReject()
	cls := apihttp.Classify(cluster.ErrNotCaughtUp)
	cls.SetRetryAfter(w)
	write(w, cls.Status, cls.Message)
}
