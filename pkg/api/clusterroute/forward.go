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
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
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
//
// On a worker or ingress node with SB_CLUSTER_OWNER_CACHE on, a request a
// client sent here first tries the owner cache (owner_cache.go in this
// package). A forward routed that way carries cluster.HeaderRouteHint, and the
// node it reaches serves it only when its own lookup says it owns the
// sandbox. Every other outcome is a 421 "not here", and the edge routes the
// call once more down the path below.
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
		// A single node routes nothing: its lookups are the Noop's constant
		// answers, so they are not counted as control-plane reads.
		_, single := c.(*cluster.Noop)
		if single && redirectToCell(svc, id, w, r, write) {
			return
		}
		hop := cluster.RouteHopEdge
		hint := ""
		var forwardEpoch uint64
		if r.Header.Get(cluster.HeaderForwarded) == "1" {
			hop = cluster.RouteHopOwner
			// Take the owner-cache token and drop the header before any
			// handler runs, so nothing behind this node (a toolbox proxy into
			// the sandbox) can see the token and forge a "not here".
			hint = r.Header.Get(cluster.HeaderRouteHint)
			r.Header.Del(cluster.HeaderRouteHint)
			forwardEpoch = cluster.ForwardedOwnerEpoch(r.Header)
			r.Header.Del(cluster.HeaderOwnerEpoch)
		} else if !single {
			cluster.RecordRouteRequest()
		}
		lookup := func() {
			if !single {
				cluster.RecordRouteLookup(hop)
			}
		}
		cache := cluster.OwnerCacheOf(c) // nil unless worker/ingress with the flag on
		if hop == cluster.RouteHopEdge && cache != nil && serveFromOwnerCache(c, cache, id, w, r, write) {
			return
		}

		// serveLocal hands the request to the local handler, whose answer
		// for an id with no local row is 404. While this node's placement
		// view is catching up after a restart that 404 is a guess: the
		// placement (or the move away from this node) may simply not have
		// been applied here yet. Serve a row this node holds; for one it
		// does not, answer 503 + Retry-After instead of a false "gone".
		serveLocal := func(localID string) {
			// A sandbox held by the ownership fence may be running on
			// another node by now: this node could not confirm it still
			// owns it, so it must not answer for it (I1).
			if svc.OwnershipFenced(localID) {
				WriteOwnershipFenced(w, write)
				return
			}
			if !cluster.CaughtUp(c) && !svc.HasLocalSandbox(r.Context(), localID) {
				WriteNotCaughtUp(w, write)
				return
			}
			local.ServeHTTP(w, r)
		}
		// E3b: a forward carrying the edge's owner epoch, which this node's
		// last authoritative read (the ownership lease) proves it owns at
		// that same epoch, is served without looking the sandbox up again:
		// the leader's recent answer and the edge's lookup agree. The edge
		// already checked the caller's tenant against the placement, and the
		// local handler scopes by owner again. A read holding a newer epoch
		// turns a cache-routed forward down, as the lookup below would; every
		// other case takes the lookup path.
		if hop == cluster.RouteHopOwner && forwardEpoch != 0 {
			switch svc.OwnerLeaseCheck(id, forwardEpoch, hint != "", time.Now()) {
			case service.OwnerLeaseOwned:
				cluster.RecordOwnerLeaseServe()
				serveLocal(id)
				return
			case service.OwnerLeaseNewer:
				if hint != "" {
					writeNotOwner(w, r, hint, write)
					return
				}
			}
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
		ownerRef, ownerRefKnown := "", false
		if callerOwner := strings.TrimSpace(service.OwnerRefForCreate(r.Context())); callerOwner != "" {
			lookup()
			p, ok := c.PlacementOf(id)
			if ok && strings.TrimSpace(p.OwnerRef) != callerOwner {
				if hint != "" {
					// The edge's entry named the wrong tenant: let the edge's
					// own lookup give the 404.
					writeNotOwner(w, r, hint, write)
					return
				}
				local.ServeHTTP(w, r)
				return
			}
			ownerRef, ownerRefKnown = callerOwner, ok
		}
		localID := id
		lookup()
		owner, err := c.OwnerOf(id)
		byName := false
		if errors.Is(err, cluster.ErrUnknownSandbox) && opts.ResolveName {
			// Per-owner name, resolved in the caller's namespace — the same
			// one the owner node's resolver uses.
			lookup()
			byName = true
			var resolved string
			resolved, owner, err = c.OwnerOfName(service.OwnerRefForCreate(r.Context()), id)
			if err == nil && strings.TrimSpace(resolved) != "" {
				localID = resolved
			}
		}
		if hint != "" && (err != nil || !owner.IsSelf) {
			// A forward the edge routed from its owner cache, and this node's
			// lookup does not say it owns the sandbox (or cannot say).
			// Serving it, or answering 404, 410 or 503, would be the stale
			// entry answering; the edge looks the sandbox up itself.
			writeNotOwner(w, r, hint, write)
			return
		}
		if hint != "" && forwardEpoch != 0 && owner.Epoch > forwardEpoch {
			// The edge's entry predates an owner change: the sandbox moved
			// away and came back to this node since the edge read it. This
			// node does own it, but an older epoch is turned down (I2): the
			// edge drops the entry and routes once more from a fresh lookup,
			// so its next entry carries the current epoch.
			writeNotOwner(w, r, hint, write)
			return
		}
		switch {
		case errors.Is(err, cluster.ErrUnknownSandbox):
			// Not a cluster-known sandbox: let the local handler answer
			// (it decides 404, or serves a local-only row).
			cache.Forget(id)
			// One minted in another cell is that cell's to answer. Only
			// the edge says so, and only once its placement view has
			// caught up: before that, "unknown" is a guess.
			if hop == cluster.RouteHopEdge && cluster.CaughtUp(c) && redirectToCell(svc, id, w, r, write) {
				return
			}
			serveLocal(localID)
			return
		case errors.Is(err, cluster.ErrOrphaned):
			// The owner died and was evicted; the placement points nowhere.
			cache.Forget(id)
			write(w, http.StatusGone, "sandbox owner died; placement orphaned (manual recovery required)")
			return
		case err != nil:
			// A transient lookup failure: retryable, so 503 (v1 used to
			// return 500 here).
			write(w, http.StatusServiceUnavailable, "cluster lookup: "+err.Error())
			return
		}
		if owner.IsSelf {
			cache.Forget(id)
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
		if !byName {
			// Only id lookups are cached: a name is per tenant and can be
			// reused, and the owner re-checks every entry anyway.
			cache.Put(id, owner, ownerRef, ownerRefKnown)
		}
		r = r.WithContext(cluster.ContextWithOwnerEpoch(r.Context(), owner.Epoch))
		c.ForwardHTTP(cluster.Endpoint{NodeID: owner.NodeID, InternalURL: owner.InternalURL, APIURL: owner.APIURL}, w, r)
	})
}

// redirectToCell answers 421 with the address of the cell a sandbox id was
// minted in, when that is another cell (C16, service.OtherCellEndpoint).
// Cells do not forward to each other, since each trusts only its own nodes;
// the SDKs send the request again to the address the header names.
func redirectToCell(svc *service.Service, id string, w http.ResponseWriter, r *http.Request, write ErrorWriter) bool {
	endpoint, ok := svc.OtherCellEndpoint(r.Context(), id)
	if !ok {
		return false
	}
	service.RecordCellRedirect()
	w.Header().Set(models.CellEndpointHeader, endpoint)
	write(w, http.StatusMisdirectedRequest, "this sandbox is in another cell: send the request to the address in "+models.CellEndpointHeader)
	return true
}

// WriteOwnershipFenced answers a request for a sandbox this node has paused
// because it could not confirm with the control plane that it still owns it
// (service.ErrOwnershipFenced). 503 + Retry-After, in the caller's envelope.
func WriteOwnershipFenced(w http.ResponseWriter, write ErrorWriter) {
	cls := apihttp.Classify(service.ErrOwnershipFenced)
	cls.SetRetryAfter(w)
	write(w, cls.Status, cls.Message)
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
