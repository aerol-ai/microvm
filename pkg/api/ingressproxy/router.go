package ingressproxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// HostRoutes wires the host router: the fallback the static Caddy routes send
// a request to whenever the route responder answers NXDOMAIN
// (plans/ingress-proxy-routing.md §3.3). Nil means the router is not mounted
// (flag off), which is exactly today's behaviour.
type HostRoutes struct {
	Owner      *routedns.OwnerTable
	Ingress    *routedns.IngressIndex // nil on nodes that are not ingress
	SelfNodeID string
	// ClusterMode decides what an owner answers for a host it does not hold.
	// In a cluster that is 421 (the client reconnects, and the ingress,
	// which holds the full index, gives the real answer). Single-node has
	// no one to bounce to, so it answers 404.
	ClusterMode bool
}

// hostRoute dispatches by Host:
//
//	owner table hit    in-flux → 503 + Retry-After
//	                   wake / router / ready → serveSandboxPort (wake,
//	                   masking, WASM/isolate mediators, readiness)
//	ingress index hit  in-flux → 503 · private → 404 · owned elsewhere → 421
//	                   (HTTP/2 connection coalescing, review 2A)
//	miss               ingress → 404 (it holds the full index)
//	                   worker in a cluster → 421 (review T6: no lookup, no
//	                   existence oracle) · single-node → 404
func (h *handlers) hostRoute(w http.ResponseWriter, r *http.Request) {
	hr := h.deps.Hosts
	host := requestHost(r)
	if hr == nil || host == "" {
		apihttp.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if hr.Owner != nil {
		if t, ok := hr.Owner.Lookup(host); ok {
			if t.State == routedns.TargetInFlux {
				w.Header().Set("Retry-After", "2")
				apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox is moving; retry")
				return
			}
			if t.SandboxID == "" || t.GuestPort <= 0 {
				apihttp.WriteError(w, http.StatusNotFound, "not found")
				return
			}
			h.serveSandboxPort(w, r, t.SandboxID, t.GuestPort, r.URL.Path)
			return
		}
	}
	if hr.Ingress != nil {
		e, ok := hr.Ingress.Lookup(host)
		switch {
		case !ok, e.Private:
			apihttp.WriteError(w, http.StatusNotFound, "not found")
		case e.InFlux:
			w.Header().Set("Retry-After", "2")
			apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox is moving; retry")
		case e.Routable && e.OwnerNodeID != hr.SelfNodeID:
			misdirected(w)
		default:
			// Owned here but no route entry: not public or not exposed.
			apihttp.WriteError(w, http.StatusNotFound, "not found")
		}
		return
	}
	if hr.ClusterMode {
		misdirected(w)
		return
	}
	apihttp.WriteError(w, http.StatusNotFound, "not found")
}

// misdirected answers 421. For HTTP/2 this tells the client to retry the
// request on a NEW connection, which the ingress splices to the right owner.
// It also closes this HTTP/1.1 connection, for the same reason.
func misdirected(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	apihttp.WriteError(w, http.StatusMisdirectedRequest, "misdirected request; reconnect")
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
