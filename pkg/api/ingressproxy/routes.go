// Package ingressproxy implements the loopback HTTP listener that
// fronts wake-aware Caddy port routes. Caddy rewrites a request hitting
// {id}-{port}.{domain} to /__ingress/http/{id}/{port}{path} and forwards
// it to this listener; the handler then wakes the sandbox (if armed)
// and reverse-proxies to {containerIP}:{port}.
//
// This listener MUST bind to loopback only. It carries no auth — Caddy
// is the trust boundary.
package ingressproxy

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
)

// PathPrefix is the URL prefix Caddy rewrites wake-aware HTTP port
// requests to. The shape is fixed (id / port / remaining path); both
// the route helper in pkg/caddy and the handlers in this package share
// it as the single grep target.
const PathPrefix = "/__ingress/http"

// PortResolver is the narrow slice of *service.Service the ingress
// handler needs. Kept as an interface so the package is testable
// without standing up a real Service + Docker + store stack.
type PortResolver interface {
	WakeAwarePortTarget(ctx context.Context, id string, port int) (service.PortEndpoint, error)
}

// Deps wires the ingress proxy to the rest of the daemon. Resolver
// is required; MaxBufferBytes caps how much request body is buffered
// while a cold-start wake is in flight.
type Deps struct {
	Resolver       PortResolver
	Logger         *slog.Logger
	MaxBufferBytes int64
}

// RegisterRoutes mounts the ingress proxy routes onto mux. The mux is
// expected to be served on a loopback-only listener (see pkg/api/server
// wiring in cmd/sandboxd/main.go).
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}
	// {path...} captures everything after /__ingress/http/{id}/{port}/.
	// We register the prefix shape twice so that requests landing at
	// /__ingress/http/{id}/{port} (no trailing path) still match.
	mux.Handle(PathPrefix+"/{id}/{port}", http.HandlerFunc(h.httpWake))
	mux.Handle(PathPrefix+"/{id}/{port}/{path...}", http.HandlerFunc(h.httpWake))
}

type handlers struct {
	deps Deps
}
