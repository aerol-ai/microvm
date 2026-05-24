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
	"time"

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
//
// TouchSandbox bumps last_active_at so the lifecycle idle sweep does
// not stop a sandbox that is currently serving a long-lived request
// (WebSocket, SSE, long-poll). The handler calls it at request start
// AND on a 30s ticker for as long as the upstream proxy is running.
//
// IsSandboxStarted is the fast preflight check used to bypass request-body
// buffering for warm sandboxes. Buffering exists so the body survives the
// cold-start wait (and to enforce MaxBufferBytes against unbounded uploads
// during wake), but it has no purpose when the upstream is already running
// — paying that cost on every warm request would cap normal POST uploads
// at MaxBufferBytes and add avoidable memory pressure under load.
// Returns store.ErrNotFound when no sandbox row matches id so the handler
// can surface 404 without a second store hit.
type PortResolver interface {
	WakeAwarePortTarget(ctx context.Context, id string, port int) (service.PortEndpoint, error)
	TouchSandbox(ctx context.Context, id string) error
	IsSandboxStarted(ctx context.Context, id string) (bool, error)
}

// activityTickInterval is how often a long-lived in-flight request
// re-touches the sandbox during proxy.ServeHTTP. 30s is comfortably
// shorter than any realistic StopIfIdleFor (the field is documented
// as minutes) so a stream that emits no traffic for several minutes
// still keeps its sandbox marked active. Var (not const) so tests can
// shrink it to run in <1s.
var activityTickInterval = 30 * time.Second

// defaultUpstreamReadyTimeout bounds how long the handler will hold a
// caller's HTTP request after wake while polling the in-container
// service's TCP port. The wake helper itself returns as soon as
// StartSandbox reports the container is running, but the user's
// process inside the container (npm dev server, gunicorn, etc.)
// typically needs another few seconds to bind to its listening port.
// Without this hold the reverse proxy connects too early, gets
// ECONNREFUSED, and the ErrorHandler returns 502.
//
// 30s leaves headroom for slow framework boots (Rails, Spring) without
// holding a client connection indefinitely. Operators can override via
// Deps.UpstreamReadyTimeout if their workloads are slower.
var defaultUpstreamReadyTimeout = 30 * time.Second

// Deps wires the ingress proxy to the rest of the daemon. Resolver
// is required; MaxBufferBytes caps how much request body is buffered
// while a cold-start wake is in flight; UpstreamReadyTimeout bounds
// the post-wake TCP-readiness probe (zero → defaultUpstreamReadyTimeout).
//
// MaxPendingPerSandbox / MaxPendingGlobal / MaxBufferBytesGlobal cap
// how many cold-start requests can simultaneously hold the wake window
// and how much memory their buffered bodies may pin. Zero on any of
// them disables that specific cap (intended for tests; production
// wiring in cmd/sandboxd/main.go always sets all three).
type Deps struct {
	Resolver             PortResolver
	Logger               *slog.Logger
	MaxBufferBytes       int64
	UpstreamReadyTimeout time.Duration
	MaxPendingPerSandbox int
	MaxPendingGlobal     int
	MaxBufferBytesGlobal int64
}

// RegisterRoutes mounts the ingress proxy routes onto mux. The mux is
// expected to be served on a loopback-only listener (see pkg/api/server
// wiring in cmd/sandboxd/main.go).
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{
		deps:  d,
		state: newProxyState(d.MaxPendingPerSandbox, d.MaxPendingGlobal, d.MaxBufferBytesGlobal),
	}
	// {path...} captures everything after /__ingress/http/{id}/{port}/.
	// We register the prefix shape twice so that requests landing at
	// /__ingress/http/{id}/{port} (no trailing path) still match.
	mux.Handle(PathPrefix+"/{id}/{port}", http.HandlerFunc(h.httpWake))
	mux.Handle(PathPrefix+"/{id}/{port}/{path...}", http.HandlerFunc(h.httpWake))
}

type handlers struct {
	deps  Deps
	state *proxyState
}
