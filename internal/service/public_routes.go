package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/caddy"
)

// publicRouteWriter is the single choke point for per-sandbox Caddy route
// writes (plans/ingress-proxy-routing.md §3.6, eng review 4A).
//
// Every per-sandbox HTTP, SNI-passthrough, in-flux, custom-domain and raw-TCP
// route write goes through it. Each such write is a Caddy admin call, and
// each admin call reloads Caddy's WHOLE config, which drops ~2.6% of new
// connections under churn (scripts/dev/caddy-reload-repro.py). Routing these
// writes through one interface is what makes "zero lifecycle writes" with
// SB_INGRESS_PROXY_ROUTING enforceable and testable: the flag swaps in
// noopRouteWriter, and tests swap in a counter. No call site can quietly
// keep a reload path alive.
//
// Deliberately NOT here:
//   - reads (Enabled, Snapshot, the URL/endpoint builders, Ping);
//   - owner-side protocol=tls port routes (UpsertTLSSNIRoute,
//     UpsertWakeTLSSNIRoute, DeleteTLSSNIRoute), which the plan keeps as rare
//     writes (TODOS "Owner-side protocol=tls port routes");
//   - boot-time bootstrap (EnsureLayer4, EnsureOnDemandTLS), which runs once.
type publicRouteWriter interface {
	// HTTP routes (owner).
	UpsertSandboxRoute(ctx context.Context, id, containerIP string, toolboxPort int, customs []caddy.CustomHostnameRoute) error
	UpsertSandboxRouteToPeer(ctx context.Context, id, peerHost string, customHostnames []string) error
	DeleteSandboxRoute(ctx context.Context, id string) error
	UpsertPortRoute(ctx context.Context, id, containerIP string, port int, opts ...caddy.HTTPRouteOptions) error
	UpsertPortRouteWithDial(ctx context.Context, id string, guestPort int, dial string, opts ...caddy.HTTPRouteOptions) error
	UpsertPortRouteWithRetry(ctx context.Context, id, containerIP string, port int, tryDuration time.Duration, opts ...caddy.HTTPRouteOptions) error
	UpsertPortRouteToPeer(ctx context.Context, id string, port int, peerHost string) error
	DeletePortRoute(ctx context.Context, id string, port int) error
	UpsertWakeHTTPPortRoute(ctx context.Context, id, ingressAddr string, port int) error
	DeleteWakeHTTPPortRoute(ctx context.Context, id string, port int) error
	UpsertInFluxSandboxRoute(ctx context.Context, id string) error
	DeleteInFluxSandboxRoute(ctx context.Context, id string) error
	UpsertInFluxPortRoute(ctx context.Context, id string, port int) error
	DeleteInFluxPortRoute(ctx context.Context, id string, port int) error
	UpsertCustomDomainHTTPRouteWithDial(ctx context.Context, sandboxID, hostname, dial string, opts ...caddy.HTTPRouteOptions) error
	DeleteCustomDomainHTTPRoute(ctx context.Context, sandboxID, hostname string) error

	// SNI passthrough (ingress).
	UpsertSNIPassthroughRoute(ctx context.Context, routeID, sniHost, peerHost string, peerPort int) error

	// Raw TCP host-port servers (owner + ingress).
	UpsertTCPRoute(ctx context.Context, id, containerIP string, port, hostPort int) error
	UpsertWakeTCPRoute(ctx context.Context, id string, port, hostPort int, wakeAddr string) error
	UpsertTCPProxyRoute(ctx context.Context, id string, port, hostPort int, peerHost string, peerPort int) error
	DeleteTCPRoute(ctx context.Context, hostPort int) error
	DeleteTCPServer(ctx context.Context, serverID string) error

	// Generic by-ID delete used by reconcile/GC for the routes above.
	DeleteRouteByID(ctx context.Context, routeID string) error
}

var _ publicRouteWriter = (*caddy.Client)(nil)

// publicRoutes returns the writer every per-sandbox route write must use.
// With no writer installed it is the concrete Caddy client, the exact
// pre-4A behaviour (including a nil *caddy.Client, whose methods the call
// sites already guard against).
func (s *Service) publicRoutes() publicRouteWriter {
	s.routeWriterMu.RLock()
	w := s.routeWriter
	s.routeWriterMu.RUnlock()
	if w != nil {
		return w
	}
	return s.caddy
}

// routesWrittenToCaddy reports whether per-sandbox route writes land in
// Caddy's config, so that Caddy's live config is where they can be checked.
// Under SB_INGRESS_PROXY_ROUTING they land in the in-memory index instead.
func (s *Service) routesWrittenToCaddy() bool {
	s.routeWriterMu.RLock()
	defer s.routeWriterMu.RUnlock()
	return s.routeWriter == nil
}

func (s *Service) setRouteWriter(w publicRouteWriter) {
	s.routeWriterMu.Lock()
	s.routeWriter = w
	s.routeWriterMu.Unlock()
}

// noopRouteWriter drops every per-sandbox route write. SB_INGRESS_PROXY_ROUTING
// installs it: routing then comes from the static routes plus the sandboxd
// responder, and a lifecycle event must not touch Caddy config.
type noopRouteWriter struct{}

var _ publicRouteWriter = noopRouteWriter{}

func (noopRouteWriter) UpsertSandboxRoute(context.Context, string, string, int, []caddy.CustomHostnameRoute) error {
	return nil
}
func (noopRouteWriter) UpsertSandboxRouteToPeer(context.Context, string, string, []string) error {
	return nil
}
func (noopRouteWriter) DeleteSandboxRoute(context.Context, string) error { return nil }
func (noopRouteWriter) UpsertPortRoute(context.Context, string, string, int, ...caddy.HTTPRouteOptions) error {
	return nil
}
func (noopRouteWriter) UpsertPortRouteWithDial(context.Context, string, int, string, ...caddy.HTTPRouteOptions) error {
	return nil
}
func (noopRouteWriter) UpsertPortRouteWithRetry(context.Context, string, string, int, time.Duration, ...caddy.HTTPRouteOptions) error {
	return nil
}
func (noopRouteWriter) UpsertPortRouteToPeer(context.Context, string, int, string) error { return nil }
func (noopRouteWriter) DeletePortRoute(context.Context, string, int) error               { return nil }
func (noopRouteWriter) UpsertWakeHTTPPortRoute(context.Context, string, string, int) error {
	return nil
}
func (noopRouteWriter) DeleteWakeHTTPPortRoute(context.Context, string, int) error        { return nil }
func (noopRouteWriter) UpsertInFluxSandboxRoute(context.Context, string) error            { return nil }
func (noopRouteWriter) DeleteInFluxSandboxRoute(context.Context, string) error            { return nil }
func (noopRouteWriter) UpsertInFluxPortRoute(context.Context, string, int) error          { return nil }
func (noopRouteWriter) DeleteInFluxPortRoute(context.Context, string, int) error          { return nil }
func (noopRouteWriter) DeleteCustomDomainHTTPRoute(context.Context, string, string) error { return nil }
func (noopRouteWriter) UpsertCustomDomainHTTPRouteWithDial(context.Context, string, string, string, ...caddy.HTTPRouteOptions) error {
	return nil
}
func (noopRouteWriter) UpsertSNIPassthroughRoute(context.Context, string, string, string, int) error {
	return nil
}
func (noopRouteWriter) UpsertTCPRoute(context.Context, string, string, int, int) error { return nil }
func (noopRouteWriter) UpsertWakeTCPRoute(context.Context, string, int, int, string) error {
	return nil
}
func (noopRouteWriter) UpsertTCPProxyRoute(context.Context, string, int, int, string, int) error {
	return nil
}
func (noopRouteWriter) DeleteTCPRoute(context.Context, int) error     { return nil }
func (noopRouteWriter) DeleteTCPServer(context.Context, string) error { return nil }
func (noopRouteWriter) DeleteRouteByID(context.Context, string) error { return nil }
