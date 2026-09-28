package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/ingressproxy"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// routingService is the part of *service.Service the routing-mode boot
// drives, as an interface so the rollout matrix can be tested without a
// daemon.
type routingService interface {
	StartIngressProxyRouting(ctx context.Context, opts service.IngressRoutingOptions) (*service.IngressRouting, error)
	CommitIngressProxyRouting(ctx context.Context, r *service.IngressRouting, ownerReasserted bool) error
	RollbackIngressProxyRouting(ctx context.Context, fwd service.HostPortForwarder) error
}

// ingressRoutingBoot carries SB_INGRESS_PROXY_ROUTING through boot
// (plans/ingress-proxy-routing.md §5).
//
// The marker file records whether the last boot engaged the mode. It is
// written true BEFORE the commit's Caddy load, so a crash after the load
// still triggers the rollback on a later flag-off boot. It is written false
// only after a rollback fully succeeds, so a failed rollback is retried on
// the next boot. The same pattern is used for bypass_last_enabled.
type ingressRoutingBoot struct {
	routing *service.IngressRouting
	fwd     service.HostPortForwarder
	marker  string
	logger  *slog.Logger
}

func ingressRoutingMarkerPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.DBPath), "ingress_proxy_routing_last_enabled")
}

// startIngressRouting runs before the boot reconciles:
//   - Flag on: engage (the reconciles then fill the in-memory tables).
//   - Flag off after a flag-on boot: roll back in one Caddy load.
//
// A refused engage (resolver path not proven, no iptables, ...) leaves the
// node on per-sandbox Caddy routes. The node then keeps serving, just
// without the new routing.
func startIngressRouting(ctx context.Context, cfg config.Config, svc routingService, fwd service.HostPortForwarder, logger *slog.Logger) *ingressRoutingBoot {
	b := &ingressRoutingBoot{fwd: fwd, marker: ingressRoutingMarkerPath(cfg), logger: logger}
	if !cfg.IngressProxyRouting {
		if readBypassMarker(b.marker) {
			logger.Info("ingress proxy routing turned off since the last boot; rolling back to per-sandbox Caddy routes")
			if err := svc.RollbackIngressProxyRouting(ctx, fwd); err != nil {
				logger.Error("ingress proxy routing rollback failed; will retry next boot", "error", err)
				return b
			}
			b.writeMarker(false)
		}
		return b
	}
	if !cfg.IsWorker() && !cfg.IsIngress() {
		return b // a pure server node serves no sandbox traffic
	}
	routing, err := svc.StartIngressProxyRouting(ctx, service.IngressRoutingOptions{
		Static: caddy.StaticRouteSpec{
			RouteDNSAddr: cfg.RouteDNSAddr,
			RouterAddr:   cfg.InternalIngressAddr,
			ToolboxPort:  cfg.ToolboxPort,
			LocalIP:      "127.0.0.1",
		},
		Forwarder:    fwd,
		RedirectAddr: fmt.Sprintf(":%d", cfg.HostPortRedirectPort),
	})
	if err != nil {
		logger.Error("ingress proxy routing refused; keeping per-sandbox Caddy routes", "error", err)
		return b
	}
	b.routing = routing
	b.writeMarker(true)
	return b
}

// hostRoutes is the router the ingress mux mounts at "/" (nil: not engaged).
func (b *ingressRoutingBoot) hostRoutes() *ingressproxy.HostRoutes {
	if b == nil || b.routing == nil {
		return nil
	}
	return &ingressproxy.HostRoutes{
		Owner:       b.routing.Owner,
		Ingress:     b.routing.Ingress,
		SelfNodeID:  b.routing.SelfNodeID,
		ClusterMode: b.routing.ClusterMode,
	}
}

func (b *ingressRoutingBoot) engaged() bool { return b != nil && b.routing != nil }

// commit runs once the router is serving (it is the static routes'
// fallback). If it fails, the node rolls back to per-sandbox Caddy routes
// rather than sit half-switched. Half-switched means the index writer is
// live while Caddy still holds stale dynamic routes and no static ones.
func (b *ingressRoutingBoot) commit(ctx context.Context, svc routingService, ownerReasserted bool) {
	if !b.engaged() {
		return
	}
	err := svc.CommitIngressProxyRouting(ctx, b.routing, ownerReasserted)
	if err == nil {
		return
	}
	b.logger.Error("ingress proxy routing commit failed; rolling back to per-sandbox Caddy routes", "error", err)
	b.routing.Stop()
	b.routing = nil
	if rerr := svc.RollbackIngressProxyRouting(ctx, b.fwd); rerr != nil {
		b.logger.Error("ingress proxy routing rollback after a failed commit failed; will retry next boot", "error", rerr)
		return
	}
	b.writeMarker(false)
}

func (b *ingressRoutingBoot) writeMarker(v bool) {
	if err := writeBypassMarker(b.marker, v); err != nil {
		b.logger.Warn("write ingress proxy routing marker failed; rollback detection may misfire next boot",
			"marker_path", b.marker, "error", err)
	}
}

// newHostPortForwarder returns the kernel forwarder, or nil where iptables
// is unavailable. It returns an interface, never a typed nil, so the
// service's nil check works.
func newHostPortForwarder(logger *slog.Logger) service.HostPortForwarder {
	backend, err := hostport.NewIPTablesBackend()
	if err != nil {
		logger.Warn("iptables unavailable; raw-TCP host-port forwarding (ingress proxy routing) disabled", "error", err)
		return nil
	}
	return hostport.New(backend, hostport.FlushConntrack)
}
