package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// Routing-mode lifecycle for SB_INGRESS_PROXY_ROUTING
// (plans/ingress-proxy-routing.md §5, task T9). The daemon drives it in
// three steps, each tied to a point in boot:
//
//	StartIngressProxyRouting   before the boot reconciles. Starts the route
//	                           responder, proves the resolver path, and swaps
//	                           in the index writer, so the boot reconciles
//	                           fill the in-memory tables instead of writing
//	                           Caddy.
//	CommitIngressProxyRouting  after the router is serving. Makes ONE Caddy
//	                           load (static routes plus pruning every
//	                           per-sandbox route), then prunes kernel
//	                           host-port rules nobody re-asserted.
//	RollbackIngressProxyRouting  on the first boot with the flag off after
//	                           it was on. Makes ONE Caddy load (removes the
//	                           static routes, re-asserts every per-sandbox
//	                           route) and removes the kernel rules.
//
// The flag is refused, and the node keeps writing Caddy routes, when the
// resolver path isn't proven. Engaging without it would drop every
// connection on this node.

// HostPortForwarder is the kernel forwarding the index writer drives for raw
// TCP host ports (*hostport.Forwarder on Linux).
type HostPortForwarder interface {
	Ensure(hostPort int, t hostport.Target) error
	Remove(hostPort int) error
	PruneUnasserted() error
	Reconcile(desired map[int]hostport.Target) error
}

var _ HostPortForwarder = (*hostport.Forwarder)(nil)

// IngressRoutingOptions wires the routing mode.
type IngressRoutingOptions struct {
	Static caddy.StaticRouteSpec
	// Forwarder is required: under the flag no Caddy tcp-port servers
	// remain, so without kernel forwarding raw TCP exposures would go dark.
	Forwarder HostPortForwarder
	// RedirectAddr is the listener that REDIRECTed host ports land on (wake
	// and WASM/isolate mediator targets), on workers. It must listen on
	// every address: REDIRECT rewrites the destination to the receiving
	// interface's address.
	RedirectAddr string
	// ProbeTimeout bounds the responder bind, each resolver probe, and the
	// wait for the first ingress index snapshot. Zero means 60s. Boot is
	// noisy: bootstrap restarts sandboxd back to back, so the previous
	// process may still hold the port, and install.sh restarts
	// systemd-resolved. A 5s budget refused the flag on every node of a
	// live cluster.
	ProbeTimeout time.Duration
	// SystemResolver is the resolver caddy-l4 dials through (nil: the
	// system resolver). Tests inject one.
	SystemResolver *net.Resolver
}

// IngressRouting is an engaged routing mode: the tables the host router
// reads, plus what Commit needs.
type IngressRouting struct {
	Owner       *routedns.OwnerTable
	Ingress     *routedns.IngressIndex // nil unless this node is a cluster ingress
	SelfNodeID  string
	ClusterMode bool

	opts        IngressRoutingOptions
	indexSynced chan struct{}
	stop        context.CancelFunc
}

// Stop ends the responder, the index watcher and the redirect listener.
func (r *IngressRouting) Stop() {
	if r != nil && r.stop != nil {
		r.stop()
	}
}

// StartIngressProxyRouting engages the routing mode's in-memory half. It
// returns (nil, nil) when the flag is off. On error nothing is left running
// and the Caddy writer stays in place.
func (s *Service) StartIngressProxyRouting(ctx context.Context, opts IngressRoutingOptions) (*IngressRouting, error) {
	if !s.cfg.IngressProxyRouting {
		return nil, nil
	}
	if s.caddy == nil || !s.caddy.Enabled() || s.cfg.Domain == "" {
		return nil, errors.New("ingress proxy routing needs Caddy in domain mode (SB_ENABLE_CADDY + SB_DOMAIN)")
	}
	if s.cfg.IsWorker() && !s.cfg.AutoReconcile {
		// The owner table is in memory. Caddy used to hold routes across
		// restarts; now the boot reconcile is what rebuilds them.
		return nil, errors.New("ingress proxy routing needs SB_AUTO_RECONCILE on worker nodes (the boot reconcile rebuilds the in-memory route table)")
	}
	if opts.Forwarder == nil {
		return nil, errors.New("ingress proxy routing needs kernel host-port forwarding (iptables), unavailable on this host")
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 60 * time.Second
	}

	rctx, cancel := context.WithCancel(ctx)
	r := &IngressRouting{
		Owner:       routedns.NewOwnerTable(),
		ClusterMode: s.cfg.EnableCluster,
		opts:        opts,
		indexSynced: make(chan struct{}),
		stop:        cancel,
	}
	if c := s.Cluster(); c != nil {
		r.SelfNodeID = c.SelfNodeID()
	}
	if s.cfg.EnableCluster && s.servesClusterIngress() {
		r.Ingress = routedns.NewIngressIndex()
	} else {
		close(r.indexSynced)
	}
	responder := &routedns.Responder{
		Domain:      s.cfg.Domain,
		SelfNodeID:  r.SelfNodeID,
		LocalIP:     net.ParseIP(opts.Static.LocalIP),
		ToolboxPort: s.cfg.ToolboxPort,
		Owner:       r.Owner,
		Ingress:     r.Ingress,
	}
	if r.Ingress != nil {
		responder.Miss = s.ingressMissLookup()
	}
	served := make(chan error, 1)
	go func() {
		// Retry the bind: on a back-to-back restart the previous process can
		// still hold the port for a moment.
		deadline := time.Now().Add(opts.ProbeTimeout)
		for {
			err := responder.ListenAndServe(rctx, s.cfg.RouteDNSAddr)
			if err == nil || rctx.Err() != nil || time.Now().After(deadline) {
				served <- err
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	fail := func(err error) (*IngressRouting, error) {
		cancel()
		return nil, err
	}
	// The owner's static route asks the responder directly; the ingress
	// dials through the system resolver, which must route the zone here.
	if err := waitRouteProbe(rctx, directResolver(s.cfg.RouteDNSAddr), opts.ProbeTimeout, served); err != nil {
		return fail(fmt.Errorf("route responder on %s: %w", s.cfg.RouteDNSAddr, err))
	}
	if r.Ingress != nil {
		if err := waitRouteProbe(rctx, opts.SystemResolver, opts.ProbeTimeout, served); err != nil {
			return fail(err)
		}
		var once sync.Once
		if !s.watchIngressRouteIndex(rctx, r.Ingress, func() { once.Do(func() { close(r.indexSynced) }) }) {
			// No change feed: the responder's on-miss read still answers
			// every host, one control-plane read per new name.
			s.logger.Warn("ingress proxy routing: no placement change feed; ingress index is on-miss only")
			once.Do(func() { close(r.indexSynced) })
		}
	}

	w := newIndexRouteWriter(r.Owner, s.cfg.Domain)
	w.tcp = opts.Forwarder
	if s.cfg.IsWorker() {
		ln, err := s.StartL4RedirectListener(rctx, opts.RedirectAddr)
		if err != nil {
			return fail(fmt.Errorf("host-port redirect listener %s: %w", opts.RedirectAddr, err))
		}
		w.redirectPort = ln.Addr().(*net.TCPAddr).Port
	}
	s.setRouteWriter(w)
	s.logger.Info("ingress proxy routing engaged",
		"route_dns_addr", s.cfg.RouteDNSAddr, "ingress_index", r.Ingress != nil, "redirect_port", w.redirectPort)
	return r, nil
}

// CommitIngressProxyRouting removes what the static routes replace, in one
// Caddy load. ownerReasserted says whether the boot reconcile re-asserted
// every local exposure. Only then is it safe to prune kernel rules nobody
// asserted: a failed pass would otherwise cut live sessions.
func (s *Service) CommitIngressProxyRouting(ctx context.Context, r *IngressRouting, ownerReasserted bool) error {
	if r == nil {
		return nil
	}
	ingressReasserted := true
	if r.Ingress != nil {
		select {
		case <-r.indexSynced:
		case <-time.After(r.opts.ProbeTimeout):
			s.logger.Warn("ingress proxy routing: first index snapshot not in yet; on-miss reads cover new hosts meanwhile")
		case <-ctx.Done():
			return ctx.Err()
		}
		// Re-asserts every ingress TCP proxy rule (the index writer's only
		// non-memory write) before the prune below.
		if err := s.ReconcileClusterIngress(ctx); err != nil {
			ingressReasserted = false
			s.logger.Warn("ingress proxy routing: ingress reconcile failed; skipping the host-port prune", "error", err)
		}
	}
	removed := 0
	err := s.caddy.Batch(ctx, func() error {
		if err := s.caddy.EnsureStaticSandboxRoute(ctx, r.opts.Static); err != nil {
			return err
		}
		if r.Ingress != nil && s.caddy.L4TLSListen() != "" {
			if err := s.caddy.EnsureStaticIngressRoutes(ctx, r.opts.Static); err != nil {
				return err
			}
		}
		n, err := s.caddy.PruneDynamicRoutes(ctx)
		removed = n
		return err
	})
	if err != nil {
		return fmt.Errorf("ingress proxy routing: static install + prune: %w", err)
	}
	if ownerReasserted && ingressReasserted {
		if err := r.opts.Forwarder.PruneUnasserted(); err != nil {
			return fmt.Errorf("ingress proxy routing: prune host-port rules: %w", err)
		}
	} else {
		s.logger.Warn("ingress proxy routing: boot re-assert incomplete; kernel host-port rules left for the next boot",
			"owner_reasserted", ownerReasserted, "ingress_reasserted", ingressReasserted)
	}
	s.logger.Info("ingress proxy routing committed", "caddy_entries_removed", removed)
	return nil
}

// RollbackIngressProxyRouting undoes a previous boot's routing mode in one
// Caddy load. It removes the static routes and re-asserts every per-sandbox
// route through the Caddy writer, then removes the kernel host-port rules
// (Caddy's tcp-port servers own the ports again). It runs the full boot
// reconcile inside the batch: that is the one complete re-assert of every
// route shape.
func (s *Service) RollbackIngressProxyRouting(ctx context.Context, fwd HostPortForwarder) error {
	// Back to Caddy route writes first, so the re-assert below (and any
	// concurrent lifecycle write) lands in the batch.
	s.setRouteWriter(nil)
	if s.caddy == nil || !s.caddy.Enabled() {
		return nil
	}
	err := s.caddy.Batch(ctx, func() error {
		if err := s.caddy.RemoveStaticRoutes(ctx); err != nil {
			return err
		}
		if s.cfg.IsWorker() {
			if err := s.Reconcile(ctx); err != nil {
				return err
			}
		}
		if s.cfg.EnableCluster && s.servesClusterIngress() {
			s.ingressLastHash.Store(0) // force the full pass
			if err := s.ReconcileClusterIngress(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ingress proxy routing rollback: %w", err)
	}
	if fwd != nil {
		if err := fwd.Reconcile(nil); err != nil {
			return fmt.Errorf("ingress proxy routing rollback: remove host-port rules: %w", err)
		}
	}
	s.logger.Info("ingress proxy routing rolled back to per-sandbox Caddy routes")
	return nil
}

// directResolver asks addr only (the responder), never the system resolver.
func directResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// waitRouteProbe retries checkRouteResolver until it passes, the timeout
// ends, or the responder stops serving.
func waitRouteProbe(ctx context.Context, resolver *net.Resolver, timeout time.Duration, served <-chan error) error {
	deadline := time.Now().Add(timeout)
	for {
		attempt := 2 * time.Second
		if left := time.Until(deadline); left > 0 && left < attempt {
			attempt = left
		}
		pctx, cancel := context.WithTimeout(ctx, attempt)
		err := checkRouteResolver(pctx, resolver)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case serr := <-served:
			if serr == nil {
				serr = errors.New("responder stopped")
			}
			return serr
		default:
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
