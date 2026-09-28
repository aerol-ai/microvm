package service

import (
	"context"
	"fmt"
	"net"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/routedns"
)

// watchIngressRouteIndex keeps the ingress side of the route responder
// current (plans/ingress-proxy-routing.md §3.4). It streams placement
// changes from whichever watcher this node has (an Agent's delta feed, or a
// server's own change log) and applies them in O(changes). It reports false
// when there is no watcher (the flag is off on an Agent, or single-node).
//
// synced (optional) runs after every full view is applied; the first call
// means the index holds the whole fleet.
func (s *Service) watchIngressRouteIndex(ctx context.Context, idx *routedns.IngressIndex, synced ...func()) bool {
	w, ok := s.Cluster().(cluster.PlacementChangeWatcher)
	if !ok || idx == nil {
		return false
	}
	domain := s.cfg.Domain
	return w.WatchPlacementChanges(ctx, func(full []cluster.Placement, changes []cluster.PlacementChange) {
		if full != nil {
			idx.Replace(full, domain)
			for _, fn := range synced {
				fn()
			}
		}
		applyIngressIndexChanges(idx, changes, domain)
	})
}

func applyIngressIndexChanges(idx *routedns.IngressIndex, changes []cluster.PlacementChange, domain string) {
	for _, ch := range changes {
		if ch.Deleted || ch.Placement == nil {
			idx.Remove(ch.SandboxID)
			continue
		}
		idx.Upsert(*ch.Placement, domain)
	}
}

// ingressMissLookup is the responder's on-miss read: the cluster's internal
// placement point read (not /ingress-route, which returns ring owners).
func (s *Service) ingressMissLookup() routedns.MissLookup {
	return func(_ context.Context, sandboxID string) (cluster.Placement, bool) {
		c := s.Cluster()
		if c == nil {
			return cluster.Placement{}, false
		}
		return c.PlacementOf(sandboxID)
	}
}

// checkRouteResolver proves the node's resolver routes the ingress zone to
// the route responder: it resolves routedns.ProbeName and expects
// routedns.ProbeIP. caddy-l4 dials "{sni}.rt.internal" through that same
// resolver, so a node without the routing domain would drop every sandbox
// connection. The flag must refuse to engage there (plan §3.1). resolver nil
// means the system resolver.
func checkRouteResolver(ctx context.Context, resolver *net.Resolver) error {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupHost(ctx, routedns.ProbeName+".")
	if err != nil {
		return fmt.Errorf("route responder probe %s: %w (is *.%s routed to SB_ROUTE_DNS_ADDR? see install.sh --ingress-proxy-routing)", routedns.ProbeName, err, routedns.IngressZone)
	}
	for _, a := range addrs {
		if a == routedns.ProbeIP {
			return nil
		}
	}
	return fmt.Errorf("route responder probe %s answered %v, want %s: *.%s is routed somewhere other than the sandboxd responder", routedns.ProbeName, addrs, routedns.ProbeIP, routedns.IngressZone)
}
