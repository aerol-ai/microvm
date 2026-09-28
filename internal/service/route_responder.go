package service

import (
	"context"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/routedns"
)

// watchIngressRouteIndex keeps the ingress side of the route responder
// current (plans/ingress-proxy-routing.md §3.4). It streams placement
// changes from whichever watcher this node has (an Agent's delta feed, or a
// server's own change log) and applies them in O(changes). It reports false
// when there is no watcher (the flag is off on an Agent, or single-node).
func (s *Service) watchIngressRouteIndex(ctx context.Context, idx *routedns.IngressIndex) bool {
	w, ok := s.Cluster().(cluster.PlacementChangeWatcher)
	if !ok || idx == nil {
		return false
	}
	domain := s.cfg.Domain
	return w.WatchPlacementChanges(ctx, func(full []cluster.Placement, changes []cluster.PlacementChange) {
		if full != nil {
			idx.Replace(full, domain)
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
