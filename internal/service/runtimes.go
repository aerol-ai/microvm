package service

import (
	"maps"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"golang.org/x/sync/singleflight"
)

// runtimeOffersTTL bounds how stale a cluster's runtime offers may be. On a
// worker or gateway, Members() is one control-plane call that carries every
// member's capacity (about 850 bytes a member, so ~1.7 MB at 2,000 nodes).
// The cache makes that at most one call per node per TTL, however many
// callers list runtimes. A runtime appears or goes away only when an
// operator changes a node, so a few seconds of lag costs nothing.
const runtimeOffersTTL = 5 * time.Second

// runtimeOffersCache holds the last cluster answer and makes concurrent
// misses share one Members() read.
type runtimeOffersCache struct {
	mu      sync.Mutex
	offers  map[string]int
	expires time.Time
	group   singleflight.Group
	// now is the clock; nil is time.Now. Tests set it.
	now func() time.Time
}

func (c *runtimeOffersCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *runtimeOffersCache) fresh() (map[string]int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offers == nil || !c.clock().Before(c.expires) {
		return nil, false
	}
	return c.offers, true
}

// get returns the cached offers or loads them once for every waiting caller.
// The result is a copy: one caller cannot change what the next one reads.
func (c *runtimeOffersCache) get(load func() map[string]int) map[string]int {
	if offers, ok := c.fresh(); ok {
		return maps.Clone(offers)
	}
	v, _, _ := c.group.Do("offers", func() (any, error) {
		if offers, ok := c.fresh(); ok {
			return offers, nil
		}
		offers := load()
		c.mu.Lock()
		c.offers, c.expires = offers, c.clock().Add(runtimeOffersTTL)
		c.mu.Unlock()
		return offers, nil
	})
	return maps.Clone(v.(map[string]int))
}

// RuntimeOffers reports, per runtime name, how many nodes offer it now: the
// names each node advertises (capacity.Snapshot.SupportedRuntimes, the list
// placement filters on). It reads only what this node already holds, and
// asks no worker: a single node reads its own admitter; a cluster node reads
// the members' last capacity heartbeats. Read-only; safe to call any number
// of times.
func (s *Service) RuntimeOffers() map[string]int {
	if !s.ClusterEnabled() {
		return s.localRuntimeOffers()
	}
	c := s.Cluster()
	if c == nil {
		return s.localRuntimeOffers()
	}
	return s.runtimeOffers.get(func() map[string]int { return clusterRuntimeOffers(c) })
}

// localRuntimeOffers is a single node's offers: what its admitter admits.
// No admitter (tests) offers nothing.
func (s *Service) localRuntimeOffers() map[string]int {
	offers := map[string]int{}
	if s.admitter == nil {
		return offers
	}
	for _, name := range s.admitter.SupportedRuntimes() {
		offers[name] = 1
	}
	return offers
}

// clusterRuntimeOffers counts, per runtime name, the members a create could
// be placed on now as far as the runtime goes: the static checks placement
// makes before it looks at free room (placementFilter.scan in
// internal/cluster). A member that is full still counts: it offers the
// runtime, and room comes and goes by the second.
//
// The drained set is read once, and only from a client that holds it in one
// read (cluster.DrainedNodesReader). Asking IsNodeDrained per member would
// be one control-plane call per member on a worker.
func clusterRuntimeOffers(c cluster.Client) map[string]int {
	var drained map[string]bool
	if reader, ok := c.(cluster.DrainedNodesReader); ok {
		drained = reader.DrainedNodes()
	}
	denied, _ := c.(cluster.DeniedNodeChecker)
	offers := map[string]int{}
	for _, m := range c.Members() {
		if !memberTakesSandboxes(m) || drained[m.NodeID] || (denied != nil && denied.IsNodeDenied(m.NodeID)) {
			continue
		}
		seen := make(map[string]bool, len(m.Capacity.SupportedRuntimes))
		for _, name := range m.Capacity.SupportedRuntimes {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			offers[name]++
		}
	}
	return offers
}

// memberTakesSandboxes reports whether placement would consider m at all:
// alive, not restarting, a role that runs sandboxes, and a fresh capacity
// heartbeat (the same test as cluster's hasCapacitySnapshot). A member with
// an empty runtime list is a build older than the field; placement lets it
// take any runtime, but this list claims only what a node reports.
func memberTakesSandboxes(m cluster.Member) bool {
	return m.Alive && !m.Restarting && cluster.CanOwnSandboxRole(m.Role) &&
		!m.CapacityStale && (m.Capacity.HostCPUCores > 0 || m.Capacity.HostMemoryTotalMB > 0)
}
