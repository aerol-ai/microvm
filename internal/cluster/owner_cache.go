package cluster

import (
	"container/list"
	"strings"
	"sync"
	"time"
	"unique"
)

// Owner cache on worker and ingress nodes (plan PR #1000, item E3a).
//
// A worker or ingress node (an Agent) holds no placement state, so routing one
// request for a sandbox costs control-plane round trips: the edge asks the
// server tier who owns it (OwnerOf, plus PlacementOf for a tenant-scoped
// caller), and the owner asks again when the forward arrives. That is up to
// four lookups for one call. With SB_CLUSTER_OWNER_CACHE on, the edge keeps
// the owner its last lookup found and forwards straight there.
//
// The cache only chooses where a request goes. It never answers one: not a
// 404, not a 410, not a local serve. The owner still looks the sandbox up on
// every request, and when the edge's entry is stale (the sandbox moved, was
// deleted, was orphaned or belongs to another tenant) it answers 421 with
// HeaderNotOwner instead of serving. The edge then drops the entry and routes
// the call once more from a fresh lookup, exactly as with the cache off. A
// stale entry costs one extra hop, never a different answer. Both halves live
// in pkg/api/clusterroute.
//
// Server-role nodes keep no cache: their lookups read the local FSM already.

const (
	// ownerCacheMaxEntries bounds the cache to the sandboxes an edge routes
	// most, not the fleet: at 100,000 sandboxes an edge keeps the busiest
	// 16,384, and a miss costs what every request costs with the cache off.
	// A full cache is about 3.8 MiB (~245 bytes per entry, measured by
	// TestOwnerCacheMemoryPerEntry), the same at any fleet size.
	ownerCacheMaxEntries = 16384
	// ownerCacheTTL bounds how old an entry can be. The 421 answer corrects
	// a stale entry whenever the old owner is up; the TTL covers the case it
	// cannot, an old owner that is unreachable but not yet dead in gossip.
	// It equals the default SB_DEAD_OWNER_GRACE, the soonest the cluster
	// moves a dead node's sandboxes.
	ownerCacheTTL = 30 * time.Second
)

// OwnerRoute is where a cached entry sends a sandbox's requests.
type OwnerRoute struct {
	// Endpoint is the owner's current gossip address, read when the entry is
	// used, so a node that restarted on a new URL is reached at the new one.
	Endpoint Endpoint
	// OwnerRef is the sandbox's tenant, known (HasOwnerRef) only when the
	// lookup that filled the entry read the placement for a scoped caller.
	OwnerRef    string
	HasOwnerRef bool
}

// OwnerCache is a bounded, least-recently-used map from sandbox id to owner
// node. Safe for concurrent use; every method is a no-op on a nil cache.
type OwnerCache struct {
	self   string
	max    int
	ttl    time.Duration
	now    func() time.Time
	member func(nodeID string) (Member, bool)

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List // front = most recently used
}

// ownerCacheEntry interns the node id and tenant: a fleet has a few thousand
// nodes and tenants but up to ownerCacheMaxEntries entries pointing at them.
type ownerCacheEntry struct {
	sandboxID   string
	node        unique.Handle[string]
	ownerRef    unique.Handle[string]
	hasOwnerRef bool
	expires     time.Time
}

// NewOwnerCache returns a cache for node self holding at most maxEntries
// entries for ttl each. member resolves a node id to its gossip record: an
// entry is used only while its node is alive there with an internal URL.
func NewOwnerCache(self string, maxEntries int, ttl time.Duration, member func(nodeID string) (Member, bool)) *OwnerCache {
	if maxEntries <= 0 {
		maxEntries = ownerCacheMaxEntries
	}
	if ttl <= 0 {
		ttl = ownerCacheTTL
	}
	return &OwnerCache{
		self:    self,
		max:     maxEntries,
		ttl:     ttl,
		now:     time.Now,
		member:  member,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Get returns where to forward sandboxID, or false when there is no fresh
// entry or its node is not a live gossip member with an internal URL.
func (oc *OwnerCache) Get(sandboxID string) (OwnerRoute, bool) {
	if oc == nil {
		return OwnerRoute{}, false
	}
	now := oc.now()
	oc.mu.Lock()
	el, ok := oc.entries[sandboxID]
	if !ok {
		oc.mu.Unlock()
		return OwnerRoute{}, false
	}
	e := el.Value.(*ownerCacheEntry)
	if !now.Before(e.expires) {
		oc.removeLocked(el)
		oc.mu.Unlock()
		return OwnerRoute{}, false
	}
	oc.lru.MoveToFront(el)
	node, ownerRef, hasOwnerRef := e.node.Value(), e.ownerRef.Value(), e.hasOwnerRef
	oc.mu.Unlock()

	// Gossip marks a node dead within seconds; the cache must not keep
	// sending it traffic until the dead-owner grace moves its sandboxes. A
	// miss here sends the request through a fresh lookup, as without a cache.
	if node == oc.self || oc.member == nil {
		return OwnerRoute{}, false
	}
	m, ok := oc.member(node)
	if !ok || !m.Alive || strings.TrimSpace(m.InternalURL) == "" {
		return OwnerRoute{}, false
	}
	return OwnerRoute{
		Endpoint:    Endpoint{NodeID: node, InternalURL: m.InternalURL, APIURL: m.APIURL},
		OwnerRef:    ownerRef,
		HasOwnerRef: hasOwnerRef,
	}, true
}

// Put records that a fresh lookup found sandboxID on owner. An owner that is
// this node is never stored: a local serve must always come from a lookup.
// An unscoped caller's lookup does not read the tenant, so it keeps a tenant
// an earlier lookup learned for the same owner.
func (oc *OwnerCache) Put(sandboxID string, owner OwnerInfo, ownerRef string, hasOwnerRef bool) {
	if oc == nil || sandboxID == "" {
		return
	}
	node := strings.TrimSpace(owner.NodeID)
	if node == "" || owner.IsSelf || node == oc.self {
		oc.Forget(sandboxID)
		return
	}
	nodeHandle := unique.Make(node)
	expires := oc.now().Add(oc.ttl)
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if el, ok := oc.entries[sandboxID]; ok {
		e := el.Value.(*ownerCacheEntry)
		if !hasOwnerRef && e.hasOwnerRef && e.node == nodeHandle {
			ownerRef, hasOwnerRef = e.ownerRef.Value(), true
		}
		e.node, e.ownerRef, e.hasOwnerRef, e.expires = nodeHandle, unique.Make(ownerRef), hasOwnerRef, expires
		oc.lru.MoveToFront(el)
		return
	}
	oc.entries[sandboxID] = oc.lru.PushFront(&ownerCacheEntry{
		sandboxID:   sandboxID,
		node:        nodeHandle,
		ownerRef:    unique.Make(ownerRef),
		hasOwnerRef: hasOwnerRef,
		expires:     expires,
	})
	for oc.lru.Len() > oc.max {
		oc.removeLocked(oc.lru.Back())
	}
	ownerCacheEntries.Set(int64(oc.lru.Len()))
}

// Forget drops sandboxID's entry, if any.
func (oc *OwnerCache) Forget(sandboxID string) {
	if oc == nil {
		return
	}
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if el, ok := oc.entries[sandboxID]; ok {
		oc.removeLocked(el)
	}
}

// Len is the number of entries held, expired ones included until touched.
func (oc *OwnerCache) Len() int {
	if oc == nil {
		return 0
	}
	oc.mu.Lock()
	defer oc.mu.Unlock()
	return oc.lru.Len()
}

func (oc *OwnerCache) removeLocked(el *list.Element) {
	delete(oc.entries, el.Value.(*ownerCacheEntry).sandboxID)
	oc.lru.Remove(el)
	ownerCacheEntries.Set(int64(oc.lru.Len()))
}

// OwnerCacheHolder is a Client that may keep an owner cache. Only the Agent
// implements it.
type OwnerCacheHolder interface {
	OwnerCache() *OwnerCache
}

// OwnerCacheOf returns c's owner cache, or nil: a server-role node, a single
// node, or SB_CLUSTER_OWNER_CACHE off.
func OwnerCacheOf(c Client) *OwnerCache {
	if h, ok := c.(OwnerCacheHolder); ok {
		return h.OwnerCache()
	}
	return nil
}

// OwnerCache returns this worker or ingress node's owner cache, or nil when
// SB_CLUSTER_OWNER_CACHE is off.
func (a *Agent) OwnerCache() *OwnerCache {
	if a == nil {
		return nil
	}
	return a.ownerCache
}

// newAgentOwnerCache builds the Agent's cache when the flag is on. It reads
// liveness from the gossip index only: a node missing from the index is a
// miss, not a scan of the whole membership on the request path.
func newAgentOwnerCache(a *Agent) *OwnerCache {
	if a == nil || !a.cfg.ClusterOwnerCache {
		return nil
	}
	return NewOwnerCache(a.nodeID, ownerCacheMaxEntries, ownerCacheTTL, func(nodeID string) (Member, bool) {
		return a.gossip.lookupMember(nodeID)
	})
}
