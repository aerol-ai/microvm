package cluster

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unique"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/google/uuid"
)

// liveMembers is a member lookup where every listed node is alive.
func liveMembers(nodes ...string) func(string) (Member, bool) {
	set := map[string]bool{}
	for _, n := range nodes {
		set[n] = true
	}
	return func(id string) (Member, bool) {
		if !set[id] {
			return Member{}, false
		}
		return Member{NodeID: id, Alive: true, APIURL: "http://" + id, InternalURL: "https://" + id + ":7002"}, true
	}
}

func TestOwnerCacheGetReturnsTheLiveEndpoint(t *testing.T) {
	oc := NewOwnerCache("edge", 0, 0, liveMembers("worker-a"))
	if oc.max != ownerCacheMaxEntries || oc.ttl != ownerCacheTTL {
		t.Fatalf("defaults = %d entries, %s; want %d, %s", oc.max, oc.ttl, ownerCacheMaxEntries, ownerCacheTTL)
	}
	if _, ok := oc.Get("sb-1"); ok {
		t.Fatal("hit on an empty cache")
	}
	// The URL in the lookup is ignored: the entry is used at the node's
	// current gossip address.
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a", InternalURL: "https://old:7002"}, "acct-a", true)
	got, ok := oc.Get("sb-1")
	want := OwnerRoute{Endpoint: Endpoint{NodeID: "worker-a", InternalURL: "https://worker-a:7002", APIURL: "http://worker-a"}, OwnerRef: "acct-a", HasOwnerRef: true}
	if !ok || got != want {
		t.Fatalf("Get = %+v, %v; want %+v", got, ok, want)
	}
}

// An entry is used only while gossip says its node is alive and reachable
// over the internal channel; otherwise the router looks the sandbox up.
func TestOwnerCacheSkipsNodesGossipCannotReach(t *testing.T) {
	cases := map[string]func(string) (Member, bool){
		"unknown node": func(string) (Member, bool) { return Member{}, false },
		"dead node": func(id string) (Member, bool) {
			return Member{NodeID: id, Alive: false, InternalURL: "https://" + id}, true
		},
		"no internal URL":  func(id string) (Member, bool) { return Member{NodeID: id, Alive: true}, true },
		"no member lookup": nil,
	}
	for name, member := range cases {
		t.Run(name, func(t *testing.T) {
			oc := NewOwnerCache("edge", 4, time.Minute, member)
			oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
			if _, ok := oc.Get("sb-1"); ok {
				t.Fatal("cache routed to a node gossip cannot reach")
			}
			if oc.Len() != 1 {
				t.Fatal("an unreachable node must not drop the entry; a fresh lookup replaces it")
			}
		})
	}
}

// The cache holds at most max entries and drops the least recently used.
func TestOwnerCacheEvictsLeastRecentlyUsed(t *testing.T) {
	oc := NewOwnerCache("edge", 3, time.Minute, liveMembers("worker-a"))
	for _, id := range []string{"sb-1", "sb-2", "sb-3"} {
		oc.Put(id, OwnerInfo{NodeID: "worker-a"}, "", false)
	}
	oc.Get("sb-1") // sb-2 is now the oldest
	oc.Put("sb-4", OwnerInfo{NodeID: "worker-a"}, "", false)
	if oc.Len() != 3 {
		t.Fatalf("Len = %d, want 3", oc.Len())
	}
	if _, ok := oc.Get("sb-2"); ok {
		t.Fatal("least recently used entry survived")
	}
	for _, id := range []string{"sb-1", "sb-3", "sb-4"} {
		if _, ok := oc.Get(id); !ok {
			t.Fatalf("%s evicted", id)
		}
	}
	if got := ownerCacheEntries.Value(); got != 3 {
		t.Fatalf("entries gauge = %d, want 3", got)
	}
}

// An entry is at most ttl old: an expired one is dropped on first touch.
// A fresh lookup's Put restarts the clock.
func TestOwnerCacheExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	oc := NewOwnerCache("edge", 4, 30*time.Second, liveMembers("worker-a"))
	oc.now = func() time.Time { return now }
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	now = now.Add(29 * time.Second)
	if _, ok := oc.Get("sb-1"); !ok {
		t.Fatal("expired early")
	}
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	now = now.Add(29 * time.Second)
	if _, ok := oc.Get("sb-1"); !ok {
		t.Fatal("Put did not restart the clock")
	}
	now = now.Add(time.Second)
	if _, ok := oc.Get("sb-1"); ok {
		t.Fatal("entry used at its TTL")
	}
	if oc.Len() != 0 {
		t.Fatal("expired entry kept")
	}
}

// A local serve must always come from a lookup, so this node is never an
// entry: a lookup that finds the sandbox here drops the old entry.
func TestOwnerCacheNeverHoldsThisNode(t *testing.T) {
	oc := NewOwnerCache("edge", 4, time.Minute, liveMembers("worker-a", "edge"))
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	oc.Put("sb-1", OwnerInfo{NodeID: "edge", IsSelf: true}, "", false)
	if oc.Len() != 0 {
		t.Fatal("self-owned sandbox cached")
	}
	oc.Put("sb-2", OwnerInfo{NodeID: "edge"}, "", false)
	oc.Put("sb-3", OwnerInfo{NodeID: "  "}, "", false)
	oc.Put("", OwnerInfo{NodeID: "worker-a"}, "", false)
	if oc.Len() != 0 {
		t.Fatalf("Len = %d, want 0", oc.Len())
	}
	// Defensive: an entry naming this node is never returned.
	oc.entries["sb-4"] = oc.lru.PushFront(&ownerCacheEntry{sandboxID: "sb-4", node: unique.Make("edge"), ownerRef: unique.Make(""), expires: time.Now().Add(time.Minute)})
	if _, ok := oc.Get("sb-4"); ok {
		t.Fatal("entry naming this node used")
	}
}

// The tenant is immutable for a sandbox id, so an unscoped caller's lookup
// (which does not read it) keeps the tenant an earlier lookup learned for the
// same owner, and loses it when the owner changes.
func TestOwnerCachePutKeepsAKnownTenant(t *testing.T) {
	oc := NewOwnerCache("edge", 4, time.Minute, liveMembers("worker-a", "worker-b"))
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "acct-a", true)
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	if r, _ := oc.Get("sb-1"); !r.HasOwnerRef || r.OwnerRef != "acct-a" {
		t.Fatalf("tenant lost on a same-owner refresh: %+v", r)
	}
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-b"}, "", false)
	if r, _ := oc.Get("sb-1"); r.HasOwnerRef || r.Endpoint.NodeID != "worker-b" {
		t.Fatalf("tenant kept across an owner change: %+v", r)
	}
	oc.Forget("sb-1")
	oc.Forget("sb-unknown")
	if oc.Len() != 0 {
		t.Fatal("Forget kept the entry")
	}
}

func TestOwnerCacheNilIsANoop(t *testing.T) {
	var oc *OwnerCache
	if _, ok := oc.Get("sb-1"); ok {
		t.Fatal("nil cache hit")
	}
	oc.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	oc.Forget("sb-1")
	if oc.Len() != 0 {
		t.Fatal("nil cache holds entries")
	}
}

// Only a worker or ingress Agent with SB_CLUSTER_OWNER_CACHE keeps a cache.
// A server node reads its own FSM, and a single node routes nothing.
func TestOwnerCacheOf(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "worker-a", Alive: true, InternalURL: "https://worker-a:7002"})
	on := &Agent{cfg: config.Config{ClusterOwnerCache: true}, nodeID: "ingress-1", gossip: &gossipNode{memberIndex: index}}
	on.ownerCache = newAgentOwnerCache(on)
	off := &Agent{cfg: config.Config{}, nodeID: "ingress-1"}
	off.ownerCache = newAgentOwnerCache(off)

	if OwnerCacheOf(on) == nil {
		t.Fatal("flag on: no cache")
	}
	if OwnerCacheOf(off) != nil || OwnerCacheOf(&Cluster{}) != nil || OwnerCacheOf(NewNoop("n", "", "")) != nil {
		t.Fatal("cache where the flag is off, on a server node, or on a single node")
	}
	if (*Agent)(nil).OwnerCache() != nil || newAgentOwnerCache(nil) != nil {
		t.Fatal("nil agent has a cache")
	}

	// The Agent's cache reads liveness from the gossip index.
	c := OwnerCacheOf(on)
	c.Put("sb-1", OwnerInfo{NodeID: "worker-a"}, "", false)
	c.Put("sb-2", OwnerInfo{NodeID: "worker-gone"}, "", false)
	if r, ok := c.Get("sb-1"); !ok || r.Endpoint.InternalURL != "https://worker-a:7002" {
		t.Fatalf("live member: %+v %v", r, ok)
	}
	if _, ok := c.Get("sb-2"); ok {
		t.Fatal("member missing from the gossip index used")
	}
}

func TestOwnerCacheConcurrentUse(t *testing.T) {
	oc := NewOwnerCache("edge", 64, time.Minute, liveMembers("worker-a", "worker-b"))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := fmt.Sprintf("sb-%d", (g*7+i)%128)
				switch i % 3 {
				case 0:
					oc.Put(id, OwnerInfo{NodeID: []string{"worker-a", "worker-b"}[i%2]}, "acct", i%2 == 0)
				case 1:
					oc.Get(id)
				default:
					oc.Forget(id)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := oc.Len(); n > 64 {
		t.Fatalf("Len = %d over the bound", n)
	}
}

// TestOwnerCacheMemoryPerEntry measures what a full cache costs: realistic
// sandbox ids, 2,000 owner nodes, 500 tenants. The number goes in the PR and
// in the ownerCacheMaxEntries comment.
func TestOwnerCacheMemoryPerEntry(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector changes allocation sizes")
	}
	nodes := make([]string, 2000)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("worker-%04d", i)
	}
	tenants := make([]string, 500)
	for i := range tenants {
		tenants[i] = "acct-" + uuid.NewString()
	}
	ids := make([]string, ownerCacheMaxEntries)
	for i := range ids {
		ids[i] = "sb-" + uuid.NewString()
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	oc := NewOwnerCache("edge", ownerCacheMaxEntries, time.Minute, nil)
	for i, id := range ids {
		// A copy: in the daemon the id comes from the request path, so the
		// cache is what keeps its bytes alive.
		oc.Put(strings.Clone(id), OwnerInfo{NodeID: nodes[i%len(nodes)]}, tenants[i%len(tenants)], true)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	perEntry := float64(after.HeapAlloc-before.HeapAlloc) / float64(oc.Len())
	t.Logf("owner cache: %d entries, %.0f bytes/entry, %.2f MiB total",
		oc.Len(), perEntry, perEntry*float64(oc.Len())/(1<<20))
	if perEntry > 400 {
		t.Fatalf("%.0f bytes per entry; the documented bound is 400", perEntry)
	}
	runtime.KeepAlive(ids)
	runtime.KeepAlive(oc)
}

// The routing counters the router (pkg/api/clusterroute) bumps.
func TestRouteAndOwnerCacheCounters(t *testing.T) {
	reqs, hits, misses, retries, notOwner := clusterRouteRequests.Value(), ownerCacheHits.Value(), ownerCacheMisses.Value(), ownerCacheRetries.Value(), ownerCacheNotOwner.Value()
	lookup := func(hop string) int64 {
		v, _ := clusterRouteLookups.Get(hop).(interface{ Value() int64 })
		if v == nil {
			return 0
		}
		return v.Value()
	}
	edge, owner := lookup(RouteHopEdge), lookup(RouteHopOwner)
	RecordRouteRequest()
	RecordRouteLookup(RouteHopEdge)
	RecordRouteLookup(RouteHopOwner)
	RecordRouteLookup(RouteHopOwner)
	RecordOwnerCacheHit()
	RecordOwnerCacheMiss()
	RecordOwnerCacheRetry()
	RecordOwnerCacheNotOwner()
	if clusterRouteRequests.Value()-reqs != 1 || lookup(RouteHopEdge)-edge != 1 || lookup(RouteHopOwner)-owner != 2 {
		t.Fatal("route counters did not move")
	}
	if ownerCacheHits.Value()-hits != 1 || ownerCacheMisses.Value()-misses != 1 || ownerCacheRetries.Value()-retries != 1 || ownerCacheNotOwner.Value()-notOwner != 1 {
		t.Fatal("owner cache counters did not move")
	}
}
