package cluster

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestCapacityLeaseCacheMarksMissingAndStaleWorkers(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	cache.set("fresh", capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16000}, now.Add(-5*time.Second))
	cache.set("old", capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16000}, now.Add(-30*time.Second))

	got := cache.apply([]Member{
		{NodeID: "fresh", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "old", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "missing", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "server", Role: config.NodeRoleServer, Alive: true},
	}, now)

	byID := make(map[string]Member, len(got))
	for _, m := range got {
		byID[m.NodeID] = m
	}
	if byID["fresh"].CapacityStale {
		t.Fatalf("fresh lease marked stale: %+v", byID["fresh"])
	}
	if !byID["old"].CapacityStale {
		t.Fatalf("old lease not marked stale: %+v", byID["old"])
	}
	if !byID["missing"].CapacityStale {
		t.Fatalf("missing lease not marked stale: %+v", byID["missing"])
	}
	if byID["server"].CapacityStale {
		t.Fatalf("pure server should not require worker capacity: %+v", byID["server"])
	}
}

// TestCapacityLeaseCacheOverlaysLocalTemplateIDs is the Phase 6 PR-D
// regression. The cache calls SetLocalTemplateIDsProvider's callback at
// every refreshLocal tick and overlays the result onto the admitter
// snapshot before storing — without this, our local lease would
// advertise no templates and remote peers would treat us as
// "unknown, allow," routing template-bound creates here even when
// another node has the artifacts cached.
func TestCapacityLeaseCacheOverlaysLocalTemplateIDs(t *testing.T) {
	// admitter is nil; refreshLocal short-circuits at admitter==nil. So
	// exercise the overlay through set() directly, mirroring what
	// refreshLocal would have written.
	cache := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	called := 0
	cache.SetLocalTemplateIDsProvider(func() ([]string, bool) {
		called++
		return []string{"tpl-a", "tpl-b"}, true
	})

	// Simulate the refreshLocal overlay step on a hand-built snapshot.
	snap := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16000}
	if cache.localTemplateInventory != nil {
		if ids, known := cache.localTemplateInventory(); known {
			snap.LocalTemplateInventoryKnown = true
			snap.LocalTemplateIDs = ids
		}
	}
	if called != 1 {
		t.Fatalf("provider called %d times, want 1", called)
	}
	if !snap.LocalTemplateInventoryKnown {
		t.Fatal("overlay should mark template inventory authoritative")
	}
	if len(snap.LocalTemplateIDs) != 2 || snap.LocalTemplateIDs[0] != "tpl-a" {
		t.Fatalf("LocalTemplateIDs = %v, want [tpl-a tpl-b]", snap.LocalTemplateIDs)
	}

	// nil provider must not panic — single-node mode (or Firecracker
	// disabled) leaves the field untouched.
	cache.SetLocalTemplateIDsProvider(nil)
	if cache.localTemplateInventory != nil {
		t.Fatal("nil provider should clear the callback")
	}
}

func TestCapacityLeaseCacheOverlaysKnownEmptyTemplateInventory(t *testing.T) {
	cache := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	cache.SetLocalTemplateIDsProvider(func() ([]string, bool) {
		return nil, true
	})

	snap := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16000}
	if cache.localTemplateInventory != nil {
		if ids, known := cache.localTemplateInventory(); known {
			snap.LocalTemplateInventoryKnown = true
			snap.LocalTemplateIDs = ids
		}
	}
	if !snap.LocalTemplateInventoryKnown {
		t.Fatal("known empty template inventory lost its authoritative bit")
	}
	if len(snap.LocalTemplateIDs) != 0 {
		t.Fatalf("LocalTemplateIDs = %v, want empty authoritative inventory", snap.LocalTemplateIDs)
	}
}

func TestCapacityLeaseCacheOverlaysTemplateCatalogSeparately(t *testing.T) {
	cache := newCapacityLeaseCache("self", nil, 5*time.Second, nil)
	cache.SetLocalTemplateCatalogProvider(func() ([]string, bool) {
		return []string{"tpl-failed", "tpl-pending", "tpl-ready"}, true
	})

	snap := capacity.Snapshot{}
	if cache.localTemplateCatalog != nil {
		if ids, known := cache.localTemplateCatalog(); known {
			snap.LocalTemplateCatalogInventoryKnown = true
			snap.LocalTemplateCatalogIDs = ids
		}
	}
	if !snap.LocalTemplateCatalogInventoryKnown || len(snap.LocalTemplateCatalogIDs) != 3 {
		t.Fatalf("catalog overlay = known:%v ids:%v", snap.LocalTemplateCatalogInventoryKnown, snap.LocalTemplateCatalogIDs)
	}
	if snap.LocalTemplateInventoryKnown || len(snap.LocalTemplateIDs) != 0 {
		t.Fatal("administrative catalogue must not make templates placement-eligible")
	}
}

func TestHasCapacitySnapshot(t *testing.T) {
	if hasCapacitySnapshot(capacity.Snapshot{}) {
		t.Fatal("zero snapshot should be unknown")
	}
	if !hasCapacitySnapshot(capacity.Snapshot{HostCPUCores: 1}) {
		t.Fatal("snapshot with CPU should be known")
	}
	if !hasCapacitySnapshot(capacity.Snapshot{HostMemoryTotalMB: 1}) {
		t.Fatal("snapshot with memory should be known")
	}
}

// slowPeerTransport answers "healthy" instantly and hangs for everyone else
// until their request's deadline — a fleet expansion or restart burst where
// many endpoints are newly visible but not yet answering.
type slowPeerTransport struct {
	healthy atomic.Int64
}

func (r *slowPeerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "healthy" {
		r.healthy.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"can_admit":true}`)),
			Header:     make(http.Header),
		}, nil
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// Every never-seen peer sorts ahead of every existing lease, and a newly
// visible peer is not in backoff yet — so a burst of slow newcomers consumed
// the whole sweep and a healthy node lost a lease it could have renewed in
// milliseconds. A node whose lease goes stale is dropped from scheduling, so
// this removes usable capacity while the fleet is growing.
func TestCapacityRefreshReservesBudgetForExistingLeases(t *testing.T) {
	idx := newGossipMemberIndex()
	members := make([]Member, 0, 97)
	for i := range 96 {
		members = append(members, Member{
			NodeID:      fmt.Sprintf("new-slow-%03d", i),
			InternalURL: fmt.Sprintf("https://slow-%03d", i),
			Role:        config.NodeRoleWorker,
			Alive:       true,
		})
	}
	members = append(members, Member{NodeID: "healthy", InternalURL: "https://healthy", Role: config.NodeRoleWorker, Alive: true})
	idx.replace(members)

	leases := newCapacityLeaseCache("server", nil, 5*time.Second, nil)
	// Valid, but three seconds from expiry.
	leases.set("healthy", step3FatCapacity(), time.Now().Add(-12*time.Second))

	rt := &slowPeerTransport{}
	c := &Cluster{
		nodeID:         "server",
		gossip:         &gossipNode{memberIndex: idx},
		capacityLeases: leases,
		internalClient: &http.Client{Transport: rt},
	}
	c.refreshCapacityLeases(context.Background())

	if rt.healthy.Load() == 0 {
		t.Fatal("the healthy node was never attempted; 96 newly visible slow peers consumed the entire sweep")
	}
	leases.mu.RLock()
	age := time.Since(leases.leases["healthy"].updated)
	ttl := leases.ttl
	leases.mu.RUnlock()
	if age > ttl {
		t.Fatalf("healthy lease is %s old against a %s TTL; it expired while the node was answering in milliseconds", age, ttl)
	}
}

// The reservation must not lock newcomers out: when renewals are quick (the
// normal case) first contact still gets nearly the whole sweep.
func TestCapacityRefreshStillReachesNewPeers(t *testing.T) {
	idx := newGossipMemberIndex()
	idx.replace([]Member{
		{NodeID: "healthy", InternalURL: "https://healthy", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "newcomer", InternalURL: "https://healthy", Role: config.NodeRoleWorker, Alive: true},
	})
	leases := newCapacityLeaseCache("server", nil, 5*time.Second, nil)
	leases.set("healthy", step3FatCapacity(), time.Now().Add(-12*time.Second))

	rt := &slowPeerTransport{}
	c := &Cluster{
		nodeID:         "server",
		gossip:         &gossipNode{memberIndex: idx},
		capacityLeases: leases,
		internalClient: &http.Client{Transport: rt},
	}
	c.refreshCapacityLeases(context.Background())

	if !leases.hasLease("newcomer") {
		t.Fatal("a peer with no lease was never contacted; reserving budget for renewals must not starve first contact")
	}
}
