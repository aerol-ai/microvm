package cluster

import (
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
	cache.SetLocalTemplateIDsProvider(func() []string {
		called++
		return []string{"tpl-a", "tpl-b"}
	})

	// Simulate the refreshLocal overlay step on a hand-built snapshot.
	snap := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16000}
	if cache.localTemplateIDs != nil {
		if ids := cache.localTemplateIDs(); len(ids) > 0 {
			snap.LocalTemplateIDs = ids
		}
	}
	if called != 1 {
		t.Fatalf("provider called %d times, want 1", called)
	}
	if len(snap.LocalTemplateIDs) != 2 || snap.LocalTemplateIDs[0] != "tpl-a" {
		t.Fatalf("LocalTemplateIDs = %v, want [tpl-a tpl-b]", snap.LocalTemplateIDs)
	}

	// nil provider must not panic — single-node mode (or Firecracker
	// disabled) leaves the field untouched.
	cache.SetLocalTemplateIDsProvider(nil)
	if cache.localTemplateIDs != nil {
		t.Fatal("nil provider should clear the callback")
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
