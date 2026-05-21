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
