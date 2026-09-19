package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestIngressTopTwoPreservesFullSortRouting(t *testing.T) {
	ids := []string{"ing-c", "ing-a", "ing-b", "ing-a", strings.Repeat("long-id", 60)}
	for shard := 0; shard < 100; shard++ {
		order := make([]int, len(ids))
		for i, id := range ids {
			order[i] = i
			old := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", shard, id)))
			if rendezvousScore(shard, id) != binary.BigEndian.Uint64(old[:8]) {
				t.Fatal("changed HRW hash remaps existing routes")
			}
		}
		sort.SliceStable(order, func(i, j int) bool {
			a, b := rendezvousScore(shard, ids[order[i]]), rendezvousScore(shard, ids[order[j]])
			return a > b || (a == b && ids[order[i]] < ids[order[j]])
		})
		for n := 1; n <= len(ids)+1; n++ {
			if got := rendezvousIngressOwnerIndexes(shard, ids, n); !slices.Equal(got, order[:min(n, len(ids))]) {
				t.Fatalf("shard %d n %d: got %v want %v", shard, n, got, order)
			}
		}
	}
}

func ingressBenchmarkMembers() []Member {
	members := make([]Member, 2000)
	for i := range members {
		members[i] = Member{NodeID: fmt.Sprintf("node-%04d", i), Alive: true, Role: config.NodeRoleWorker}
		if i < 100 {
			members[i].Role = config.NodeRoleIngress
		}
	}
	return members
}

func TestIngressShardCacheTracksTopologyAndOwnsResult(t *testing.T) {
	members := ingressBenchmarkMembers()
	var cache IngressShardFilterCache
	want := IngressShardFilterForNode(members, "node-0000", config.NodeRoleIngress)
	got := cache.ForNode(members, "node-0000", config.NodeRoleIngress)
	if !slices.Equal(got.Shards, want.Shards) {
		t.Fatal("cached result differs")
	}
	got.Shards[0] = -1
	cacheStorage := &cache.filter.Shards[0]
	slices.Reverse(members)
	if got := cache.ForNode(members, "node-0000", config.NodeRoleIngress); !slices.Equal(got.Shards, want.Shards) {
		t.Fatal("caller mutated cache or membership order remapped it")
	}
	if &cache.filter.Shards[0] != cacheStorage {
		t.Fatal("unchanged topology rebuilt the filter")
	}
	members[len(members)-1].Alive = false
	want = IngressShardFilterForNode(members, "node-0001", config.NodeRoleIngress)
	if got := cache.ForNode(members, "node-0001", config.NodeRoleIngress); !slices.Equal(got.Shards, want.Shards) {
		t.Fatal("membership change did not invalidate cache")
	}
}

func TestIngressShardAllocationBudget(t *testing.T) {
	// AllocsPerRun counts process-wide allocations. Other cluster tests leave
	// gossip/raft shutdown work in flight, so measure in a clean subprocess.
	const isolated = "AEROLVM_INGRESS_ALLOCATION_TEST"
	if os.Getenv(isolated) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestIngressShardAllocationBudget$", "-test.count=1")
		cmd.Env = append(os.Environ(), isolated+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated allocation check: %v\n%s", err, out)
		}
		return
	}
	members := ingressBenchmarkMembers()
	var cache IngressShardFilterCache
	// A fixed allocation budget catches the original millions-of-allocations
	// per-tick regression without a hardware-sensitive wall-clock assertion.
	if allocs := testing.AllocsPerRun(10, func() { cache.ForNode(members, "node-0001", config.NodeRoleIngress) }); allocs > 30 {
		t.Fatalf("cached filter allocated %.0f objects, budget 30", allocs)
	}
	if allocs := testing.AllocsPerRun(1, func() { IngressShardFilterForNode(members, "node-0001", config.NodeRoleIngress) }); allocs > 30 {
		t.Fatalf("cold filter allocated %.0f objects, budget 30", allocs)
	}
}

func BenchmarkIngressShardFilter100Ingress2000Nodes(b *testing.B) {
	members := ingressBenchmarkMembers()
	b.Run("cold", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			IngressShardFilterForNode(members, "node-0000", config.NodeRoleIngress)
		}
	})
	b.Run("cached", func(b *testing.B) {
		var cache IngressShardFilterCache
		cache.ForNode(members, "node-0000", config.NodeRoleIngress)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			cache.ForNode(members, "node-0000", config.NodeRoleIngress)
		}
	})
}

func TestIngressShardFilterReplicatesSmallIngressTier(t *testing.T) {
	members := []Member{
		{NodeID: "worker-a", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "ing-a", Role: config.NodeRoleIngress, Alive: true},
		{NodeID: "ing-b", Role: config.NodeRoleIngress, Alive: true},
		{NodeID: "ing-c", Role: config.NodeRoleIngress, Alive: true},
	}

	filter := IngressShardFilterForNode(members, "ing-b", config.NodeRoleIngress)
	if filter.ShardCount != 0 || len(filter.Shards) != 0 {
		t.Fatalf("filter = %+v, want empty all-shards filter for small ingress tier", filter)
	}
}

func TestIngressShardFilterShardsLargeIngressTier(t *testing.T) {
	members := make([]Member, 0, MaxReplicatedIngressRouteNodes+1)
	for i := 0; i < MaxReplicatedIngressRouteNodes+1; i++ {
		members = append(members, Member{
			NodeID: fmt.Sprintf("ing-%02d", i),
			Role:   config.NodeRoleIngress,
			Alive:  true,
		})
	}

	filter := IngressShardFilterForNode(members, "ing-05", config.NodeRoleIngress)
	if filter.ShardCount != DefaultPlacementShardCount {
		t.Fatalf("shard count = %d, want %d", filter.ShardCount, DefaultPlacementShardCount)
	}
	if len(filter.Shards) == 0 {
		t.Fatal("large ingress tier returned all-shards filter, want stable subset")
	}
	if len(filter.Shards) >= DefaultPlacementShardCount {
		t.Fatalf("large ingress tier returned %d shards, want subset", len(filter.Shards))
	}
}

func TestIngressRouteForSandboxReturnsAllOwnersForSmallIngressTier(t *testing.T) {
	members := []Member{
		{NodeID: "ing-b", APIURL: "http://ing-b:21212", DataPlaneHost: "ing-b.internal", Alive: true, Role: config.NodeRoleIngress},
		{NodeID: "worker-a", APIURL: "http://worker-a:21212", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "ing-a", APIURL: "http://ing-a:21212", DataPlaneHost: "ing-a.internal", Alive: true, Role: config.NodeRoleIngress},
	}

	route := IngressRouteForSandbox(members, "sb-route")
	if len(route.Owners) != 2 {
		t.Fatalf("owners = %+v, want both ingress owners", route.Owners)
	}
	if route.Owners[0].NodeID != "ing-a" || route.Owners[1].NodeID != "ing-b" {
		t.Fatalf("owners = %+v, want sorted ingress owners ing-a, ing-b", route.Owners)
	}
}

func TestIngressRouteForSandboxReturnsShardOwnerForLargeIngressTier(t *testing.T) {
	members := make([]Member, 0, MaxReplicatedIngressRouteNodes+1)
	for i := 0; i < MaxReplicatedIngressRouteNodes+1; i++ {
		members = append(members, Member{
			NodeID:        fmt.Sprintf("ing-%02d", i),
			APIURL:        fmt.Sprintf("http://ing-%02d:21212", i),
			DataPlaneHost: fmt.Sprintf("ing-%02d.internal", i),
			Alive:         true,
			Role:          config.NodeRoleIngress,
		})
	}

	route := IngressRouteForSandbox(members, "sb-route")
	wantShard := PlacementShardForSandbox("sb-route", DefaultPlacementShardCount)
	ids := ingressShardNodeIDs(members)
	wantIdxs := rendezvousIngressOwnerIndexes(wantShard, ids, 2)
	if len(route.Owners) != len(wantIdxs) {
		t.Fatalf("owners = %+v, want %d shard owners", route.Owners, len(wantIdxs))
	}
	for i, idx := range wantIdxs {
		if route.Owners[i].NodeID != ids[idx] {
			t.Fatalf("owners[%d] = %q, want %q", i, route.Owners[i].NodeID, ids[idx])
		}
	}
}

func TestIngressShardRendezvousStableUnderMembershipChurn(t *testing.T) {
	n := MaxReplicatedIngressRouteNodes + 5
	full := make([]Member, 0, n)
	for i := 0; i < n; i++ {
		full = append(full, Member{
			NodeID: fmt.Sprintf("ing-%02d", i),
			Alive:  true,
			Role:   config.NodeRoleIngress,
		})
	}
	shrunk := full[:n-1]
	moved := 0
	for shard := 0; shard < DefaultPlacementShardCount; shard++ {
		a := rendezvousIngressOwnerIndex(shard, ingressShardNodeIDs(full))
		b := rendezvousIngressOwnerIndex(shard, ingressShardNodeIDs(shrunk))
		if ingressShardNodeIDs(full)[a] != ingressShardNodeIDs(shrunk)[b] {
			moved++
		}
	}
	// Modulo assignment remaps ~99%; rendezvous should remap roughly 1/N.
	if moved > DefaultPlacementShardCount/2 {
		t.Fatalf("membership N→N-1 remapped %d/%d shards (want well under half)", moved, DefaultPlacementShardCount)
	}
}
