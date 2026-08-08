package cluster

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestIngressShardFilterReplicatesSmallIngressTier(t *testing.T) {
	members := []Member{
		{NodeID: "worker-a", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "ing-a", Role: config.NodeRoleIngress, Alive: true},
		{NodeID: "ing-b", Role: config.NodeRoleIngress, Alive: true},
		{NodeID: "ing-c", Role: config.NodeRoleIngress, Alive: true},
	}

	filter := IngressShardFilterForNode(members, "ing-b")
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

	filter := IngressShardFilterForNode(members, "ing-05")
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
	wantOwner := ids[rendezvousIngressOwnerIndex(wantShard, ids)]
	if len(route.Owners) != 1 || route.Owners[0].NodeID != wantOwner {
		t.Fatalf("owners = %+v, want single shard owner %q", route.Owners, wantOwner)
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
