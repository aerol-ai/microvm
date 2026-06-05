package cluster

import (
	"reflect"
	"testing"
)

func TestPlacementPageRequestNormalize(t *testing.T) {
	req := PlacementPageRequest{
		Limit:       -5,
		PageToken:   "foo",
		ShardFilter: PlacementShardFilter{ShardCount: -1},
	}
	norm := req.Normalize()
	if norm.Limit != DefaultPlacementPageLimit {
		t.Errorf("Limit = %v, want %v", norm.Limit, DefaultPlacementPageLimit)
	}
	if norm.PageToken != "foo" {
		t.Errorf("PageToken = %v, want %v", norm.PageToken, "foo")
	}

	req2 := PlacementPageRequest{Limit: MaxPlacementPageLimit + 10}
	norm2 := req2.Normalize()
	if norm2.Limit != MaxPlacementPageLimit {
		t.Errorf("Limit = %v, want %v", norm2.Limit, MaxPlacementPageLimit)
	}
}

func TestPlacementShardFilterNormalize(t *testing.T) {
	f := PlacementShardFilter{
		ShardCount: -1,
		Shards:     []int{3, 1, 1, 5, -1, 99999999},
	}
	norm := f.Normalize()
	if norm.ShardCount != DefaultPlacementShardCount {
		t.Errorf("ShardCount = %v, want %v", norm.ShardCount, DefaultPlacementShardCount)
	}
	wantShards := []int{1, 3, 5}
	if !reflect.DeepEqual(norm.Shards, wantShards) {
		t.Errorf("Shards = %v, want %v", norm.Shards, wantShards)
	}

	// Test allShards
	if !(PlacementShardFilter{}).allShards() {
		t.Errorf("allShards() = false, want true for empty filter")
	}
	if (PlacementShardFilter{Shards: []int{1}}).allShards() {
		t.Errorf("allShards() = true, want false for non-empty filter")
	}
}

func TestPlacementShardForSandbox(t *testing.T) {
	shard := PlacementShardForSandbox("sandbox-1", -1)
	if shard < 0 || shard >= DefaultPlacementShardCount {
		t.Errorf("shard = %v, want in [0, %v)", shard, DefaultPlacementShardCount)
	}

	shard2 := PlacementShardForSandbox("sandbox-1", 10)
	shard3 := PlacementShardForSandbox("sandbox-1", 10)
	if shard2 != shard3 {
		t.Errorf("expected deterministic shard for same sandbox")
	}
}

func TestIngressShardFilterForNodeEdgeCases(t *testing.T) {
	// Empty node ID
	f := IngressShardFilterForNode([]Member{}, "")
	if f.ShardCount != 0 {
		t.Errorf("expected empty filter for empty nodeID, got %+v", f)
	}
}

func TestIngressRouteForSandboxEdgeCases(t *testing.T) {
	route := IngressRouteForSandbox([]Member{}, "sb-1")
	if len(route.Owners) != 0 {
		t.Errorf("expected 0 owners, got %v", len(route.Owners))
	}
}
