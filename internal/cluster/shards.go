package cluster

import (
	"hash/fnv"
	"sort"
)

// DefaultPlacementShardCount is the stable shard space for placement-index
// reads. The value intentionally stays independent from the number of ingress
// nodes: ingress ownership changes remap shard IDs to nodes, but a sandbox's
// shard ID remains stable as the fleet scales up and down.
const DefaultPlacementShardCount = 1024

// PlacementShardFilter asks the control plane for only a subset of placement
// shards. Empty Shards means "all shards" for compatibility with existing
// callers; ShardCount <= 0 uses DefaultPlacementShardCount.
type PlacementShardFilter struct {
	ShardCount int   `json:"shard_count,omitempty"`
	Shards     []int `json:"shards,omitempty"`
}

// Normalize returns a deterministic, de-duplicated copy of f.
func (f PlacementShardFilter) Normalize() PlacementShardFilter {
	shardCount := f.ShardCount
	if shardCount <= 0 {
		shardCount = DefaultPlacementShardCount
	}
	if len(f.Shards) == 0 {
		return PlacementShardFilter{ShardCount: shardCount}
	}
	seen := make(map[int]struct{}, len(f.Shards))
	shards := make([]int, 0, len(f.Shards))
	for _, shard := range f.Shards {
		if shard < 0 || shard >= shardCount {
			continue
		}
		if _, ok := seen[shard]; ok {
			continue
		}
		seen[shard] = struct{}{}
		shards = append(shards, shard)
	}
	sort.Ints(shards)
	return PlacementShardFilter{ShardCount: shardCount, Shards: shards}
}

func (f PlacementShardFilter) allShards() bool {
	f = f.Normalize()
	return len(f.Shards) == 0
}

// PlacementShardForSandbox maps sandboxID to a stable shard ID in [0, count).
func PlacementShardForSandbox(sandboxID string, count int) int {
	if count <= 0 {
		count = DefaultPlacementShardCount
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(sandboxID))
	return int(h.Sum32() % uint32(count))
}
