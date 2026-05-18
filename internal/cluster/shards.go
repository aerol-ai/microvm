package cluster

import (
	"hash/fnv"
	"sort"
)

// DefaultPlacementShardCount is the stable shard space for placement-index
// reads. The value intentionally stays independent from the number of ingress
// nodes: ingress ownership changes remap shard IDs to nodes, but a sandbox's
// shard ID remains stable as the fleet scales up and down.
const DefaultPlacementShardCount = 16384

const (
	DefaultPlacementPageLimit = 1000
	MaxPlacementPageLimit     = 5000
)

// PlacementShardFilter asks the control plane for only a subset of placement
// shards. Empty Shards means "all shards" for compatibility with existing
// callers; ShardCount <= 0 uses DefaultPlacementShardCount.
type PlacementShardFilter struct {
	ShardCount int   `json:"shard_count,omitempty"`
	Shards     []int `json:"shards,omitempty"`
}

type PlacementPageRequest struct {
	Limit       int                  `json:"limit,omitempty"`
	PageToken   string               `json:"page_token,omitempty"`
	ShardFilter PlacementShardFilter `json:"shard_filter,omitempty"`
}

type PlacementPageResponse struct {
	Placements    []Placement `json:"placements"`
	NextPageToken string      `json:"next_page_token,omitempty"`
}

type IngressRouteOwner struct {
	NodeID        string `json:"node_id"`
	APIURL        string `json:"api_url,omitempty"`
	InternalURL   string `json:"internal_url,omitempty"`
	DataPlaneHost string `json:"data_plane_host,omitempty"`
}

type IngressShardRoute struct {
	SandboxID  string              `json:"sandbox_id"`
	Shard      int                 `json:"shard"`
	ShardCount int                 `json:"shard_count"`
	Owners     []IngressRouteOwner `json:"owners"`
}

func (r PlacementPageRequest) Normalize() PlacementPageRequest {
	limit := r.Limit
	if limit <= 0 {
		limit = DefaultPlacementPageLimit
	}
	if limit > MaxPlacementPageLimit {
		limit = MaxPlacementPageLimit
	}
	return PlacementPageRequest{
		Limit:       limit,
		PageToken:   r.PageToken,
		ShardFilter: r.ShardFilter.Normalize(),
	}
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

// IngressShardFilterForNode returns the stable placement shard subset a single
// ingress-capable node should reconcile. The nodeID is included even if gossip
// has not reported the local member yet, which keeps a freshly booted ingress
// process from temporarily reconciling the full placement table.
func IngressShardFilterForNode(members []Member, nodeID string) PlacementShardFilter {
	if nodeID == "" {
		return PlacementShardFilter{}
	}
	ids := ingressShardNodeIDs(members)
	found := false
	for _, id := range ids {
		if id == nodeID {
			found = true
			break
		}
	}
	if !found {
		ids = append(ids, nodeID)
		sort.Strings(ids)
	}
	selfIndex := -1
	for i, id := range ids {
		if id == nodeID {
			selfIndex = i
			break
		}
	}
	if selfIndex < 0 || len(ids) == 0 {
		return PlacementShardFilter{}
	}

	shards := make([]int, 0, DefaultPlacementShardCount/len(ids)+1)
	for shard := 0; shard < DefaultPlacementShardCount; shard++ {
		if shard%len(ids) == selfIndex {
			shards = append(shards, shard)
		}
	}
	return PlacementShardFilter{
		ShardCount: DefaultPlacementShardCount,
		Shards:     shards,
	}
}

// IngressRouteForSandbox returns the ingress owner set an upstream router
// should target for sandboxID. Today the owner set has one member; the slice is
// intentional so replicated shard owners can be added without changing the
// response shape.
func IngressRouteForSandbox(members []Member, sandboxID string) IngressShardRoute {
	shardCount := DefaultPlacementShardCount
	shard := PlacementShardForSandbox(sandboxID, shardCount)
	owners := ingressRouteOwners(members)
	route := IngressShardRoute{
		SandboxID:  sandboxID,
		Shard:      shard,
		ShardCount: shardCount,
		Owners:     []IngressRouteOwner{},
	}
	if len(owners) == 0 {
		return route
	}
	route.Owners = append(route.Owners, owners[shard%len(owners)])
	return route
}

func ingressShardNodeIDs(members []Member) []string {
	seen := make(map[string]struct{}, len(members))
	ids := make([]string, 0, len(members))
	for _, m := range members {
		if m.NodeID == "" || !m.Alive || !CanServeIngressRole(m.Role) {
			continue
		}
		if _, ok := seen[m.NodeID]; ok {
			continue
		}
		seen[m.NodeID] = struct{}{}
		ids = append(ids, m.NodeID)
	}
	sort.Strings(ids)
	return ids
}

func ingressRouteOwners(members []Member) []IngressRouteOwner {
	seen := make(map[string]struct{}, len(members))
	owners := make([]IngressRouteOwner, 0, len(members))
	for _, m := range members {
		if m.NodeID == "" || !m.Alive || !CanServeIngressRole(m.Role) {
			continue
		}
		if _, ok := seen[m.NodeID]; ok {
			continue
		}
		seen[m.NodeID] = struct{}{}
		owners = append(owners, IngressRouteOwner{
			NodeID:        m.NodeID,
			APIURL:        m.APIURL,
			InternalURL:   m.InternalURL,
			DataPlaneHost: m.DataPlaneHost,
		})
	}
	sort.Slice(owners, func(i, j int) bool {
		return owners[i].NodeID < owners[j].NodeID
	})
	return owners
}
