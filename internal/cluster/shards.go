package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DefaultPlacementShardCount is the stable shard space for placement-index
// reads. The value intentionally stays independent from the number of ingress
// nodes: ingress ownership changes remap shard IDs to nodes, but a sandbox's
// shard ID remains stable as the fleet scales up and down.
const DefaultPlacementShardCount = 16384

const (
	DefaultPlacementPageLimit = 1000
	MaxPlacementPageLimit     = 5000
	// MaxReplicatedIngressRouteNodes is the largest ingress tier where every
	// ingress-capable node keeps the full public route table. Ordinary DNS
	// round-robin / TCP load balancers can only work if any advertised ingress
	// node can answer for any sandbox.
	MaxReplicatedIngressRouteNodes = 10
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
	// OwnerRef, when set, returns only placements for that tenant account.
	OwnerRef string `json:"owner_ref,omitempty"`
	// OwnerNodeID, when set, returns only placements this cluster node owns.
	// Distinct from OwnerRef (tenant account). It is the read path a worker's
	// reconcile sweep uses to enumerate its own rows: at 100k sandboxes the
	// unfiltered view is ~72 MB, which every worker would otherwise pull on
	// every sweep. Reserved and orphaned rows are excluded — the FSM's owner
	// index only tracks materialized placements.
	OwnerNodeID string `json:"owner_node_id,omitempty"`
}

type PlacementPageResponse struct {
	Placements    []Placement `json:"placements"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	// Authoritative is true when the page was produced by a ready FSM / control
	// plane. Empty Authoritative pages mean "tenant (or fleet) has zero rows"
	// — not "placement view unavailable". Agents set this false on CP errors.
	Authoritative bool `json:"authoritative,omitempty"`
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
	// RingVersion identifies the membership view this answer was computed
	// from. Route installation and route lookup hash the same ordered set of
	// ingress node IDs, so two nodes that disagree about membership hand out
	// routes for different rings — the upstream can be pointed at a node that
	// never installed the shard. Publishing the version makes that divergence
	// observable (compare across ingress nodes) instead of silent.
	RingVersion string `json:"ring_version,omitempty"`
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
		OwnerRef:    strings.TrimSpace(r.OwnerRef),
		OwnerNodeID: strings.TrimSpace(r.OwnerNodeID),
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

// IngressShardFilterForNode returns the placement shard subset a single
// ingress-capable node should reconcile. Small ingress tiers replicate the full
// public route table to each ingress node so ordinary DNS round-robin / TCP
// load balancers work for every sandbox. Very large ingress tiers shard the
// table and require a shard-aware upstream router.
func IngressShardFilterForNode(members []Member, nodeID string) PlacementShardFilter {
	return ingressShardFilterForIDs(ingressShardNodeIDs(members), nodeID)
}

// IngressShardFilterCache retains only the last topology for one reconciler.
// Capacity heartbeats and endpoint changes do not change HRW ownership. Compare
// the sorted live ingress IDs, not the entire membership (or a lossy hash).
type IngressShardFilterCache struct {
	mu     sync.Mutex
	nodeID string
	ids    []string
	filter PlacementShardFilter
}

func (c *IngressShardFilterCache) ForNode(members []Member, nodeID string) PlacementShardFilter {
	ids := ingressShardNodeIDs(members)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodeID != nodeID || !slices.Equal(c.ids, ids) {
		c.nodeID, c.ids = nodeID, slices.Clone(ids)
		c.filter = ingressShardFilterForIDs(ids, nodeID)
	}
	filter := c.filter
	filter.Shards = slices.Clone(filter.Shards)
	return filter
}

func ingressShardFilterForIDs(ids []string, nodeID string) PlacementShardFilter {
	if nodeID == "" {
		return PlacementShardFilter{}
	}
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
	if len(ids) <= MaxReplicatedIngressRouteNodes {
		return PlacementShardFilter{}
	}

	shards := make([]int, 0, 2*DefaultPlacementShardCount/len(ids)+1)
	for shard := 0; shard < DefaultPlacementShardCount; shard++ {
		primary, backup := rendezvousIngressTopTwo(shard, ids)
		if primary == selfIndex || backup == selfIndex {
			shards = append(shards, shard)
		}
	}
	return PlacementShardFilter{
		ShardCount: DefaultPlacementShardCount,
		Shards:     shards,
	}
}

// IngressRouteForSandbox returns the ingress owner set an upstream router
// should target for sandboxID. Small ingress tiers all own every sandbox route;
// very large ingress tiers return the primary shard owner plus one failover
// replica so a single ingress death does not create a traffic vacuum.
// IngressRingMembers is the single membership view the shard-aware ingress
// path may hash. Reconciliation (which shards this node installs) and the
// route lookup (which node the upstream is sent to) must agree: an Agent's
// Members() is a control-plane snapshot while LocalMembers() is local gossip,
// and hashing one on the install side and the other on the lookup side routes
// traffic to nodes that never installed the shard. Local gossip is the
// preferred source — it is what the installer can act on — with the
// control-plane view as the fallback for a node whose gossip is not up yet.
func IngressRingMembers(c Client) []Member {
	if c == nil {
		return nil
	}
	if members := c.LocalMembers(); len(members) > 0 {
		return members
	}
	return c.Members()
}

// IngressRingVersion fingerprints the ordered set of ingress-eligible node IDs
// a ring was computed from. Equal versions mean two nodes will compute the
// same owners for every sandbox; different versions mean they are mid-
// convergence and their answers may disagree.
func IngressRingVersion(members []Member) string {
	ids := ingressShardNodeIDs(members)
	if len(ids) == 0 {
		return ""
	}
	sorted := slices.Clone(ids)
	sort.Strings(sorted)
	h := sha256.New()
	for _, id := range sorted {
		_, _ = h.Write([]byte(id))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func IngressRouteForSandbox(members []Member, sandboxID string) IngressShardRoute {
	shardCount := DefaultPlacementShardCount
	shard := PlacementShardForSandbox(sandboxID, shardCount)
	owners := ingressRouteOwners(members)
	route := IngressShardRoute{
		SandboxID:   sandboxID,
		Shard:       shard,
		ShardCount:  shardCount,
		Owners:      []IngressRouteOwner{},
		RingVersion: IngressRingVersion(members),
	}
	if len(owners) == 0 {
		return route
	}
	if len(owners) <= MaxReplicatedIngressRouteNodes {
		route.Owners = owners
		return route
	}
	ids := ingressShardNodeIDs(members)
	for _, idx := range rendezvousIngressOwnerIndexes(shard, ids, 2) {
		if idx >= 0 && idx < len(owners) {
			route.Owners = append(route.Owners, owners[idx])
		}
	}
	return route
}

// rendezvousIngressOwnerIndex picks a stable shard owner via highest-random-weight
// hashing so membership N→N-1 remaps ~1/N shards instead of ~99%.
func rendezvousIngressOwnerIndex(shard int, nodeIDs []string) int {
	idxs := rendezvousIngressOwnerIndexes(shard, nodeIDs, 1)
	if len(idxs) == 0 {
		return -1
	}
	return idxs[0]
}

// rendezvousIngressOwnerIndexes returns up to n distinct HRW owners for shard.
func rendezvousIngressOwnerIndexes(shard int, nodeIDs []string, n int) []int {
	if len(nodeIDs) == 0 || n <= 0 {
		return nil
	}
	if n <= 2 {
		first, second := rendezvousIngressTopTwo(shard, nodeIDs)
		if n == 1 || second < 0 {
			return []int{first}
		}
		return []int{first, second}
	}
	type scored struct {
		idx   int
		score uint64
		id    string
	}
	all := make([]scored, 0, len(nodeIDs))
	for i, id := range nodeIDs {
		all = append(all, scored{idx: i, score: rendezvousScore(shard, id), id: id})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].score == all[j].score {
			return all[i].id < all[j].id
		}
		return all[i].score > all[j].score
	})
	if n > len(all) {
		n = len(all)
	}
	out := make([]int, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, all[i].idx)
	}
	return out
}

// The routing contract uses at most two winners. Keep the same hash and lexical
// tie-break as the full ordering, without allocating/sorting N scored entries.
func rendezvousIngressTopTwo(shard int, ids []string) (first, second int) {
	first, second = -1, -1
	var firstScore, secondScore uint64
	for i, id := range ids {
		score := rendezvousScore(shard, id)
		if first < 0 || score > firstScore || (score == firstScore && id < ids[first]) {
			second, secondScore = first, firstScore
			first, firstScore = i, score
		} else if second < 0 || score > secondScore || (score == secondScore && id < ids[second]) {
			second, secondScore = i, score
		}
	}
	return first, second
}

func rendezvousScore(shard int, nodeID string) uint64 {
	// SHA-256 avoids FNV clustering on sequential node IDs (ing-00..ing-N)
	// which left some owners with zero shards under naive FNV-HRW.
	// Preserve the wire-compatible decimal-shard/NUL/node input. A stack
	// buffer eliminates fmt's per-candidate allocations for normal node IDs.
	var buf [256]byte
	input := strconv.AppendInt(buf[:0], int64(shard), 10)
	input = append(input, 0)
	input = append(input, nodeID...)
	sum := sha256.Sum256(input)
	return binary.BigEndian.Uint64(sum[:8])
}

func ingressShardNodeIDs(members []Member) []string {
	count := 0
	for _, m := range members {
		if m.NodeID != "" && m.Alive && CanServeIngressRole(m.Role) {
			count++
		}
	}
	seen := make(map[string]struct{}, count)
	ids := make([]string, 0, count)
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
