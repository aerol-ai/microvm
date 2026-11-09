package cluster

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/hashicorp/memberlist"
)

// gossipPeerCacheFile lives in the raft data directory on purpose: the cache
// and the raft state share one lifetime. An operator who wipes the raft dir to
// re-initialise a node also forgets the old peers, so a fresh `cluster-init`
// can never be dragged back into the cluster it was meant to leave.
const gossipPeerCacheFile = "gossip-peers.json"

// gossipMemberCacheFile remembers a few members that are not control-plane
// (workers, ingress), beside gossipPeerCacheFile and for the same lifetime.
// It is a separate file, not more entries in gossip-peers.json, so that file
// keeps meaning "control-plane peers": a node that loses every server must
// never overwrite its way back to them with workers, and an older binary
// reading gossip-peers.json after a downgrade finds the format it wrote.
const gossipMemberCacheFile = "gossip-members.json"

// maxCachedMemberPeers is how many non-control-plane members a node
// remembers. Any one that is still up hands a restarted node the whole
// membership in a single push/pull, so a few are enough; the rest only
// survive the case where those few went down too.
const maxCachedMemberPeers = 3

// maxCachedGossipPeers bounds the rejoin fan-out. memberlist.Join dials the
// list serially and an address whose host is gone costs a full TCP timeout,
// so a long stale list turns one rejoin attempt into minutes. Control-plane
// peers are the only useful rejoin targets and the server tier is capped at
// MaxServerTierNodes, so a handful is enough to reach the cluster.
const maxCachedGossipPeers = 8

// gossipPeerCache remembers the gossip addresses of the control-plane peers
// this node last saw alive, so a restart can find the cluster again without an
// operator-supplied peer list.
//
// Why it exists: the seed is started with SB_CLUSTER_BOOTSTRAP=true and no
// SB_CLUSTER_PEERS — the joiners dial it, never the reverse. memberlist keeps
// no state across a restart, so a restarted seed came back as a gossip island.
// The survivors had already elected a leader and, after the dead-owner grace,
// evicted the seed from the raft configuration; the leader only re-admits a
// server it can see in gossip, so the seed stayed a lone raft candidate
// forever (live S2 run, 2026-09-26: "rejecting pre-vote request since node is
// not in configuration" on the new leader, every ~1.5s, until teardown). The
// same hole strands a joiner whose only configured peer has been replaced.
type gossipPeerCache struct {
	path string

	mu   sync.Mutex
	last []string
}

func newGossipPeerCache(dir string) *gossipPeerCache {
	if dir == "" {
		return nil
	}
	return &gossipPeerCache{path: filepath.Join(dir, gossipPeerCacheFile)}
}

// newGossipMemberCache is the cache for gossipMemberCacheFile. It shares the
// type, and so the write-only-on-change and never-write-empty rules.
func newGossipMemberCache(dir string) *gossipPeerCache {
	if dir == "" {
		return nil
	}
	return &gossipPeerCache{path: filepath.Join(dir, gossipMemberCacheFile)}
}

// snapshot returns a copy of the remembered list.
func (c *gossipPeerCache) snapshot() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.last...)
}

// load returns the remembered peers. A missing or unreadable cache is not an
// error: it only means this node has nothing to add to the configured peers.
func (c *gossipPeerCache) load() []string {
	if c == nil {
		return nil
	}
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return nil
	}
	var peers []string
	if err := json.Unmarshal(raw, &peers); err != nil {
		return nil
	}
	peers = normalizeGossipPeers(peers)
	c.mu.Lock()
	c.last = peers
	c.mu.Unlock()
	return peers
}

// remember persists peers when they differ from what is already on disk.
//
// An empty set is never written. The moment this node is alone is exactly the
// moment it needs the old list, so an isolated node must not overwrite its
// only way back with "nobody".
func (c *gossipPeerCache) remember(peers []string) error {
	if c == nil {
		return nil
	}
	peers = normalizeGossipPeers(peers)
	if len(peers) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if slices.Equal(peers, c.last) {
		return nil
	}
	raw, err := json.Marshal(peers)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write leaves the previous list, not a
	// truncated file that load would discard.
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	c.last = peers
	return nil
}

// liveControlPlanePeerAddrs extracts the gossip addresses worth remembering:
// alive peers that can serve the control plane. Workers and ingress nodes are
// left out — they cannot re-admit anyone to raft, and at fleet scale they
// would crowd the servers out of the bounded list.
func liveControlPlanePeerAddrs(nodes []*memberlist.Node, selfNodeID string) []string {
	controlPlane, _ := livePeerAddrsByRole(nodes, selfNodeID)
	return controlPlane
}

// livePeerAddrsByRole splits the alive peers' gossip addresses into those
// that can serve the control plane and the rest, in one pass: the refresh
// loop runs it every tick, and decoding every member's metadata twice would
// double that cost at fleet size.
func livePeerAddrsByRole(nodes []*memberlist.Node, selfNodeID string) (controlPlane, others []string) {
	for _, n := range nodes {
		if n == nil || n.State != memberlist.StateAlive || len(n.Addr) == 0 {
			continue
		}
		m := memberFromMemberlistNode(n)
		if m.NodeID == "" || m.NodeID == selfNodeID || n.Name == selfNodeID {
			continue
		}
		if CanServeControlPlaneRole(m.Role) {
			controlPlane = append(controlPlane, n.Address())
		} else {
			others = append(others, n.Address())
		}
	}
	return controlPlane, others
}

// pickMemberPeers chooses up to maxCachedMemberPeers addresses from alive.
// Members already remembered (previous) are kept while they stay alive, and
// the rest are filled in address order, so the list, and the file behind it,
// changes only when a chosen member goes away, not on every tick.
func pickMemberPeers(alive, previous []string) []string {
	alive = slices.Clone(alive)
	slices.Sort(alive)
	alive = slices.Compact(alive)
	out := make([]string, 0, maxCachedMemberPeers)
	for _, a := range alive {
		if len(out) < maxCachedMemberPeers && slices.Contains(previous, a) {
			out = append(out, a)
		}
	}
	for _, a := range alive {
		if len(out) < maxCachedMemberPeers && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// normalizeGossipPeers sorts, de-duplicates and bounds a peer list so the
// on-disk form is stable and the change check in remember is a plain compare.
func normalizeGossipPeers(peers []string) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p != "" {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxCachedGossipPeers {
		out = out[:maxCachedGossipPeers]
	}
	return out
}

// mergeRejoinPeers is the list a rejoin dials: operator-configured peers
// first, so an explicit SB_CLUSTER_PEERS keeps priority, then remembered peers
// not already present. self is dropped — joining yourself "succeeds" and would
// report the island as rejoined.
func mergeRejoinPeers(configured, cached []string, self string) []string {
	out := make([]string, 0, len(configured)+len(cached))
	seen := make(map[string]bool, len(configured)+len(cached))
	for _, list := range [][]string{configured, cached} {
		for _, p := range list {
			if p == "" || p == self || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
