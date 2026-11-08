package cluster

import (
	"slices"
	"sync"

	"github.com/hashicorp/memberlist"
)

// gossipNodeTable is our own copy of every node memberlist currently knows
// (alive or suspect; dead and left nodes are removed), keyed by memberlist
// name.
//
// Why a copy: the *memberlist.Node pointers that ml.Members() and
// ml.LocalNode() return point into memberlist's live node table.
// memberlist.aliveNode rewrites Meta, Addr, Port and State on those structs
// under memberlist's private node lock, so any read of them after Members()
// returns is a data race (seen under -race in TestRestartedSeedRejoinsAfterEviction).
// memberlist calls its EventDelegate while holding that same lock, so a copy
// taken inside NotifyJoin / NotifyUpdate is consistent. Serf and Consul build
// their member view the same way.
//
// What the copy cannot see: memberlist sends no event when it starts to
// suspect a node, so a suspect node stays alive here until memberlist
// declares it dead (NotifyLeave), the same as in memberlist's own Members()
// and NumMembers(). Before this table, the 5 s rescan also turned a suspect
// node not-alive on its next tick.
type gossipNodeTable struct {
	mu    sync.RWMutex
	nodes map[string]memberlist.Node
}

func newGossipNodeTable() *gossipNodeTable {
	return &gossipNodeTable{nodes: make(map[string]memberlist.Node)}
}

// put stores a deep copy of n. Call it only from a memberlist event callback,
// where memberlist holds its node lock.
func (t *gossipNodeTable) put(n *memberlist.Node) {
	if t == nil || n == nil || n.Name == "" {
		return
	}
	c := *n
	c.Addr = slices.Clone(n.Addr)
	c.Meta = slices.Clone(n.Meta)
	t.mu.Lock()
	t.nodes[n.Name] = c
	t.mu.Unlock()
}

func (t *gossipNodeTable) remove(name string) {
	if t == nil || name == "" {
		return
	}
	t.mu.Lock()
	delete(t.nodes, name)
	t.mu.Unlock()
}

// snapshot returns fresh copies, so callers may keep or read them from any
// goroutine (maybeRejoinBootstrapPeers reads them from its own).
func (t *gossipNodeTable) snapshot() []*memberlist.Node {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*memberlist.Node, 0, len(t.nodes))
	for _, n := range t.nodes {
		c := n
		c.Addr = slices.Clone(n.Addr)
		c.Meta = slices.Clone(n.Meta)
		out = append(out, &c)
	}
	return out
}

// address returns name's gossip address ("host:port"), or "" when the table
// has no entry for it.
func (t *gossipNodeTable) address(name string) string {
	if t == nil {
		return ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	n, ok := t.nodes[name]
	if !ok {
		return ""
	}
	return n.Address()
}
