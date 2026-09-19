package v1

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func templatePeer(id string, known bool, ids ...string) cluster.Member {
	return cluster.Member{
		NodeID:      id,
		Alive:       true,
		Role:        config.NodeRoleWorker,
		InternalURL: "https://" + id,
		Capacity: capacity.Snapshot{
			SupportedRuntimes:                  []string{"firecracker"},
			LocalTemplateCatalogInventoryKnown: known,
			LocalTemplateCatalogIDs:            ids,
		},
	}
}

type templateSweepCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *templateSweepCluster) Members() []cluster.Member {
	return append([]cluster.Member(nil), c.members...)
}
func (c *templateSweepCluster) LocalMembers() []cluster.Member { return c.Members() }

// The catalogue list merged every eligible runtime worker's complete answer.
// Capacity heartbeats already publish which templates each node owns, so the
// sweep can ask only the nodes that can add something.
func TestClusterRuntimePeersUsesTemplateLocationIndex(t *testing.T) {
	cl := &templateSweepCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	// A large fleet where almost nobody holds a template the caller lacks.
	for i := range 500 {
		cl.members = append(cl.members, templatePeer(fmt.Sprintf("wrk-%03d", i), true))
	}
	cl.members = append(cl.members,
		templatePeer("wrk-has-known", true, "tpl-local"),
		templatePeer("wrk-has-new", true, "tpl-remote"),
		templatePeer("wrk-legacy", false),
	)

	have := map[string]struct{}{"tpl-local": {}}
	peers := clusterRuntimePeers(cl, "firecracker", clusterTemplateLocationIndex, have)

	got := map[string]bool{}
	for _, p := range peers {
		got[p.NodeID] = true
	}
	if len(peers) != 2 {
		t.Fatalf("sweep asked %d peers of 503; want 2 (the one with an unseen template and the one with no published inventory): %v", len(peers), got)
	}
	if !got["wrk-has-new"] {
		t.Fatal("the peer holding a template the caller lacks was skipped; the list would be incomplete")
	}
	if !got["wrk-legacy"] {
		t.Fatal("a peer with no published inventory must still be asked — unknown is never treated as empty")
	}
	if got["wrk-has-known"] {
		t.Fatal("a peer whose only template the caller already has was asked; its rows are discarded by the dedupe anyway")
	}

	// Without an index, every eligible peer is asked, exactly as before.
	if all := clusterRuntimePeers(cl, "firecracker", nil, have); len(all) != 503 {
		t.Fatalf("index-less sweep asked %d peers, want all 503", len(all))
	}
}

// A peer that adds nothing is not missing coverage: counting it would mark a
// complete list partial.
func TestUnavailablePeerCountIgnoresPeersThatAddNothing(t *testing.T) {
	cl := &templateSweepCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	dead := templatePeer("wrk-dead-empty", true)
	dead.Alive = false
	deadWithRows := templatePeer("wrk-dead-rows", true, "tpl-remote")
	deadWithRows.Alive = false
	deadUnknown := templatePeer("wrk-dead-legacy", false)
	deadUnknown.Alive = false
	cl.members = []cluster.Member{dead, deadWithRows, deadUnknown}

	have := map[string]struct{}{"tpl-local": {}}
	count := clusterRuntimeUnavailablePeerCount(cl, "firecracker", clusterTemplateLocationIndex, have)
	if count != 2 {
		t.Fatalf("missing-coverage count = %d, want 2 (the dead peer with rows and the dead peer with no published inventory)", count)
	}
}

func TestClusterPeerCanContributeEdgeCases(t *testing.T) {
	have := map[string]struct{}{"tpl-a": {}}
	if !clusterPeerCanContribute(nil, templatePeer("x", true), have) {
		t.Fatal("a nil index must ask everyone")
	}
	if !clusterPeerCanContribute(clusterTemplateLocationIndex, templatePeer("x", false, "tpl-a"), have) {
		t.Fatal("an unpublished inventory must never be treated as authoritative")
	}
	if clusterPeerCanContribute(clusterTemplateLocationIndex, templatePeer("x", true, "tpl-a", "  "), have) {
		t.Fatal("blank ids must not count as a contribution")
	}
	if !clusterPeerCanContribute(clusterTemplateLocationIndex, templatePeer("x", true, "tpl-a", "tpl-b"), have) {
		t.Fatal("a peer holding one unseen id must be asked")
	}
}
