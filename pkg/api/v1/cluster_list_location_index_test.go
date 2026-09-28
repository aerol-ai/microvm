package v1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
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
	peers := clusterRuntimePeers(cl, "firecracker", clusterTemplateLocationIndex, have, nil)

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
	if all := clusterRuntimePeers(cl, "firecracker", nil, have, nil); len(all) != 503 {
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
	count := clusterRuntimeUnavailablePeerCount(cl, "firecracker", clusterTemplateLocationIndex, have, nil)
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

// A dedicated server or ingress holds no artifacts of its own, so the gossip
// location index cannot narrow anything: every worker advertising a template
// is a target, and at 2,000 workers that is 2,000 requests per uncached list.
// The replicated catalogue answers for every node that has published, leaving
// only the nodes whose inventory nobody knows.
func TestClusterListSweepAnswersFromTheReplicatedCatalogue(t *testing.T) {
	cl := &templateSweepCluster{Noop: cluster.NewNoop("entry", "http://entry", "")}
	publishers := make([]string, 0, 2000)
	for i := range 2000 {
		id := fmt.Sprintf("worker-%04d", i)
		m := templatePeer(id, true, fmt.Sprintf("template-%04d", i))
		m.Capacity.SupportedRuntimes = []string{models.RuntimeFirecracker, models.RuntimeIsolate}
		cl.members = append(cl.members, m)
		publishers = append(publishers, id)
	}
	published := make(map[string]struct{}, len(publishers))
	for _, id := range publishers {
		published[id] = struct{}{}
	}

	if peers := clusterRuntimePeers(cl, models.RuntimeFirecracker, clusterTemplateLocationIndex, map[string]struct{}{}, published); len(peers) != 0 {
		t.Fatalf("catalogue covers every worker but the sweep still targets %d of them", len(peers))
	}
	if peers := clusterRuntimePeers(cl, models.RuntimeIsolate, nil, map[string]struct{}{}, published); len(peers) != 0 {
		t.Fatalf("js-bundle sweep still targets %d workers; the tenant-scoped catalogue must narrow it too", len(peers))
	}
	if missing := clusterRuntimeUnavailablePeerCount(cl, models.RuntimeFirecracker, clusterTemplateLocationIndex, map[string]struct{}{}, published); missing != 0 {
		t.Fatalf("%d covered peers counted as missing coverage; their rows are in the answer", missing)
	}
}

// A node that has not published is never silently dropped: its rows can only
// come from asking it.
func TestClusterListSweepStillAsksUnpublishedPeers(t *testing.T) {
	cl := &templateSweepCluster{Noop: cluster.NewNoop("entry", "http://entry", "")}
	cl.members = append(cl.members,
		templatePeer("worker-published", true, "template-a"),
		templatePeer("worker-upgrading", true, "template-b"),
	)
	published := map[string]struct{}{"worker-published": {}}

	peers := clusterRuntimePeers(cl, models.RuntimeFirecracker, clusterTemplateLocationIndex, map[string]struct{}{}, published)
	if len(peers) != 1 || peers[0].NodeID != "worker-upgrading" {
		t.Fatalf("sweep targets = %+v, want only the node whose inventory nobody has published", peers)
	}
}

// The sweep must merge the catalogue's rows into the answer, dedupe them
// against local rows, and keep asking the peers the catalogue does not cover.
func TestClusterListSweepMergesCatalogueRows(t *testing.T) {
	cl := &templateSweepCluster{Noop: cluster.NewNoop("entry", "http://entry", "")}
	cl.members = append(cl.members,
		templatePeer("worker-published", true, "template-remote"),
		templatePeer("worker-unpublished", true, "template-unknown"),
	)
	catalog := func(*http.Request) ([]*models.Template, []string, bool) {
		return []*models.Template{{ID: "template-remote"}, {ID: "template-local"}}, []string{"worker-published"}, true
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	agg, err := clusterListSweep(req, cl, models.RuntimeFirecracker, clusterTemplateForwardedHeader,
		[]*models.Template{{ID: "template-local"}}, nil, templateListKey, nil, "templates",
		clusterTemplateLocationIndex, catalog)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	ids := make([]string, 0, len(agg.rows))
	for _, row := range agg.rows {
		ids = append(ids, row.ID)
	}
	sort.Strings(ids)
	if len(ids) != 2 || ids[0] != "template-local" || ids[1] != "template-remote" {
		t.Fatalf("rows = %v, want the local row plus the catalogue's, deduped", ids)
	}
	// worker-unpublished could not be reached in this test, so the answer is
	// honestly marked partial rather than claiming completeness.
	if agg.failedPeers == 0 {
		t.Fatal("an unreachable, unpublished peer must be reported as missing coverage")
	}
}
