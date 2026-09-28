package clusterlist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

type membersOnlyCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *membersOnlyCluster) Members() []cluster.Member { return c.members }

// Embed the Client interface so LookupMember is not promoted from *Noop.
// Embed the Client interface so LookupMember is not promoted from *Noop.
type noLookupCluster struct{ cluster.Client }

func TestSelectPeersForPageLimitAndMissingOwners(t *testing.T) {
	if peers, _, _, ready, _ := SelectPeersForPage(nil, "", "", 0); peers != nil || ready {
		t.Fatalf("nil cluster = peers=%v ready=%v", peers, ready)
	}

	c := &stubListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		placements: []cluster.Placement{
			{SandboxID: "sb-1", OwnerNodeID: "self"},
			{SandboxID: "sb-2", OwnerNodeID: "dead"},
			{SandboxID: "sb-3", OwnerNodeID: "no-url"},
			{SandboxID: "sb-4", OwnerNodeID: "ingress"},
			{SandboxID: "sb-5", OwnerNodeID: "ok"},
		},
		byID: map[string]cluster.Member{
			"dead":    {NodeID: "dead", Alive: false, Role: config.NodeRoleWorker, InternalURL: "https://dead"},
			"no-url":  {NodeID: "no-url", Alive: true, Role: config.NodeRoleWorker},
			"ingress": {NodeID: "ingress", Alive: true, Role: config.NodeRoleIngress, InternalURL: "https://ing"},
			"ok":      {NodeID: "ok", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://ok"},
		},
	}
	peers, placements, _, ready, missing := SelectPeersForPage(c, "", "", MaxPageLimit+10)
	if !ready || len(placements) != 5 || len(peers) != 1 || peers[0].NodeID != "ok" {
		t.Fatalf("peers=%+v placements=%d ready=%v missing=%v", peers, len(placements), ready, missing)
	}
	if len(missing) != 3 {
		t.Fatalf("missing = %v, want dead/no-url/ingress", missing)
	}

	// Cold-start small fleet: skip self / empty role owners without InternalURL.
	small := &stubListCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		members: []cluster.Member{
			{NodeID: "self", Alive: true, Role: config.NodeRoleMixed},
			{NodeID: "peer", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://peer"},
			{NodeID: "nourl", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://x"},
			{NodeID: "dead", Alive: false, Role: config.NodeRoleWorker, InternalURL: "https://d"},
			{NodeID: "ing", Alive: true, Role: config.NodeRoleIngress, InternalURL: "https://i"},
		},
	}
	peers, _, _, ready, _ = SelectPeersForPage(small, "", "", 0)
	if !ready || len(peers) != 1 || peers[0].NodeID != "peer" {
		t.Fatalf("small fleet peers=%+v ready=%v", peers, ready)
	}

	// Embed Client as the interface so LookupMember is not promoted.
	lookup := memberLookupFn(&noLookupCluster{
		Client: &membersOnlyCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "peer", Alive: true},
				{NodeID: ""},
			},
		},
	})
	if m, ok := lookup("peer"); !ok || m.NodeID != "peer" {
		t.Fatalf("fallback lookup = %+v %v", m, ok)
	}
	if _, ok := lookup("missing"); ok {
		t.Fatal("fallback lookup found missing peer")
	}
}

func TestFilterLocalMergeAndFetchGaps(t *testing.T) {
	local := []*models.Sandbox{nil, {ID: "sb-keep"}, {ID: "sb-drop"}}
	got := FilterLocalToPage(local, []cluster.Placement{{SandboxID: "sb-keep"}, {SandboxID: "  "}}, "")
	if len(got) != 1 || got[0].ID != "sb-keep" {
		t.Fatalf("filter = %+v", got)
	}

	if !wantIDOK(nil, "any") || wantIDOK(map[string]struct{}{"a": {}}, "b") {
		t.Fatal("wantIDOK mismatch")
	}
	if q := wantIDsQuery(nil); q != "" {
		t.Fatalf("empty want query = %q", q)
	}
	if q := wantIDsQuery(map[string]struct{}{"": {}}); q != "" {
		t.Fatalf("blank id query = %q", q)
	}

	res := Merge(context.Background(), nil, Options{Local: []*models.Sandbox{nil, {ID: "local"}}})
	if len(res.Sandboxes) != 1 || res.Sandboxes[0].ID != "local" {
		t.Fatalf("local merge = %+v", res.Sandboxes)
	}

	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "keep=1") && strings.Contains(r.URL.RawQuery, "ids=") {
			_ = json.NewEncoder(w).Encode([]*models.Sandbox{{ID: "from-peer"}, {ID: "local"}, nil})
			return
		}
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	t.Cleanup(peer.Close)
	member := cluster.Member{NodeID: "p1", Alive: true, InternalURL: peer.URL, Role: config.NodeRoleWorker}
	warned := 0
	merged := Merge(context.Background(), []cluster.Member{member}, Options{
		Local:      []*models.Sandbox{{ID: "local"}},
		RawQuery:   "keep=1",
		WantIDs:    map[string]struct{}{"local": {}, "from-peer": {}},
		AuthHeader: "Bearer t",
		SelfNodeID: "self",
		Transport:  Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }},
		Warn:       func(string, string, error) { warned++ },
	})
	if len(merged.Sandboxes) != 2 {
		t.Fatalf("merged = %+v", idsOf(merged.Sandboxes))
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	partial := Merge(cancelled, []cluster.Member{member}, Options{
		Transport: Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }},
		Path:      "/v1/sandboxes",
		Warn:      func(string, string, error) { warned++ },
	})
	if !partial.Coverage.Partial {
		t.Fatal("cancelled merge must be partial")
	}

	huge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, io.LimitReader(neverEnding{}, 8<<20+64))
	}))
	t.Cleanup(huge.Close)
	if _, err := fetchPeerJSON(context.Background(), cluster.Member{NodeID: "h", Alive: true, InternalURL: huge.URL}, "/v1/sandboxes", "X-Cluster-Forwarded", "1", Options{
		Transport: Transport{InternalClient: huge.Client(), PeerClient: func(string) *http.Client { return huge.Client() }},
	}); err == nil || !strings.Contains(err.Error(), "8MiB") {
		t.Fatalf("oversize body = %v", err)
	}

	if c := withTimeout(nil); c == nil || c.Timeout != PeerTimeout {
		t.Fatalf("nil timeout client = %+v", c)
	}
	slow := &http.Client{Timeout: 30 * time.Second}
	if c := withTimeout(slow); c.Timeout != PeerTimeout {
		t.Fatalf("clamped timeout = %v", c.Timeout)
	}
	fast := &http.Client{Timeout: time.Second}
	if c := withTimeout(fast); c != fast {
		t.Fatal("fast client should be reused")
	}

	items, cov := MergeJSON(context.Background(), nil, []string{"a"}, func(s string) string { return s }, Options{WantIDs: map[string]struct{}{"b": {}}})
	if len(items) != 0 || !cov.PlacementViewReady {
		t.Fatalf("filtered local json = %+v %+v", items, cov)
	}
	_ = warned
}

func idsOf(sbs []*models.Sandbox) []string {
	out := make([]string, 0, len(sbs))
	for _, sb := range sbs {
		if sb != nil {
			out = append(out, sb.ID)
		}
	}
	return out
}

type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
