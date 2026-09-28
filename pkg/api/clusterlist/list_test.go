package clusterlist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

type stubListCluster struct {
	*cluster.Noop
	members       []cluster.Member
	placements    []cluster.Placement
	byID          map[string]cluster.Member
	authoritative bool
}

func (c *stubListCluster) Members() []cluster.Member { return c.members }
func (c *stubListCluster) Placements() []cluster.Placement {
	return append([]cluster.Placement(nil), c.placements...)
}
func (c *stubListCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	byID := make(map[string]cluster.Placement, len(c.placements))
	for _, p := range c.placements {
		byID[p.SandboxID] = p
	}
	for _, id := range ids {
		if p, ok := byID[id]; ok {
			out[id] = p
		}
	}
	return out
}
func (c *stubListCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	out := make([]cluster.Placement, 0, limit)
	for _, p := range c.placements {
		if req.OwnerRef != "" && p.OwnerRef != req.OwnerRef {
			continue
		}
		out = append(out, p)
		if len(out) >= limit {
			break
		}
	}
	return cluster.PlacementPageResponse{Placements: out, Authoritative: c.authoritative}
}
func (c *stubListCluster) LookupMember(id string) (cluster.Member, bool) {
	if c.byID != nil {
		m, ok := c.byID[id]
		return m, ok
	}
	for _, m := range c.members {
		if m.NodeID == id {
			return m, true
		}
	}
	return cluster.Member{}, false
}
func (c *stubListCluster) PeerInternalHTTPClient() *http.Client { return http.DefaultClient }

func TestSelectPeersUsesPlacementOwnersNotFullMembership(t *testing.T) {
	members := make([]cluster.Member, 0, 300)
	members = append(members, cluster.Member{
		NodeID: "self", APIURL: "http://self", Alive: true, Role: config.NodeRoleMixed,
	})
	for i := 0; i < 300; i++ {
		members = append(members, cluster.Member{
			NodeID:      fmt.Sprintf("w-%03d", i),
			APIURL:      fmt.Sprintf("http://w-%03d", i),
			InternalURL: fmt.Sprintf("https://w-%03d.internal", i),
			Alive:       true,
			Role:        config.NodeRoleWorker,
		})
	}
	members[1].NodeID = "owner-a"
	members[1].APIURL = "http://owner-a"
	members[1].InternalURL = "https://owner-a.internal"
	members[2].NodeID = "owner-b"
	members[2].APIURL = "http://owner-b"
	members[2].InternalURL = "https://owner-b.internal"

	c := &stubListCluster{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		members: members,
		placements: []cluster.Placement{
			{SandboxID: "sb-1", OwnerNodeID: "owner-a", OwnerRef: "tenant-1"},
			{SandboxID: "sb-2", OwnerNodeID: "owner-b", OwnerRef: "tenant-1"},
			{SandboxID: "sb-3", OwnerNodeID: "owner-a", OwnerRef: "tenant-2"},
		},
	}
	peers, _, _, ready, missing := SelectPeersForPage(c, "tenant-1", "", DefaultPageLimit)
	if !ready {
		t.Fatal("expected placement view ready")
	}
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none", missing)
	}
	if len(peers) != 2 {
		t.Fatalf("SelectPeersForPage(tenant-1) = %d peers, want 2", len(peers))
	}
	got := map[string]bool{}
	for _, p := range peers {
		got[p.NodeID] = true
	}
	if !got["owner-a"] || !got["owner-b"] {
		t.Fatalf("peers = %+v, want owner-a and owner-b", peers)
	}

	c.placements = nil
	peers, _, _, ready, _ = SelectPeersForPage(c, "", "", DefaultPageLimit)
	if ready {
		t.Fatal("empty placements at large membership must mark view not ready")
	}
	if peers != nil {
		t.Fatalf("empty placements at large membership: got %d peers, want nil", len(peers))
	}
}

func TestSelectPeersAuthoritativeEmptyTenantReady(t *testing.T) {
	members := make([]cluster.Member, 0, 300)
	members = append(members, cluster.Member{
		NodeID: "self", APIURL: "http://self", Alive: true, Role: config.NodeRoleMixed,
	})
	for i := 0; i < 300; i++ {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("w-%03d", i),
			APIURL: fmt.Sprintf("http://w-%03d", i),
			Alive:  true,
			Role:   config.NodeRoleWorker,
		})
	}
	c := &stubListCluster{
		Noop:       cluster.NewNoop("self", "http://self", ""),
		members:    members,
		placements: nil,
	}
	c.authoritative = true
	peers, placements, _, ready, _ := SelectPeersForPage(c, "empty-tenant", "", DefaultPageLimit)
	if !ready {
		t.Fatal("authoritative empty tenant must be viewReady=true")
	}
	if peers != nil {
		t.Fatalf("peers = %v, want nil", peers)
	}
	if placements == nil || len(placements) != 0 {
		t.Fatalf("placements = %v, want non-nil empty", placements)
	}
	want := PlacementWantIDs(placements)
	if want == nil {
		t.Fatal("WantIDs for authoritative empty must be non-nil empty map")
	}
	if wantIDOK(want, "any") {
		t.Fatal("empty WantIDs must deny all IDs")
	}
}

func TestDialPeerRequiresInternalURLAndClient(t *testing.T) {
	tr := Transport{
		InternalClient: http.DefaultClient,
	}
	client, base, err := dialPeer(cluster.Member{
		NodeID:      "n1",
		APIURL:      "http://public",
		InternalURL: "https://internal",
		Alive:       true,
	}, tr)
	if err != nil || client == nil || base != "https://internal" {
		t.Fatalf("dialPeer = %v %q %v, want internal mTLS", client != nil, base, err)
	}

	// Public-only peers must fail closed (no advertise-URL fallback).
	_, _, err = dialPeer(cluster.Member{
		NodeID: "n2",
		APIURL: "http://public-only",
		Alive:  true,
	}, tr)
	if err == nil {
		t.Fatal("dialPeer without InternalURL: want error")
	}

	_, _, err = dialPeer(cluster.Member{
		NodeID:      "n3",
		APIURL:      "http://public",
		InternalURL: "https://internal",
		Alive:       true,
	}, Transport{})
	if err == nil {
		t.Fatal("dialPeer without InternalClient: want error")
	}
}

func TestFilterLocalToPageTerminalEmptyPage(t *testing.T) {
	local := []*models.Sandbox{{ID: "sb-1"}, {ID: "sb-2"}}
	if got := FilterLocalToPage(local, nil, ""); len(got) != 2 {
		t.Fatalf("cold start empty placements: got %d, want all local", len(got))
	}
	if got := FilterLocalToPage(local, nil, "sb-last"); len(got) != 0 {
		t.Fatalf("terminal empty page with pageToken: got %d, want 0", len(got))
	}
	if got := FilterLocalToPage(local, []cluster.Placement{}, ""); len(got) != 0 {
		t.Fatalf("authoritative empty page: got %d, want 0", len(got))
	}
	page := []cluster.Placement{{SandboxID: "sb-2"}}
	got := FilterLocalToPage(local, page, "")
	if len(got) != 1 || got[0].ID != "sb-2" {
		t.Fatalf("filter to page = %+v, want [sb-2]", got)
	}
}

func TestMergeFiltersPeerRowsToWantIDs(t *testing.T) {
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]*models.Sandbox{
			{ID: "sb-on-page"},
			{ID: "sb-off-page"},
		})
	}))
	t.Cleanup(peer.Close)

	res := Merge(context.Background(), []cluster.Member{{
		NodeID: "peer-1", Alive: true, InternalURL: peer.URL, Role: config.NodeRoleWorker,
	}}, Options{
		Local:     []*models.Sandbox{{ID: "sb-local-off"}},
		WantIDs:   map[string]struct{}{"sb-on-page": {}},
		Transport: Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }},
		Path:      "/v1/sandboxes",
	})
	if len(res.Sandboxes) != 1 || res.Sandboxes[0].ID != "sb-on-page" {
		t.Fatalf("Merge WantIDs filter = %+v, want [sb-on-page]", res.Sandboxes)
	}
}

func TestWriteCoverageHeadersMarksPartial(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteCoverageHeaders(rec, Coverage{
		Partial:            true,
		PlacementViewReady: false,
		Missing:            []string{"w-1"},
		Answered:           []string{"local"},
	}, "tok")
	if rec.Header().Get(HeaderPartial) != "true" {
		t.Fatalf("partial header = %q", rec.Header().Get(HeaderPartial))
	}
	if rec.Header().Get(HeaderPlacementReady) != "false" {
		t.Fatalf("ready header = %q", rec.Header().Get(HeaderPlacementReady))
	}
	if rec.Header().Get(HeaderNextPageToken) != "tok" {
		t.Fatalf("next token = %q", rec.Header().Get(HeaderNextPageToken))
	}
}

type transportListCluster struct{ *stubListCluster }

func (c *transportListCluster) ClientForPeer(string) *http.Client { return http.DefaultClient }

func TestTransportOwnerContextAndSelectPeersHelpers(t *testing.T) {
	if got := TransportFromCluster(nil); got.InternalClient != nil || got.PeerClient != nil {
		t.Fatalf("nil transport = %+v", got)
	}
	base := &stubListCluster{
		Noop:          cluster.NewNoop("self", "http://self", ""),
		authoritative: true,
		placements:    []cluster.Placement{{SandboxID: "sb", OwnerNodeID: "peer", OwnerRef: "tenant"}},
		byID: map[string]cluster.Member{
			"peer": {NodeID: "peer", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://peer.internal"},
		},
	}
	tr := TransportFromCluster(&transportListCluster{stubListCluster: base})
	if tr.InternalClient == nil || tr.PeerClient == nil || tr.PeerClient("peer") == nil {
		t.Fatalf("transport = %+v", tr)
	}
	peers := SelectPeers(base, "tenant")
	if len(peers) != 1 || peers[0].NodeID != "peer" {
		t.Fatalf("SelectPeers = %+v", peers)
	}
	if _, ok := memberLookupFn(nil)("peer"); ok {
		t.Fatal("nil member lookup unexpectedly found peer")
	}

	if got := OwnerRefFromContext(context.Background()); got != "" {
		t.Fatalf("unscoped owner = %q", got)
	}
	operator := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true})
	if got := OwnerRefFromContext(operator); got != "" {
		t.Fatalf("operator owner = %q", got)
	}
	tenant := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: " tenant "}})
	if got := OwnerRefFromContext(tenant); got != "tenant" {
		t.Fatalf("tenant owner = %q", got)
	}
}

func TestMergeJSONSuccessDedupFilterAndErrors(t *testing.T) {
	type item struct {
		ID string `json:"id"`
	}
	var sawHeaders bool
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") == "1" && r.Header.Get("Authorization") == "Bearer tenant" && r.Header.Get(cluster.PeerNodeIDHeader) == "self" {
			sawHeaders = true
		}
		switch r.URL.Path {
		case "/good":
			if got := r.URL.Query().Get("ids"); got != "local,peer" {
				t.Fatalf("ids query = %q", got)
			}
			_ = json.NewEncoder(w).Encode([]item{{ID: "local"}, {ID: "peer"}, {ID: "off-page"}})
		case "/bad-json":
			_, _ = w.Write([]byte("{"))
		case "/failure":
			http.Error(w, "peer failed", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)
	member := cluster.Member{NodeID: "peer-1", Alive: true, InternalURL: peer.URL, Role: config.NodeRoleWorker}
	transport := Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }}
	opts := Options{
		Path:       "/good",
		AuthHeader: "Bearer tenant",
		SelfNodeID: "self",
		WantIDs:    map[string]struct{}{"local": {}, "peer": {}},
		Transport:  transport,
	}
	items, cov := MergeJSON(context.Background(), []cluster.Member{member}, []item{{ID: "local"}}, func(v item) string { return v.ID }, opts)
	if !sawHeaders || cov.Partial || len(cov.Answered) != 2 || len(items) != 2 || items[0].ID != "local" || items[1].ID != "peer" {
		t.Fatalf("items=%+v coverage=%+v sawHeaders=%v", items, cov, sawHeaders)
	}

	for _, path := range []string{"/bad-json", "/failure"} {
		warned := false
		opts.Path = path
		opts.Warn = func(string, string, error) { warned = true }
		_, cov = MergeJSON(context.Background(), []cluster.Member{member}, nil, func(v item) string { return v.ID }, opts)
		if !cov.Partial || len(cov.Missing) != 1 || !warned {
			t.Fatalf("path=%s coverage=%+v warned=%v", path, cov, warned)
		}
	}
	items, cov = MergeJSON(context.Background(), nil, []item{{ID: ""}}, nil, Options{})
	if len(items) != 1 || cov.Partial {
		t.Fatalf("local-only items=%+v coverage=%+v", items, cov)
	}
}

func TestPaginationAndCoverageHeaderHelpers(t *testing.T) {
	if got := StripFacadePagination(""); got != "" {
		t.Fatalf("empty stripped query = %q", got)
	}
	raw := "page=2&limit=20&nextToken=n&offset=5&ids=a%2Cb&keep=value"
	if got := StripFacadePagination(raw); got != "keep=value" {
		t.Fatalf("stripped query = %q", got)
	}
	malformed := "%zz"
	if got := StripFacadePagination(malformed); got != malformed {
		t.Fatalf("malformed query = %q", got)
	}

	if limit, token := ParsePageParams(nil); limit != DefaultPageLimit || token != "" {
		t.Fatalf("nil params = %d %q", limit, token)
	}
	u, _ := url.Parse("https://example.test?limit=9999&pageToken=tok")
	if limit, token := ParsePageParams(u); limit != MaxPageLimit || token != "tok" {
		t.Fatalf("capped params = %d %q", limit, token)
	}
	u, _ = url.Parse("https://example.test?limit=bad&page_token=%20primary%20&pageToken=fallback")
	if limit, token := ParsePageParams(u); limit != DefaultPageLimit || strings.TrimSpace(token) != "primary" {
		t.Fatalf("default params = %d %q", limit, token)
	}
	WriteCoverageHeaders(nil, Coverage{}, "")
}

func TestPeerWantIDsRequiresForwardedHopAndBoundsInput(t *testing.T) {
	public := httptest.NewRequest(http.MethodGet, "/sandboxes?ids=sb-a,sb-b", nil)
	if got, err := PeerWantIDs(public); err != nil || got != nil {
		t.Fatalf("public PeerWantIDs = %#v, %v; want nil, nil", got, err)
	}

	forwarded := httptest.NewRequest(http.MethodGet, "/sandboxes?ids=sb-a,sb-b&ids=sb-b,sb-c", nil)
	forwarded.Header.Set("X-Cluster-Forwarded", "1")
	got, err := PeerWantIDs(forwarded)
	if err != nil {
		t.Fatalf("PeerWantIDs() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("PeerWantIDs() = %#v, want three deduplicated IDs", got)
	}
	for _, id := range []string{"sb-a", "sb-b", "sb-c"} {
		if _, ok := got[id]; !ok {
			t.Fatalf("PeerWantIDs() missing %q: %#v", id, got)
		}
	}

	empty := httptest.NewRequest(http.MethodGet, "/sandboxes?ids=", nil)
	empty.Header.Set("X-Cluster-Forwarded", "1")
	got, err = PeerWantIDs(empty)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty PeerWantIDs = %#v, %v; want non-nil empty set", got, err)
	}

	tooMany := httptest.NewRequest(http.MethodGet, "/sandboxes", nil)
	tooMany.Header.Set("X-Cluster-Forwarded", "1")
	q := tooMany.URL.Query()
	ids := make([]string, MaxPageLimit+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("sb-%d", i)
	}
	q.Set("ids", strings.Join(ids, ","))
	tooMany.URL.RawQuery = q.Encode()
	if _, err := PeerWantIDs(tooMany); err == nil {
		t.Fatal("PeerWantIDs() accepted more than MaxPageLimit IDs")
	}
}
