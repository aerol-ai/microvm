package clusterlist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

func forwardedReq(t *testing.T, forwarded bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if forwarded {
		r.Header.Set("X-Cluster-Forwarded", "1")
	}
	return r
}

// ListMode is the one definition the facades used to each copy: fan out only
// with a real cluster client and only when this is not a forwarded peer hop.
func TestListMode(t *testing.T) {
	stub := &stubListCluster{Noop: cluster.NewNoop("self", "", "")}
	cases := []struct {
		name string
		c    cluster.Client
		fwd  bool
		want bool
	}{
		{"nil client", nil, false, false},
		{"noop", cluster.NewNoop("self", "", ""), false, false},
		{"real", stub, false, true},
		{"real but forwarded", stub, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ListMode(tc.c, forwardedReq(t, tc.fwd)); got != tc.want {
				t.Fatalf("ListMode = %v, want %v", got, tc.want)
			}
		})
	}
}

// filterLocalToPage keeps only the local rows in the page's placement set; a nil
// placement set means "all local" at the first page, "none" past it.
func TestFilterLocalToPage(t *testing.T) {
	type item struct{ ID string }
	id := func(it item) string { return it.ID }
	local := []item{{ID: "sb-1"}, {ID: "sb-2"}, {ID: ""}}

	if got := filterLocalToPage(local, nil, "", id); len(got) != 3 {
		t.Fatalf("cold start = %d, want 3", len(got))
	}
	if got := filterLocalToPage(local, nil, "tok", id); got != nil {
		t.Fatalf("past the local page = %+v, want nil", got)
	}
	got := filterLocalToPage(local, []cluster.Placement{{SandboxID: "sb-2"}}, "", id)
	if len(got) != 1 || got[0].ID != "sb-2" {
		t.Fatalf("page filter = %+v, want [sb-2]", got)
	}
}

// FacadeListPage short-circuits to the local rows when there is no cluster or
// this is a forwarded peer hop.
func TestFacadeListPageShortCircuits(t *testing.T) {
	type item struct{ ID string }
	id := func(it item) string { return it.ID }
	local := []item{{ID: "a"}}

	for _, tc := range []struct {
		name string
		c    cluster.Client
		fwd  bool
	}{
		{"no cluster", nil, false},
		{"noop", cluster.NewNoop("self", "", ""), false},
		{"forwarded hop", &stubListCluster{Noop: cluster.NewNoop("self", "", "")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, cov, next, ok := FacadeListPage(forwardedReq(t, tc.fwd), tc.c, local, id, FacadeListOptions{Path: "/x"})
			if !ok || next != "" || len(items) != 1 || items[0].ID != "a" || cov.Partial {
				t.Fatalf("short-circuit = items %+v cov %+v next %q ok %v", items, cov, next, ok)
			}
		})
	}
}

// The merge forwards the caller's X-API-KEY (not just Authorization) so an
// X-API-KEY-only tenant's remote sandboxes are not dropped (B9).
func TestMergeJSONForwardsAPIKey(t *testing.T) {
	type item struct {
		ID string `json:"id"`
	}
	var sawAPIKey, sawAuth bool
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAPIKey = r.Header.Get("X-API-KEY") == "key-123"
		sawAuth = r.Header.Get("Authorization") == "Bearer tenant"
		_ = json.NewEncoder(w).Encode([]item{{ID: "peer"}})
	}))
	t.Cleanup(peer.Close)
	member := cluster.Member{NodeID: "peer-1", Alive: true, InternalURL: peer.URL, Role: config.NodeRoleWorker}
	transport := Transport{InternalClient: peer.Client(), PeerClient: func(string) *http.Client { return peer.Client() }}

	items, cov := MergeJSON(context.Background(), []cluster.Member{member}, []item{{ID: "local"}}, func(v item) string { return v.ID }, Options{
		Path:         "/peer",
		AuthHeader:   "Bearer tenant",
		APIKeyHeader: "key-123",
		SelfNodeID:   "self",
		WantIDs:      map[string]struct{}{"local": {}, "peer": {}},
		Transport:    transport,
	})
	if !sawAPIKey {
		t.Fatal("peer did not receive the forwarded X-API-KEY")
	}
	if !sawAuth {
		t.Fatal("peer did not receive the forwarded Authorization")
	}
	if cov.Partial || len(items) != 2 {
		t.Fatalf("merge = items %+v cov %+v", items, cov)
	}
}
