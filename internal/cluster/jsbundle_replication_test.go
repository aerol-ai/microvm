package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

type replicaCapture struct {
	owner      string
	replicated string
	auth       string
	body       models.CreateJSBundleRequest
}

// TestReplicateJSBundleToPeers: the fan-out POSTs the bundle to every OTHER
// live member with the replication + owner headers and PAT, and skips self,
// dead members, and members with no API URL — the loop guard + owner
// preservation the isolate-on-cluster fix depends on.
func TestReplicateJSBundleToPeers(t *testing.T) {
	var mu sync.Mutex
	got := map[string]replicaCapture{}
	mk := func(node string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var req models.CreateJSBundleRequest
			_ = json.Unmarshal(b, &req)
			mu.Lock()
			got[node] = replicaCapture{
				owner:      r.Header.Get(models.HeaderJSBundleOwner),
				replicated: r.Header.Get(models.HeaderJSBundleReplicated),
				auth:       r.Header.Get("Authorization"),
				body:       req,
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		}))
	}
	peerB, peerC := mk("B"), mk("C")
	defer peerB.Close()
	defer peerC.Close()

	members := []Member{
		{NodeID: "A", Alive: true, APIURL: "http://self.invalid"}, // self -> skip
		{NodeID: "B", Alive: true, APIURL: peerB.URL},
		{NodeID: "C", Alive: true, APIURL: peerC.URL},
		{NodeID: "D", Alive: false, APIURL: "http://dead.invalid"}, // dead -> skip
		{NodeID: "E", Alive: true, APIURL: ""},                     // no URL -> skip
	}
	req := models.CreateJSBundleRequest{Name: "hello", Source: "export default { async fetch(){return new Response('ok')} }"}
	err := replicateJSBundleToPeers(context.Background(), members, &http.Client{}, "pat123", "A", "tenant-x", req)
	if err != nil {
		t.Fatalf("replicate: %v", err)
	}
	if _, ok := got["A"]; ok {
		t.Error("self node A received a replica (should skip self)")
	}
	if _, ok := got["D"]; ok {
		t.Error("dead node D received a replica (should skip dead)")
	}
	if len(got) != 2 {
		t.Fatalf("replicated to %d peers, want 2 (B,C): %v", len(got), got)
	}
	for _, node := range []string{"B", "C"} {
		c := got[node]
		if c.replicated != "1" {
			t.Errorf("%s: replicated header = %q, want 1", node, c.replicated)
		}
		if c.owner != "tenant-x" {
			t.Errorf("%s: owner header = %q, want tenant-x", node, c.owner)
		}
		if c.auth != "Bearer pat123" {
			t.Errorf("%s: auth = %q, want Bearer pat123", node, c.auth)
		}
		if c.body.Name != "hello" || c.body.Source != req.Source {
			t.Errorf("%s: body = %+v, want name=hello + source", node, c.body)
		}
	}
}

// TestReplicateJSBundleToPeers_NoPeers: a lone node (only self, or no members)
// makes zero requests and returns nil — the single-node no-op guarantee.
func TestReplicateJSBundleToPeers_NoPeers(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	for _, members := range [][]Member{
		nil,
		{{NodeID: "A", Alive: true, APIURL: srv.URL}}, // only self
	} {
		if err := replicateJSBundleToPeers(context.Background(), members, &http.Client{}, "p", "A", "o", models.CreateJSBundleRequest{Source: "x"}); err != nil {
			t.Fatalf("no-peer replicate returned error: %v", err)
		}
	}
	if hit {
		t.Error("a request was made when the only member was self")
	}
}
