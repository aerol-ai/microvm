package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type replicaCapture struct {
	owner  string
	peerID string
	auth   string
	body   models.CreateJSBundleRequest
}

// TestReplicateJSBundleToPeers: the fan-out POSTs to every other isolate
// worker with owner + peer headers and PAT, skipping ineligible members.
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
				owner:  r.Header.Get(models.HeaderJSBundleOwner),
				peerID: r.Header.Get(PeerNodeIDHeader),
				auth:   r.Header.Get("Authorization"),
				body:   req,
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		}))
	}
	peerB, peerC := mk("B"), mk("C")
	defer peerB.Close()
	defer peerC.Close()

	members := []Member{
		{NodeID: "A", Alive: true, InternalURL: "https://self.invalid"}, // self -> skip
		{NodeID: "B", Alive: true, Role: "worker", InternalURL: peerB.URL, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeIsolate}}},
		{NodeID: "C", Alive: true, Role: "worker", InternalURL: peerC.URL, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeIsolate}}},
		{NodeID: "D", Alive: false, InternalURL: "https://dead.invalid"}, // dead -> skip
		{NodeID: "E", Alive: true, InternalURL: ""},                      // no URL -> skip
		{NodeID: "F", Alive: true, Role: "ingress", InternalURL: "https://ingress.invalid", Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeIsolate}}},
		{NodeID: "G", Alive: true, Role: "worker", InternalURL: "https://docker.invalid", Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeDocker}}},
	}
	req := models.CreateJSBundleRequest{Name: "hello", Source: "export default { async fetch(){return new Response('ok')} }"}
	dial := func(m Member) (*http.Client, string, error) { return http.DefaultClient, m.InternalURL, nil }
	err := replicateJSBundleToPeers(context.Background(), members, dial, "pat123", "A", "tenant-x", req)
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
		if c.peerID != "A" {
			t.Errorf("%s: peer node header = %q, want A", node, c.peerID)
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

type concurrentReplicaTransport struct {
	current atomic.Int32
	max     atomic.Int32
}

func (t *concurrentReplicaTransport) RoundTrip(*http.Request) (*http.Response, error) {
	current := t.current.Add(1)
	for {
		previous := t.max.Load()
		if current <= previous || t.max.CompareAndSwap(previous, current) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	t.current.Add(-1)
	return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestReplicateJSBundleToPeersBoundsConcurrency(t *testing.T) {
	members := make([]Member, jsBundleReplicationConcurrency*2)
	for i := range members {
		members[i] = Member{
			NodeID:      fmt.Sprintf("worker-%d", i),
			Alive:       true,
			Role:        "worker",
			InternalURL: "https://worker.invalid",
			Capacity:    capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeIsolate}},
		}
	}
	transport := &concurrentReplicaTransport{}
	dial := func(Member) (*http.Client, string, error) {
		return &http.Client{Transport: transport}, "https://worker.invalid", nil
	}
	if err := replicateJSBundleToPeers(context.Background(), members, dial, "pat", "self", "owner", models.CreateJSBundleRequest{Source: "x"}); err != nil {
		t.Fatal(err)
	}
	if got := int(transport.max.Load()); got <= 1 || got > jsBundleReplicationConcurrency {
		t.Fatalf("maximum concurrent replicas = %d, want 2..%d", got, jsBundleReplicationConcurrency)
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
		{{NodeID: "A", Alive: true, InternalURL: srv.URL}}, // only self
	} {
		dial := func(m Member) (*http.Client, string, error) { return http.DefaultClient, m.InternalURL, nil }
		if err := replicateJSBundleToPeers(context.Background(), members, dial, "p", "A", "o", models.CreateJSBundleRequest{Source: "x"}); err != nil {
			t.Fatalf("no-peer replicate returned error: %v", err)
		}
	}
	if hit {
		t.Error("a request was made when the only member was self")
	}
}
