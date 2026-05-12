package cluster

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestNoopAlwaysSelf is the load-bearing single-node invariant: in
// EnableCluster=false mode every cluster operation must report self/no-op so
// the API wrapper falls through to the existing local handlers.
func TestNoopAlwaysSelf(t *testing.T) {
	n := NewNoop("standalone", "http://localhost:21212")

	owner, err := n.OwnerOf("any-id")
	if err != nil {
		t.Fatalf("OwnerOf returned error: %v", err)
	}
	if !owner.IsSelf {
		t.Fatal("OwnerOf must report IsSelf in single-node mode")
	}

	target, err := n.SelectPlacement(capacity.Request{CPU: 1, MemoryMB: 1024})
	if err != nil {
		t.Fatalf("SelectPlacement: %v", err)
	}
	if !target.IsSelf {
		t.Fatal("SelectPlacement must report IsSelf in single-node mode")
	}

	if err := n.RecordPlacement(context.Background(), "x", nil); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if err := n.UpsertSpec(context.Background(), "x", nil); err != nil {
		t.Fatalf("UpsertSpec: %v", err)
	}
	if err := n.DeletePlacement(context.Background(), "x"); err != nil {
		t.Fatalf("DeletePlacement: %v", err)
	}
	if err := n.AssertOwnership(context.Background(), []LocalSandboxState{{ID: "a"}, {ID: "b"}}); err != nil {
		t.Fatalf("AssertOwnership: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Members always returns self.
	members := n.Members()
	if len(members) != 1 || !members[0].Alive || members[0].NodeID != "standalone" {
		t.Fatalf("unexpected members: %+v", members)
	}
	if n.Leader() != "standalone" {
		t.Fatalf("Leader should be self in single-node mode, got %q", n.Leader())
	}
}

// TestNoopForwardHTTPSignals500 makes the bug loud: if anything ever calls
// ForwardHTTP in single-node mode, surface it rather than silently 200.
func TestNoopForwardHTTPSignals500(t *testing.T) {
	n := NewNoop("s", "http://s")
	w := newRecorder()
	n.ForwardHTTP("http://nowhere", w, nil)
	if w.code != 500 {
		t.Fatalf("expected 500 from Noop.ForwardHTTP, got %d", w.code)
	}
}

// recorder is the world's tiniest http.ResponseWriter for the test above.
type recorder struct {
	code int
	body []byte
	hdr  http.Header
}

func newRecorder() *recorder { return &recorder{code: 200, hdr: make(http.Header)} }

func (r *recorder) Header() http.Header { return r.hdr }
func (r *recorder) Write(p []byte) (int, error) {
	r.body = append(r.body, p...)
	return len(p), nil
}
func (r *recorder) WriteHeader(code int) { r.code = code }

// Compile-time guard so signature drift surfaces here.
var _ http.ResponseWriter = (*recorder)(nil)
var _ = errors.New
