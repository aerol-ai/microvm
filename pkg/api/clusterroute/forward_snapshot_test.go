package clusterroute

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// snapStub is a cluster.Client (via Noop) with a scriptable snapshot-home index
// and membership, for WrapSnapshot routing.
type snapStub struct {
	*cluster.Noop
	home      string
	found     bool
	lookupErr error
	members   []cluster.Member
	forwarded bool
}

func (c *snapStub) SnapshotHomeNode(context.Context, string) (string, bool, error) {
	return c.home, c.found, c.lookupErr
}
func (c *snapStub) Members() []cluster.Member { return c.members }
func (c *snapStub) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwarded = true
	w.WriteHeader(http.StatusAccepted)
}

func snapReq(forwarded bool) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/x/snap-a", nil)
	r.SetPathValue("id", "snap-a")
	if forwarded {
		r.Header.Set("X-Cluster-Forwarded", "1")
	}
	return r
}

func TestWrapSnapshot(t *testing.T) {
	peer := cluster.Member{NodeID: "node-b", APIURL: "http://node-b", Alive: true}
	name := func(r *http.Request) string { return r.PathValue("id") }

	t.Run("nil service serves locally", func(t *testing.T) {
		h, ran := local()
		WrapSnapshot(nil, name, writeErr, h).ServeHTTP(httptest.NewRecorder(), snapReq(false))
		if !*ran {
			t.Fatal("expected local serve with a nil service")
		}
	})

	t.Run("detached cluster serves locally", func(t *testing.T) {
		svc := svcWith(t, nil)
		svc.ClearClusterForTest()
		h, ran := local()
		WrapSnapshot(svc, name, writeErr, h).ServeHTTP(httptest.NewRecorder(), snapReq(false))
		if !*ran {
			t.Fatal("expected local serve with no cluster client")
		}
	})

	t.Run("lookup error is surfaced", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), lookupErr: errors.New("boom")}
		h, _ := local()
		rr := httptest.NewRecorder()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(rr, snapReq(false))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want 503 on lookup error", rr.Code)
		}
	})

	t.Run("no home entry serves locally", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", "")} // found=false
		h, ran := local()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(httptest.NewRecorder(), snapReq(false))
		if !*ran {
			t.Fatal("expected local serve when no home entry")
		}
	})

	t.Run("self is the home, serves locally", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "self", found: true}
		h, ran := local()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(httptest.NewRecorder(), snapReq(false))
		if !*ran {
			t.Fatal("expected local serve when this node is the home")
		}
	})

	t.Run("empty resolved name serves locally", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "node-b", found: true, members: []cluster.Member{peer}}
		h, ran := local()
		WrapSnapshot(svcWith(t, stub), func(*http.Request) string { return "" }, writeErr, h).ServeHTTP(httptest.NewRecorder(), snapReq(false))
		if !*ran {
			t.Fatal("expected local serve when the name cannot be resolved")
		}
	})

	t.Run("forwards to the home node", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "node-b", found: true, members: []cluster.Member{peer}}
		h, ran := local()
		rr := httptest.NewRecorder()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(rr, snapReq(false))
		if *ran {
			t.Fatal("served locally, expected a forward")
		}
		if !stub.forwarded || rr.Code != http.StatusAccepted {
			t.Fatalf("forward=%v code=%d, want forwarded/202", stub.forwarded, rr.Code)
		}
	})

	t.Run("loop guard", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "node-b", found: true, members: []cluster.Member{peer}}
		h, _ := local()
		rr := httptest.NewRecorder()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(rr, snapReq(true))
		if rr.Code != http.StatusMisdirectedRequest {
			t.Fatalf("code = %d, want 421 on a forwarding loop", rr.Code)
		}
	})

	t.Run("home node present but unavailable", func(t *testing.T) {
		dead := cluster.Member{NodeID: "node-b", APIURL: "", Alive: false}
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "node-b", found: true, members: []cluster.Member{dead}}
		h, _ := local()
		rr := httptest.NewRecorder()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(rr, snapReq(false))
		if rr.Code != http.StatusServiceUnavailable || stub.forwarded {
			t.Fatalf("code=%d forwarded=%v, want 503 and no forward for a dead home node", rr.Code, stub.forwarded)
		}
	})

	t.Run("home node left the cluster", func(t *testing.T) {
		stub := &snapStub{Noop: cluster.NewNoop("self", "", ""), home: "node-gone", found: true, members: []cluster.Member{peer}}
		h, _ := local()
		rr := httptest.NewRecorder()
		WrapSnapshot(svcWith(t, stub), name, writeErr, h).ServeHTTP(rr, snapReq(false))
		if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("x-should-retry") != "false" {
			t.Fatalf("code=%d x-should-retry=%q, want 503/false when the home node is gone", rr.Code, rr.Header().Get("x-should-retry"))
		}
	})
}
