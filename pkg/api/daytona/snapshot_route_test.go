package daytona

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// snapRouteStub returns a scripted snapshot home node + membership.
type snapRouteStub struct {
	*cluster.Noop
	home      string
	members   []cluster.Member
	forwarded bool
}

func (c *snapRouteStub) SnapshotHomeNode(context.Context, string) (string, bool, error) {
	return c.home, c.home != "", nil
}
func (c *snapRouteStub) Members() []cluster.Member { return c.members }
func (c *snapRouteStub) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwarded = true
	w.WriteHeader(http.StatusAccepted)
}

// A Daytona snapshot-by-id GET/DELETE whose home is another node forwards there;
// the id is the snapshot name, so the resolver reads it straight from the path.
func TestDaytonaSnapshotByIDForwardsToHomeNode(t *testing.T) {
	env := newSnapshotCreateTestEnv(t, nil)
	stub := &snapRouteStub{
		Noop:    cluster.NewNoop("self", "", ""),
		home:    "worker-a",
		members: []cluster.Member{{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true}},
	}
	env.svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: env.svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		stub.forwarded = false
		req := httptest.NewRequest(method, "/daytona/snapshots/my-snap", nil)
		req.SetPathValue("id", "my-snap")
		rr := httptest.NewRecorder()
		h.snapshotForwardWrap(http.HandlerFunc(h.getSnapshot)).ServeHTTP(rr, req)
		if !stub.forwarded || rr.Code != http.StatusAccepted {
			t.Fatalf("%s: forwarded=%v code=%d, want forwarded/202", method, stub.forwarded, rr.Code)
		}
	}
}
