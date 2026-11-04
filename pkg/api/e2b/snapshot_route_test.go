package e2b

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

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

// A template(snapshot) DELETE whose home is another node forwards there; the E2B
// id is a reversible encoding of the snapshot name, which the resolver decodes.
func TestE2BTemplateDeleteForwardsToHomeNode(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	stub := &snapRouteStub{
		Noop:    cluster.NewNoop("self", "", ""),
		home:    "worker-a",
		members: []cluster.Member{{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true}},
	}
	svc.AttachCluster(stub)
	h := &handlers{deps: Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	id := snapshotIDFromName("team/my-snap:default")
	if id == "" {
		t.Fatal("could not derive a template id")
	}
	req := httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+id, nil)
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	h.snapshotForwardWrap(http.HandlerFunc(h.deleteSnapshot)).ServeHTTP(rr, req)
	if !stub.forwarded || rr.Code != http.StatusAccepted {
		t.Fatalf("forwarded=%v code=%d, want forwarded/202", stub.forwarded, rr.Code)
	}

	// A non-decodable id (a custom alias) cannot be mapped to a name without the
	// local row, so it serves locally instead of forwarding (no regression).
	stub.forwarded = false
	req2 := httptest.NewRequest(http.MethodDelete, "/e2b/templates/custom-alias", nil)
	req2.SetPathValue("id", "custom-alias")
	rr2 := httptest.NewRecorder()
	h.snapshotForwardWrap(http.HandlerFunc(h.deleteSnapshot)).ServeHTTP(rr2, req2)
	if stub.forwarded {
		t.Fatal("a custom-alias id forwarded; it should serve locally")
	}
}
