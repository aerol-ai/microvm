package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type evacStubCluster struct {
	*staleReadStubCluster
	leader string
	err    error
	got    cluster.EvacuateRequest
}

func (c *evacStubCluster) Leader() string {
	if c.leader == "" {
		return c.SelfNodeID()
	}
	return c.leader
}

func (c *evacStubCluster) EvacuateNode(_ context.Context, id string, req cluster.EvacuateRequest) (cluster.EvacuateResult, error) {
	c.got = req
	if c.err != nil {
		return cluster.EvacuateResult{}, c.err
	}
	return cluster.EvacuateResult{NodeID: id, Moved: []string{"sb-1"}, Done: true}, nil
}

func evacRequest(id, body string, forwarded bool) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, PathPrefix+"/cluster/nodes/x/evacuate", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, PathPrefix+"/cluster/nodes/x/evacuate", strings.NewReader(body))
	}
	r.SetPathValue("id", id)
	if forwarded {
		r.Header.Set(clusterEvacuateLeaderHeader, "1")
	}
	return r
}

func TestClusterEvacuateNode(t *testing.T) {
	stub := func(err error, leader string) *evacStubCluster {
		return &evacStubCluster{staleReadStubCluster: &staleReadStubCluster{Noop: cluster.NewNoop("srv", "", "")}, err: err, leader: leader}
	}
	cases := []struct {
		name      string
		c         cluster.Client
		id, body  string
		forwarded bool
		want      int
	}{
		{name: "a pass", c: stub(nil, ""), id: "wkr-1", body: `{"stop_remaining":true,"max":4}`, want: http.StatusOK},
		{name: "no body", c: stub(nil, ""), id: "wkr-1", want: http.StatusOK},
		{name: "not cordoned", c: stub(cluster.ErrNodeNotDrained, ""), id: "wkr-1", want: http.StatusConflict},
		{name: "dead node", c: stub(cluster.ErrNodeNotAlive, ""), id: "wkr-1", want: http.StatusConflict},
		{name: "lost leadership", c: stub(cluster.ErrNotLeader, ""), id: "wkr-1", want: http.StatusServiceUnavailable},
		{name: "other error (the house classifier)", c: stub(errors.New("raft apply failed"), ""), id: "wkr-1", want: http.StatusBadRequest},
		{name: "bad JSON", c: stub(nil, ""), id: "wkr-1", body: `{`, want: http.StatusBadRequest},
		{name: "no id", c: stub(nil, ""), id: " ", want: http.StatusBadRequest},
		{name: "forwarded to a non-leader", c: stub(nil, "srv-2"), id: "wkr-1", forwarded: true, want: http.StatusServiceUnavailable},
		{name: "not a server", c: cluster.NewNoop("wkr", "", ""), id: "wkr-1", want: http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := placementChangesHandlers(t, tc.c)
			rr := httptest.NewRecorder()
			h.clusterEvacuateNode(rr, evacRequest(tc.id, tc.body, tc.forwarded))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.name == "a pass" {
				var res cluster.EvacuateResult
				if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || !res.Done || res.NodeID != "wkr-1" {
					t.Fatalf("body %s %v", rr.Body.String(), err)
				}
				if got := tc.c.(*evacStubCluster).got; !got.StopRemaining || got.Max != 4 {
					t.Fatalf("request reached the leader as %+v", got)
				}
			}
		})
	}
	rr := httptest.NewRecorder()
	(&handlers{}).clusterEvacuateNode(rr, evacRequest("wkr-1", "", false))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no service: %d", rr.Code)
	}
}

// The worker's move route: only the leader may ask, and only for this node.
func TestClusterNodeMove(t *testing.T) {
	c := &evacStubCluster{staleReadStubCluster: &staleReadStubCluster{Noop: cluster.NewNoop("wkr", "", "")}, leader: "srv-leader"}
	h := placementChangesHandlers(t, c)
	call := func(id, peer, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, PathPrefix+"/cluster/nodes/x/move", strings.NewReader(body))
		r.SetPathValue("id", id)
		if peer != "" {
			r = r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, peer))
		}
		rr := httptest.NewRecorder()
		h.clusterNodeMove(rr, r)
		return rr
	}
	if rr := call("wkr-other", "srv-leader", `{"action":"release"}`); rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("another node's id: %d", rr.Code)
	}
	if rr := call("wkr", "wkr-2", `{"action":"release"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("a non-leader peer: %d", rr.Code)
	}
	if rr := call("wkr", "", `{"action":"release"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("no peer identity: %d", rr.Code)
	}
	if rr := call("wkr", "srv-leader", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: %d", rr.Code)
	}
	if rr := call("wkr", "srv-leader", `{"action":"nuke"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d", rr.Code)
	}
	// The leader's call reaches the service: a pull that needs registry
	// credentials is left to the recreate, and says so.
	rr := call("wkr", "srv-leader", `{"action":"prepare","spec":{"image":"private/x","registry":{"username":"u"}}}`)
	var out cluster.MoveActionResult
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || !strings.Contains(out.Error, "cannot pull") {
		t.Fatalf("prepare: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	(&handlers{}).clusterNodeMove(rr, httptest.NewRequest(http.MethodPost, "/x", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no service: %d", rr.Code)
	}
}
