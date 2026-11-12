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

// goneStubCluster is a server: the leader when leader is empty or its own id.
type goneStubCluster struct {
	*staleReadStubCluster
	leader   string
	err      error
	marked   []string
	contacts []string
}

func (c *goneStubCluster) Leader() string {
	if c.leader == "" {
		return c.SelfNodeID()
	}
	return c.leader
}

func (c *goneStubCluster) MarkNodeGone(id string) (cluster.NodeGoneResult, error) {
	c.marked = append(c.marked, id)
	if c.err != nil {
		return cluster.NodeGoneResult{}, c.err
	}
	return cluster.NodeGoneResult{NodeID: id, Early: true}, nil
}

func (c *goneStubCluster) NoteOwnershipContact(id string) { c.contacts = append(c.contacts, id) }

func goneRequest(id string, forwarded bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, PathPrefix+"/cluster/nodes/x/gone", nil)
	r.SetPathValue("id", id)
	if forwarded {
		r.Header.Set(clusterNodeGoneLeaderHeader, "1")
	}
	return r
}

func TestClusterNodeGone(t *testing.T) {
	stub := func(err error, leader string) *goneStubCluster {
		return &goneStubCluster{staleReadStubCluster: &staleReadStubCluster{Noop: cluster.NewNoop("srv", "", "")}, err: err, leader: leader}
	}
	cases := []struct {
		name      string
		c         cluster.Client
		id        string
		forwarded bool
		want      int
	}{
		{name: "leader marks it", c: stub(nil, ""), id: "wkr-1", want: http.StatusOK},
		{name: "leader itself", c: stub(cluster.ErrNodeGoneSelf, ""), id: "srv", want: http.StatusConflict},
		{name: "lost leadership mid-call", c: stub(cluster.ErrNotLeader, ""), id: "wkr-1", want: http.StatusServiceUnavailable},
		{name: "bad input", c: stub(errors.New("cluster: node id required"), ""), id: "wkr-1", want: http.StatusBadRequest},
		{name: "no id", c: stub(nil, ""), id: " ", want: http.StatusBadRequest},
		{name: "forwarded to a server that is no longer leader", c: stub(nil, "srv-2"), id: "wkr-1", forwarded: true, want: http.StatusServiceUnavailable},
		{name: "no leader to forward to", c: &goneStubCluster{staleReadStubCluster: &staleReadStubCluster{Noop: cluster.NewNoop("srv", "", "")}, leader: " "}, id: "wkr-1", want: http.StatusServiceUnavailable},
		{name: "not a server (worker agent)", c: cluster.NewNoop("wkr", "", ""), id: "wkr-1", want: http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := placementChangesHandlers(t, tc.c)
			rr := httptest.NewRecorder()
			h.clusterNodeGone(rr, goneRequest(tc.id, tc.forwarded))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.want == http.StatusOK {
				var res cluster.NodeGoneResult
				if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || res.NodeID != tc.id || !res.Early {
					t.Fatalf("body = %s %v", rr.Body.String(), err)
				}
			}
		})
	}

	// Outside cluster mode there is nothing to mark.
	h := placementChangesHandlers(t, nil)
	rr := httptest.NewRecorder()
	h.clusterNodeGone(rr, goneRequest("wkr-1", false))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no cluster: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	(&handlers{}).clusterNodeGone(rr, goneRequest("wkr-1", false))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no service: %d", rr.Code)
	}
}

// The leader's answer to an authoritative read is the asking node's lease
// renewal, so it is recorded as that node's last proven contact (C19). A
// plain (non-authoritative) read renews nothing and records nothing.
func TestAuthoritativeReadRecordsOwnershipContact(t *testing.T) {
	stub := &goneStubCluster{staleReadStubCluster: &staleReadStubCluster{Noop: cluster.NewNoop("srv", "", "")}}
	h := placementChangesHandlers(t, stub)
	call := func(query string, peer string) {
		r := httptest.NewRequest(http.MethodPost, cluster.PublicInternalPlacementsByIDsPath+query, strings.NewReader(`{"ids":["sb-x"]}`))
		if peer != "" {
			r = r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, peer))
		}
		rr := httptest.NewRecorder()
		h.clusterInternalPlacementsByIDs(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
		}
	}
	call("?authoritative=true", "worker-a")
	call("", "worker-b")
	call("?authoritative=true", "")
	if len(stub.contacts) != 1 || stub.contacts[0] != "worker-a" {
		t.Fatalf("contacts = %v, want [worker-a]", stub.contacts)
	}
}
