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
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func quotaRequest(method, team, body string) *http.Request {
	r := httptest.NewRequest(method, "/v1/teams/"+team+"/quota", strings.NewReader(body))
	r.SetPathValue("team", team)
	return r
}

// The admin quota API on one node: PUT twice is the same answer, GET shows
// usage, DELETE converges, and the errors map to 400/404.
func TestTeamQuotaHandlersSingleNode(t *testing.T) {
	h := c96bHandlers(c96bServiceWithCluster(config.Config{}, c96bOpenStore(t), nil))
	for range 2 {
		rr := httptest.NewRecorder()
		h.putTeamQuota(rr, quotaRequest(http.MethodPut, "risk", `{"max_sandboxes":3,"max_cpu":4}`))
		c96bExpect(t, rr, http.StatusOK)
		var q models.TeamQuota
		if err := json.Unmarshal(rr.Body.Bytes(), &q); err != nil || q.Team != "risk" || q.MaxSandboxes != 3 || q.Generation != 1 || q.Usage == nil {
			t.Fatalf("put = %s (%v)", rr.Body.String(), err)
		}
	}
	rr := httptest.NewRecorder()
	h.getTeamQuota(rr, quotaRequest(http.MethodGet, "risk", ""))
	c96bExpect(t, rr, http.StatusOK)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"bad json", "{", http.StatusBadRequest},
		{"limits nothing", "{}", http.StatusBadRequest},
		{"negative", `{"max_cpu":-1}`, http.StatusBadRequest},
	} {
		rr := httptest.NewRecorder()
		h.putTeamQuota(rr, quotaRequest(http.MethodPut, "risk", tc.body))
		if rr.Code != tc.want {
			t.Fatalf("%s: status %d, want %d", tc.name, rr.Code, tc.want)
		}
	}
	for range 2 {
		rr = httptest.NewRecorder()
		h.deleteTeamQuota(rr, quotaRequest(http.MethodDelete, "risk", ""))
		c96bExpect(t, rr, http.StatusNoContent)
	}
	rr = httptest.NewRecorder()
	h.getTeamQuota(rr, quotaRequest(http.MethodGet, "risk", ""))
	c96bExpect(t, rr, http.StatusNotFound)
	rr = httptest.NewRecorder()
	h.deleteTeamQuota(rr, quotaRequest(http.MethodDelete, "Bad_Team", ""))
	c96bExpect(t, rr, http.StatusBadRequest)
}

type quotaWriterCluster struct {
	*cluster.Noop
	resp    cluster.TeamQuotaWriteResponse
	err     error
	read    cluster.TeamQuotaReadResponse
	readErr error
}

func (c *quotaWriterCluster) WriteTeamQuota(context.Context, cluster.TeamQuotaWriteRequest) (cluster.TeamQuotaWriteResponse, error) {
	return c.resp, c.err
}

func (c *quotaWriterCluster) ReadTeamQuota(context.Context, cluster.TeamQuotaReadRequest) (cluster.TeamQuotaReadResponse, error) {
	return c.read, c.readErr
}

// The internal endpoints a worker and a follower use: a write answers its
// outcome code in a 200 body so it survives forwarding; a read answers from
// this node's FSM; a node without placement state answers 503.
func TestClusterInternalTeamQuotaEndpoints(t *testing.T) {
	stub := &quotaWriterCluster{Noop: cluster.NewNoop("node-a", "", ""),
		resp: cluster.TeamQuotaWriteResponse{Quota: cluster.TeamQuotaRecord{Team: "risk", MaxSandboxes: 2}, Changed: true},
		read: cluster.TeamQuotaReadResponse{Found: true, Authoritative: true, Usage: models.TeamQuotaUsage{Sandboxes: 1}}}
	h := c96bHandlers(c96bServiceWithCluster(config.Config{EnableCluster: true}, nil, stub))
	post := func(fn func(http.ResponseWriter, *http.Request), path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		fn(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rr
	}
	rr := post(h.clusterInternalTeamQuotaWrite, cluster.PublicInternalTeamQuotaWritePath, `{"quota":{"team":"risk","max_sandboxes":2}}`)
	c96bExpect(t, rr, http.StatusOK)
	var wr cluster.TeamQuotaWriteResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &wr); err != nil || !wr.Changed || wr.Quota.MaxSandboxes != 2 {
		t.Fatalf("write = %s", rr.Body.String())
	}
	stub.err = cluster.ErrClusterVersion
	rr = post(h.clusterInternalTeamQuotaWrite, cluster.PublicInternalTeamQuotaWritePath, `{"quota":{"team":"risk"}}`)
	c96bExpect(t, rr, http.StatusOK)
	if err := json.Unmarshal(rr.Body.Bytes(), &wr); err != nil || wr.Code == "" {
		t.Fatalf("write during upgrade must carry its code: %s", rr.Body.String())
	}
	stub.err = errors.New("raft down")
	c96bExpect(t, post(h.clusterInternalTeamQuotaWrite, cluster.PublicInternalTeamQuotaWritePath, `{}`), http.StatusServiceUnavailable)
	c96bExpect(t, post(h.clusterInternalTeamQuotaWrite, cluster.PublicInternalTeamQuotaWritePath, `{`), http.StatusBadRequest)

	rr = post(h.clusterInternalTeamQuotaRead, cluster.PublicInternalTeamQuotaReadPath, `{"team":"risk"}`)
	c96bExpect(t, rr, http.StatusOK)
	var rd cluster.TeamQuotaReadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &rd); err != nil || !rd.Found || rd.Usage.Sandboxes != 1 {
		t.Fatalf("read = %s", rr.Body.String())
	}
	c96bExpect(t, post(h.clusterInternalTeamQuotaRead, cluster.PublicInternalTeamQuotaReadPath, `{`), http.StatusBadRequest)
	stub.readErr = errors.New("no fsm")
	c96bExpect(t, post(h.clusterInternalTeamQuotaRead, cluster.PublicInternalTeamQuotaReadPath, `{}`), http.StatusServiceUnavailable)

	bare := c96bHandlers(c96bServiceWithCluster(config.Config{EnableCluster: true}, nil, cluster.NewNoop("n", "", "")))
	c96bExpect(t, post(bare.clusterInternalTeamQuotaWrite, cluster.PublicInternalTeamQuotaWritePath, `{}`), http.StatusServiceUnavailable)
	c96bExpect(t, post(bare.clusterInternalTeamQuotaRead, cluster.PublicInternalTeamQuotaReadPath, `{}`), http.StatusServiceUnavailable)
}
