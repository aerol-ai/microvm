package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// GET /v1/cluster/members shows each node's zone and labels from its
// capacity heartbeat (plans/placement-rules.md P1.7), so an operator can see
// what a rule can target.
func TestClusterMembersShowsZoneAndLabels(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &membersStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true, Capacity: capacity.Snapshot{Labels: map[string]string{"zone": "zone-a", "gpu": "a10"}}},
			{NodeID: "node-old", Alive: true},
		},
	})
	rr := httptest.NewRecorder()
	c96bHandlers(svc).clusterMembers(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/members", nil))
	c96bExpect(t, rr, http.StatusOK)
	var body struct {
		Members []struct {
			NodeID string            `json:"node_id"`
			Zone   string            `json:"zone"`
			Labels map[string]string `json:"labels"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Members) != 2 {
		t.Fatalf("members = %+v", body.Members)
	}
	if a := body.Members[0]; a.Zone != "zone-a" || a.Labels["gpu"] != "a10" {
		t.Fatalf("labelled node = %+v", a)
	}
	if old := body.Members[1]; old.Zone != "" || old.Labels != nil {
		t.Fatalf("a node without labels must show none: %+v", old)
	}
	if strings.Contains(rr.Body.String(), `"zone":""`) {
		t.Fatalf("empty zone must be omitted: %s", rr.Body.String())
	}
}

// Every answer to a request with labels says it checked them; without the
// flag an agent fails closed. A request with no rule gets no flag, so the
// wire form for the common case is unchanged.
func TestClusterInternalSelectPlacementSaysItCheckedLabels(t *testing.T) {
	stub := &membersStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a"},
		members:   []cluster.Member{{NodeID: "node-a", Alive: true}},
	}
	h := c96bHandlers(c96bServiceWithCluster(config.Config{}, nil, stub))
	shapes := map[string]string{
		"sandbox_id":  `"sandbox_id":"sb-1","recipient_backups":1,`,
		"target_only": `"target_only":true,`,
		"legacy":      ``,
	}
	for name, extra := range shapes {
		for _, withRule := range []bool{true, false} {
			request := `"request":{"CPU":1}`
			if withRule {
				request = `"request":{"CPU":1,"Labels":{"zone":"zone-a"}}`
			}
			rr := httptest.NewRecorder()
			h.clusterInternalSelectPlacement(rr, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader("{"+extra+request+"}")))
			c96bExpect(t, rr, http.StatusOK)
			var resp cluster.SelectPlacementResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s: decode: %v", name, err)
			}
			if resp.LabelsChecked != withRule || resp.Target.NodeID != "node-a" {
				t.Fatalf("%s rule=%v: response = %+v", name, withRule, resp)
			}
		}
	}
	stub.placementErr = models.PlacementUnsatisfiableError(map[string]string{"zone": "zone-z"})
	rr := httptest.NewRecorder()
	h.clusterInternalSelectPlacement(rr, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement",
		strings.NewReader(`{"sandbox_id":"sb-1","request":{"Labels":{"zone":"zone-z"}}}`)))
	var resp cluster.SelectPlacementResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.PlacementUnsatisfiable || !strings.Contains(resp.Error, "zone=zone-z") {
		t.Fatalf("unsatisfiable answer = %+v", resp)
	}
}
