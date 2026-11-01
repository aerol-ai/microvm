package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// The control plane's placement answer to an agent marks "every worker is
// full" with at_capacity and keeps ErrNoPlacementTarget's exact text, on all
// three request shapes, so an agent on the previous build still answers 503.
func TestClusterInternalSelectPlacementMarksAtCapacity(t *testing.T) {
	svc := c96bServiceWithCluster(config.Config{}, nil, &membersStubCluster{
		Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
		placementErr: cluster.ErrClusterAtCapacity,
	})
	h := c96bHandlers(svc)
	for name, body := range map[string]string{
		"sandbox_id":  `{"sandbox_id":"sb-1","recipient_backups":1}`,
		"target_only": `{"target_only":true}`,
		"legacy":      `{"request":{"cpu":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.clusterInternalSelectPlacement(rr, httptest.NewRequest(http.MethodPost, "/v1/cluster/internal/select-placement", strings.NewReader(body)))
			c96bExpect(t, rr, http.StatusOK)
			var resp cluster.SelectPlacementResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !resp.AtCapacity || resp.Error != cluster.ErrNoPlacementTarget.Error() {
				t.Fatalf("response = %+v, want at_capacity with the plain no-target text", resp)
			}
		})
	}
}
