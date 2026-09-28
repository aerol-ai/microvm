package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type drainedSetStubCluster struct {
	*drainStubCluster
	set map[string]bool
}

func (c *drainedSetStubCluster) DrainedNodes() map[string]bool { return c.set }

// Agents refresh their drained view from this route once per TTL, so it must
// return the whole set, sorted, and refuse on a node that has no FSM to read.
func TestClusterInternalDrainedNodes(t *testing.T) {
	t.Run("serves the drained set sorted, omitting cleared marks", func(t *testing.T) {
		stub := &drainedSetStubCluster{
			drainStubCluster: &drainStubCluster{Noop: cluster.NewNoop("server-1", "http://s1", "")},
			set:              map[string]bool{"worker-y": true, "worker-a": true, "worker-cleared": false},
		}
		rr := httptest.NewRecorder()
		drainTestHandler(t, stub).clusterInternalDrainedNodes(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalDrainedNodesPath, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
		}
		var resp cluster.DrainedNodesResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(resp.Drained, []string{"worker-a", "worker-y"}) {
			t.Fatalf("drained = %v, want [worker-a worker-y]", resp.Drained)
		}
	})
	t.Run("a client with no drained set refuses", func(t *testing.T) {
		stub := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}
		rr := httptest.NewRecorder()
		drainTestHandler(t, stub).clusterInternalDrainedNodes(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalDrainedNodesPath, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})
}
