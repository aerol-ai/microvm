package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestClusterDrainedNodesReadsTheFSM(t *testing.T) {
	c, cleanup := newTestCluster(t, "node1", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	if got := c.DrainedNodes(); len(got) != 0 {
		t.Fatalf("fresh cluster drained set = %v, want empty", got)
	}
	if err := c.SetNodeDrainState(context.Background(), "worker-x", true); err != nil {
		t.Fatal(err)
	}
	got := c.DrainedNodes()
	if !got["worker-x"] || len(got) != 1 {
		t.Fatalf("drained set = %v, want {worker-x}", got)
	}
	got["worker-y"] = true // the caller's copy must not reach the FSM
	if c.IsNodeDrained("worker-y") {
		t.Fatal("mutating the returned set leaked into the FSM")
	}
	if (*Cluster)(nil).DrainedNodes() != nil {
		t.Fatal("nil cluster must report nothing")
	}
}

// The agent asks the control plane at most once per TTL, and a failed
// refresh keeps the last good set: forgetting a drain because one request
// failed would put a secret copy straight back onto the node being evacuated.
func TestAgentDrainedNodesCachesAndSurvivesAFailedRefresh(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalDrainedNodesPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(DrainedNodesResponse{Drained: []string{"worker-x", ""}})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	got := agent.DrainedNodes()
	if !got["worker-x"] || len(got) != 1 || calls.Load() != 1 {
		t.Fatalf("first read = %v after %d calls, want {worker-x} after 1", got, calls.Load())
	}
	got["poison"] = true
	if again := agent.DrainedNodes(); calls.Load() != 1 || again["poison"] {
		t.Fatalf("second read within the TTL made %d calls or leaked a caller mutation: %v", calls.Load(), again)
	}

	agent.drained.mu.Lock()
	agent.drained.fetchedAt = time.Now().Add(-2 * drainedNodesTTL)
	agent.drained.mu.Unlock()
	fail.Store(true)
	if stale := agent.DrainedNodes(); !stale["worker-x"] || calls.Load() != 2 {
		t.Fatalf("failed refresh = %v after %d calls, want the last good set after a retry", stale, calls.Load())
	}
	if (*Agent)(nil).DrainedNodes() != nil {
		t.Fatal("nil agent must report nothing")
	}
}
