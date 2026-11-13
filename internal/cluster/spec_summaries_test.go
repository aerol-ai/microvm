package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClusterSpecSummaries(t *testing.T) {
	c, cleanup := newTestCluster(t, "spec-sum-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	cmd := place("sb-a", "w1")
	cmd.Spec = &models.CreateSandboxRequest{Image: "python:3.12", Runtime: models.RuntimeGvisor, CPU: 0.5, MemoryMB: 512,
		ContainerCommand: []string{"sleep", "inf"}, Env: map[string]string{"TOKEN": "secret"}}
	if err := c.applyCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	got, err := c.SpecSummaries(ctx, []string{"sb-a", "sb-missing"})
	if err != nil {
		t.Fatal(err)
	}
	s, ok := got["sb-a"]
	if !ok || len(got) != 1 || s.Image != "python:3.12" || s.Runtime != models.RuntimeGvisor || s.CPU != 0.5 || s.MemoryMB != 512 ||
		strings.Join(s.Command, " ") != "sleep inf" || s.Version == 0 {
		t.Fatalf("summaries = %+v", got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "TOKEN") {
		t.Fatalf("a summary carries env: %s", raw)
	}
	if _, err := c.SpecSummaries(ctx, nil); !errors.Is(err, ErrBadSpecSummaryBatch) {
		t.Fatalf("empty batch: %v", err)
	}
	if _, err := c.SpecSummaries(ctx, make([]string, MaxSpecSummaryBatch+1)); !errors.Is(err, ErrBadSpecSummaryBatch) {
		t.Fatalf("oversized batch: %v", err)
	}
	var none *Cluster
	if _, err := none.SpecSummaries(ctx, []string{"sb-a"}); err == nil {
		t.Fatal("a node with no FSM")
	}
	// The leader's own refusal of a bad run-state batch (#1233's apply path).
	if _, err := c.SetRunStates(ctx, []RunStateReport{{SandboxID: "sb-a"}}); !errors.Is(err, ErrBadRunStateBatch) {
		t.Fatalf("a bad run-state batch on the leader: %v", err)
	}
}

func TestAgentSpecSummaries(t *testing.T) {
	var fail atomic.Bool
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalSpecSummariesPath || fail.Load() {
			http.Error(w, "no", http.StatusServiceUnavailable)
			return
		}
		var req SpecSummariesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		out := SpecSummariesResponse{Summaries: map[string]SpecSummary{}}
		for _, id := range req.IDs {
			out.Summaries[id] = SpecSummary{Image: "img-" + id, Version: 3}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	ctx := context.Background()
	got, err := agent.SpecSummaries(ctx, []string{"sb-a", "sb-b"})
	if err != nil || got["sb-b"].Image != "img-sb-b" || len(got) != 2 {
		t.Fatalf("agent = %+v %v", got, err)
	}
	fail.Store(true)
	if _, err := agent.SpecSummaries(ctx, []string{"sb-a"}); err == nil {
		t.Fatal("a failed read")
	}
	if _, err := agent.SpecSummaries(ctx, nil); !errors.Is(err, ErrBadSpecSummaryBatch) {
		t.Fatalf("empty batch: %v", err)
	}
	var none *Agent
	if _, err := none.SpecSummaries(ctx, []string{"sb-a"}); err == nil {
		t.Fatal("a nil agent")
	}
}
