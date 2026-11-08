package cluster

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSoleRaftServer: the service places an old row with no placement only on
// a node that is the only server in its Raft configuration, so this fact must
// turn false as soon as any other server, voter or not, is configured, and it
// is never true for a client without a local Raft.
func TestSoleRaftServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()

	if !SoleRaftServer(c) {
		t.Fatal("a single bootstrapped node is the sole Raft server")
	}
	if err := c.raft.raft.AddNonvoter("peer", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatalf("add peer: %v", err)
	}
	if SoleRaftServer(c) {
		t.Fatal("a configuration with another server is not sole")
	}
	if (*Cluster)(nil).SoleRaftServer() || (&Cluster{}).SoleRaftServer() {
		t.Fatal("a cluster without raft is never the sole server")
	}
	if SoleRaftServer(&Agent{}) || SoleRaftServer(NewNoop("n", "", "")) {
		t.Fatal("a client without a local Raft is never the sole server")
	}
}

// TestAssertOwnershipDeletedLifecycleReportsSentinel: the refusal reaches the
// caller as ErrPlacementDeleted, stops the hostname replay for that row, and
// is counted.
func TestAssertOwnershipDeletedLifecycleReportsSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	if err := c.RecordPlacement(ctx, "sb-gone", spec, PlacementSecrets{IncarnationID: "inc-gone"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePlacementExact(ctx, "sb-gone", c.nodeID, "inc-gone"); err != nil {
		t.Fatal(err)
	}
	before := clusterOwnershipReplayRefused.Value()
	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID: "sb-gone", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-gone"},
		CustomHostnames: []string{"gone.example"},
	}})
	if !errors.Is(err, ErrPlacementDeleted) {
		t.Fatalf("AssertOwnership = %v, want ErrPlacementDeleted", err)
	}
	if _, ok := c.fsm.sandboxIDByCustomHostname("gone.example"); ok {
		t.Fatal("a refused row's hostname was replayed")
	}
	if got := clusterOwnershipReplayRefused.Value() - before; got != 1 {
		t.Fatalf("refusals counted %d, want 1", got)
	}
}

// TestAgentAssertOwnershipRefusedRow is the worker side, over the
// control-plane hop: a refused row comes back as ErrPlacementDeleted and its
// ports are not replayed; the next row is still placed.
func TestAgentAssertOwnershipRefusedRow(t *testing.T) {
	var applied []command
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			body, _ := io.ReadAll(r.Body)
			var cmd command
			if err := decodeCommandInto(body, &cmd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied = append(applied, cmd)
			if cmd.Op == opPlace && cmd.SandboxID == "sb-deleted" {
				http.Error(w, "cluster: fsm apply: "+ErrPlacementDeleted.Error()+": sb-deleted", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	ports := map[int]ExposedPortRoute{8080: {Protocol: "http"}}
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{
		{ID: "sb-deleted", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-deleted"}, ExposedPorts: ports},
		{ID: "sb-fresh", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-fresh"}, ExposedPorts: ports},
	})
	if !errors.Is(err, ErrPlacementDeleted) {
		t.Fatalf("AssertOwnership = %v, want ErrPlacementDeleted", err)
	}
	var placed, freshPorts []string
	for _, cmd := range applied {
		if cmd.SandboxID == "sb-deleted" && cmd.Op != opPlace {
			t.Fatalf("a refused row's ports were replayed: %+v", cmd)
		}
		if cmd.Op == opPlace {
			placed = append(placed, cmd.SandboxID)
		}
		if cmd.SandboxID == "sb-fresh" && cmd.Op == opAddExposedPort {
			freshPorts = append(freshPorts, cmd.SandboxID)
		}
	}
	if !slices.Equal(placed, []string{"sb-deleted", "sb-fresh"}) {
		t.Fatalf("opPlace sent for %v, want [sb-deleted sb-fresh]", placed)
	}
	if len(freshPorts) != 1 {
		t.Fatalf("the placed row's port was not replayed: %+v", applied)
	}
}
