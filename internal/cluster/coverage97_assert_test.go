package cluster

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func coverage97OwnershipAgent(t *testing.T, sandboxID string, lookup PlacementLookupResponse, found bool, fail opCode) *Agent {
	t.Helper()
	return newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+sandboxID:
			if !found {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(lookup)
		case r.Method == http.MethodPost:
			payload, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(payload)
			if err != nil || cmd.Op == fail {
				http.Error(w, "denied", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}), Member{
		NodeID: "worker-self", Alive: true, Role: config.NodeRoleServer,
		InternalURL: "https://self.invalid", APIURL: "https://self.invalid",
	})
}

func TestCoverage97AssertOwnershipErrorBodies(t *testing.T) {
	ports := map[int]ExposedPortRoute{3001: {Protocol: "http"}}
	hosts := []string{"replay.example.com"}
	spec := &models.CreateSandboxRequest{Image: "alpine"}

	t.Run("fresh port", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-fresh-port", PlacementLookupResponse{}, false, opAddExposedPort)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-fresh-port", Spec: spec, ExposedPorts: ports,
		}}); err == nil {
			t.Fatal("expected exposed-port failure")
		}
	})
	t.Run("fresh domain", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-fresh-host", PlacementLookupResponse{}, false, opAddCustomDomain)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-fresh-host", Spec: spec, CustomHostnames: hosts,
		}}); err == nil {
			t.Fatal("expected custom-domain failure")
		}
	})

	reserved := PlacementLookupResponse{Placement: Placement{
		SandboxID: "sb-reserved", OwnerNodeID: "worker-self", State: PlacementStateReserved, IncarnationID: "inc-r",
	}}
	reserved.SandboxID = "sb-reserved"
	reserved.Placement.SandboxID = "sb-reserved"
	t.Run("reserved place", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-reserved", reserved, true, opPlace)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-reserved", Spec: spec,
		}}); err == nil {
			t.Fatal("expected reserved place failure")
		}
	})
	t.Run("reserved port", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-reserved-port", PlacementLookupResponse{
			SandboxID: "sb-reserved-port",
			Placement: Placement{SandboxID: "sb-reserved-port", OwnerNodeID: "worker-self", State: PlacementStateReserved, IncarnationID: "inc-r"},
		}, true, opAddExposedPort)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-reserved-port", Spec: spec, ExposedPorts: ports,
		}}); err == nil {
			t.Fatal("expected reserved port failure")
		}
	})
	t.Run("reserved domain", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-reserved-host", PlacementLookupResponse{
			SandboxID: "sb-reserved-host",
			Placement: Placement{SandboxID: "sb-reserved-host", OwnerNodeID: "worker-self", State: PlacementStateReserved, IncarnationID: "inc-r"},
		}, true, opAddCustomDomain)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-reserved-host", Spec: spec, CustomHostnames: hosts,
		}}); err == nil {
			t.Fatal("expected reserved domain failure")
		}
	})

	owned := func(id string, seal int64) PlacementLookupResponse {
		return PlacementLookupResponse{
			SandboxID: id,
			Placement: Placement{SandboxID: id, OwnerNodeID: "worker-self", IncarnationID: "inc-o", SecretSealGeneration: seal},
		}
	}
	t.Run("backfill secret", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-backfill", owned("sb-backfill", 0), true, opUpsertSpec)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-backfill", Spec: spec, Secrets: PlacementSecrets{Version: 1, IncarnationID: "inc-o"},
		}}); err == nil {
			t.Fatal("expected secret backfill failure")
		}
	})
	t.Run("reseal", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-reseal", owned("sb-reseal", 1), true, opUpdateSecretRecipients)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID:      "sb-reseal",
			Secrets: PlacementSecrets{Version: 1, SealGeneration: 2, Recipients: []string{"peer"}, IncarnationID: "inc-o"},
		}}); err == nil {
			t.Fatal("expected reseal failure")
		}
	})
	t.Run("owned port", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-owned-port", owned("sb-owned-port", 1), true, opAddExposedPort)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-owned-port", ExposedPorts: ports, Secrets: PlacementSecrets{IncarnationID: "inc-o"},
		}}); err == nil {
			t.Fatal("expected owned port failure")
		}
	})
	t.Run("owned domain", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-owned-host", owned("sb-owned-host", 1), true, opAddCustomDomain)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-owned-host", CustomHostnames: hosts, Secrets: PlacementSecrets{IncarnationID: "inc-o"},
		}}); err == nil {
			t.Fatal("expected owned domain failure")
		}
	})

	orphan := func(id string) PlacementLookupResponse {
		return PlacementLookupResponse{
			SandboxID: id,
			Orphaned:  true,
			Placement: Placement{
				SandboxID: id, OwnerState: PlacementOwnerStateOrphaned,
				OrphanedOwnerNodeID: "worker-self", IncarnationID: "inc-or",
			},
		}
	}
	t.Run("claim", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-claim", orphan("sb-claim"), true, opClaimOrphan)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-claim", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-or"},
		}}); err == nil {
			t.Fatal("expected claim failure")
		}
	})
	t.Run("claim port", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-claim-port", orphan("sb-claim-port"), true, opAddExposedPort)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-claim-port", Spec: spec, ExposedPorts: ports, Secrets: PlacementSecrets{IncarnationID: "inc-or"},
		}}); err == nil {
			t.Fatal("expected claim port failure")
		}
	})
	t.Run("claim domain", func(t *testing.T) {
		agent := coverage97OwnershipAgent(t, "sb-claim-host", orphan("sb-claim-host"), true, opAddCustomDomain)
		if err := agent.AssertOwnership(context.Background(), []LocalSandboxState{{
			ID: "sb-claim-host", Spec: spec, CustomHostnames: hosts, Secrets: PlacementSecrets{IncarnationID: "inc-or"},
		}}); err == nil {
			t.Fatal("expected claim domain failure")
		}
	})
}

func TestCoverage97NoControlPlanePlacement(t *testing.T) {
	agent := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, _, _, err := agent.selectPlacement(SelectPlacementRequest{}); err == nil {
		t.Fatal("placement without a control plane succeeded")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			agent.logNoControlPlaneMembers(http.MethodGet, "/v1/cluster/members", "/v1/cluster/members")
		}()
	}
	close(start)
	wg.Wait()
}
