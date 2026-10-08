package clustercreate

import (
	"context"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

// acceptingGateway attaches everything, so a gateway-mode create succeeds.
type acceptingGateway struct{ egress.Noop }

func (acceptingGateway) Attach(context.Context, egress.Spec) error         { return nil }
func (acceptingGateway) BlockGen(context.Context) (uint64, error)          { return 0, nil }
func (acceptingGateway) Sync(context.Context, []egress.Spec, uint64) error { return nil }
func (acceptingGateway) Ready(context.Context) (egress.ReadyStatus, error) {
	return egress.ReadyStatus{}, nil
}

// TestCreateOnSelectedNodePinsBuiltinProfiles (P2-8, CEO D11): the owner
// pins a bare built-in before promoting, so the replicated spec a failover
// replays names the exact version, never "whatever the new node ships".
func TestCreateOnSelectedNodePinsBuiltinProfiles(t *testing.T) {
	stub := &clusterStub{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placements: map[string]cluster.Placement{
			"sb-pin": {SandboxID: "sb-pin", OwnerNodeID: "node-a", IncarnationID: "inc-sb-pin", State: cluster.PlacementStateReserved},
		},
	}
	svc, _ := newCreateServiceWithConfig(t, stub, newFakeRuntime(), true, func(cfg *config.Config) { cfg.EgressFQDNEnabled = true })
	svc.SetEgressGateway(acceptingGateway{}, nil)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", EgressProfiles: []string{"builtin:pypi"}}
	if _, err := CreateOnSelectedNode(context.Background(), svc, nil, req, "sb-pin", CreateOptions{PromoteWithSpec: true}); err != nil {
		t.Fatalf("CreateOnSelectedNode: %v", err)
	}
	if len(stub.recordCalls) != 1 || stub.recordCalls[0].spec == nil {
		t.Fatalf("RecordPlacement calls = %+v", stub.recordCalls)
	}
	if got := stub.recordCalls[0].spec.EgressProfiles; !slices.Equal(got, []string{"builtin:pypi@20261006"}) {
		t.Fatalf("promoted spec profiles = %v", got)
	}
	if req.EgressProfiles[0] != "builtin:pypi" {
		t.Fatal("the caller's request must not be rewritten")
	}
}
