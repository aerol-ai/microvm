package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

// acceptingGateway attaches everything, so a gateway-mode create succeeds.
type acceptingGateway struct{ egress.Noop }

func (acceptingGateway) Attach(context.Context, egress.Spec) error { return nil }
func (acceptingGateway) Sync(context.Context, []egress.Spec) error { return nil }
func (acceptingGateway) Ready(context.Context) (egress.ReadyStatus, error) {
	return egress.ReadyStatus{}, nil
}

// TestCreateSandboxOnSelectedNodePinsBuiltinProfiles (P2-8, CEO D11): the
// native cluster create pins a bare built-in on the owner before promoting,
// so a failover replays the exact version.
func TestCreateSandboxOnSelectedNodePinsBuiltinProfiles(t *testing.T) {
	for _, reservationID := range []string{"sb-reserved", ""} {
		stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		h, _ := newClusterCreateHarnessWithConfig(t, &apiRecordingRuntime{}, stub, func(cfg *config.Config) { cfg.EgressFQDNEnabled = true })
		h.deps.Service.SetEgressGateway(acceptingGateway{}, nil)
		req := models.CreateSandboxRequest{Image: "alpine:3.20", EgressProfiles: []string{"builtin:pypi"}}
		rr := httptest.NewRecorder()
		h.createSandboxOnSelectedNode(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), req, reservationID)
		if rr.Code != http.StatusCreated {
			t.Fatalf("reservation %q: status = %d; body=%s", reservationID, rr.Code, rr.Body.String())
		}
		if len(stub.recordSpecs) != 1 || stub.recordSpecs[0] == nil ||
			!slices.Equal(stub.recordSpecs[0].EgressProfiles, []string{"builtin:pypi@20261006"}) {
			t.Fatalf("reservation %q: promoted specs = %+v", reservationID, stub.recordSpecs)
		}
	}
}
