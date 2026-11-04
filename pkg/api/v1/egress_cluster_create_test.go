package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/models"
)

// acceptingGateway attaches everything, so a gateway-mode create succeeds.
type acceptingGateway struct{ egress.Noop }

func (acceptingGateway) Attach(context.Context, egress.Spec) error { return nil }
func (acceptingGateway) SyncToken(context.Context) (egress.SyncToken, error) {
	return egress.SyncToken{Epoch: 1}, nil
}
func (acceptingGateway) Sync(context.Context, []egress.Spec, egress.SyncToken) error { return nil }
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

// TestCreateSandboxOnSelectedNodeStoresOperatorDefault (§5.10 PC-2): the
// native cluster create promotes a spec carrying the operator default, so a
// failover replay, which skips the default, still comes back shut.
func TestCreateSandboxOnSelectedNodeStoresOperatorDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndefault_policy: {mode: block_all}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, reservationID := range []string{"sb-reserved", ""} {
		stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, stub)
		h.deps.Service.SetEgressOperator(operator.NewWatcher(path, nil, nil))
		rr := httptest.NewRecorder()
		h.createSandboxOnSelectedNode(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), models.CreateSandboxRequest{Image: "alpine:3.20"}, reservationID)
		if rr.Code != http.StatusCreated {
			t.Fatalf("reservation %q: status = %d; body=%s", reservationID, rr.Code, rr.Body.String())
		}
		if len(stub.recordSpecs) != 1 || stub.recordSpecs[0] == nil || !stub.recordSpecs[0].NetworkBlockAll {
			t.Fatalf("reservation %q: promoted specs = %+v", reservationID, stub.recordSpecs)
		}
	}
}
