package clustercreate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/models"
)

func operatorFile(t *testing.T, body string) *operator.Watcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return operator.NewWatcher(path, nil, nil)
}

// TestPrepareSeesOperatorDefault (§5.10 PC-2): a hostname default needs the
// gateway, so placement must see it to pick a gateway-ready node.
func TestPrepareSeesOperatorDefault(t *testing.T) {
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), selectErr: cluster.ErrNoPlacementTarget}
	svc := testServiceWithCluster(stub)
	svc.SetEgressOperator(operatorFile(t, "version: 1\ndefault_policy: {mode: allowlist, allow_out: [pypi.org]}\n"))
	Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
		models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{})
	if len(stub.selectReqs) != 1 || !stub.selectReqs[0].NeedsEgressGateway {
		t.Fatalf("placement requests = %+v, want one needing the gateway", stub.selectReqs)
	}
}

// TestCreateOnSelectedNodeStoresOperatorDefault (§5.10 PC-2): the promoted
// spec carries the default, so a failover replay, which skips the default,
// still comes back shut.
func TestCreateOnSelectedNodeStoresOperatorDefault(t *testing.T) {
	stub := &clusterStub{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		placements: map[string]cluster.Placement{
			"sb-def": {SandboxID: "sb-def", OwnerNodeID: "node-a", IncarnationID: "inc-sb-def", State: cluster.PlacementStateReserved},
		},
	}
	svc, _ := newCreateService(t, stub, true)
	svc.SetEgressOperator(operatorFile(t, "version: 1\ndefault_policy: {mode: block_all}\n"))
	if _, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-def", CreateOptions{PromoteWithSpec: true}); err != nil {
		t.Fatalf("CreateOnSelectedNode: %v", err)
	}
	if len(stub.recordCalls) != 1 || stub.recordCalls[0].spec == nil || !stub.recordCalls[0].spec.NetworkBlockAll {
		t.Fatalf("promoted spec = %+v", stub.recordCalls)
	}

	// A create that says anything about egress keeps what it said.
	stub.placements["sb-own"] = cluster.Placement{SandboxID: "sb-own", OwnerNodeID: "node-a", IncarnationID: "inc-sb-own", State: cluster.PlacementStateReserved}
	own := models.CreateSandboxRequest{Image: "alpine:3.20", NetworkAllowOut: []string{"10.0.0.0/8"}}
	if _, err := CreateOnSelectedNode(context.Background(), svc, nil, own, "sb-own", CreateOptions{PromoteWithSpec: true}); err != nil {
		t.Fatalf("CreateOnSelectedNode: %v", err)
	}
	if spec := stub.recordCalls[1].spec; spec.NetworkBlockAll || !slices.Equal(spec.NetworkAllowOut, []string{"10.0.0.0/8"}) {
		t.Fatalf("explicit policy rewritten: %+v", spec)
	}
}
