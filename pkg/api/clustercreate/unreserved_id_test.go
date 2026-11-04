package clustercreate

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A facade with a retry-stable id creating a local-only image gets no
// reservation from Prepare. CreateOptions.SandboxID must land the create
// under that id on the unreserved path (PR #641 review finding 4), instead
// of the facade passing the id as a reservation that does not exist.
func TestCreateOnSelectedNodeUnreservedUsesSandboxID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	local := models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest", ImageDistributionMode: models.ImageDistributionLocalOnly}

	t.Run("cluster", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, _ := newCreateService(t, stub, true)
		resp, err := CreateOnSelectedNode(context.Background(), svc, logger, local, "", CreateOptions{PromoteWithSpec: true, SandboxID: "sb-0123456789abcdef"})
		if err != nil {
			t.Fatalf("unreserved create with id: %v", err)
		}
		if resp.Sandbox.ID != "sb-0123456789abcdef" {
			t.Fatalf("sandbox id = %q, want the caller's id", resp.Sandbox.ID)
		}
	})

	// service.New always wires the single-node Noop client; embedded wiring
	// can run with no client at all. Both must honor the caller's id.
	for name, clearCluster := range map[string]bool{"single_node_noop": false, "no_cluster_client": true} {
		t.Run(name, func(t *testing.T) {
			svc, st := newCreateService(t, nil, true)
			if clearCluster {
				svc.ClearClusterForTest()
			}
			resp, err := CreateOnSelectedNode(context.Background(), svc, logger, local, "", CreateOptions{SandboxID: "sb-fedcba9876543210"})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if resp.Sandbox.ID != "sb-fedcba9876543210" {
				t.Fatalf("sandbox id = %q", resp.Sandbox.ID)
			}
			if _, err := st.Get(context.Background(), resp.Sandbox.ID); err != nil {
				t.Fatalf("created sandbox not stored under the caller's id: %v", err)
			}
		})
	}
}
