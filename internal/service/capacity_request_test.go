package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCapacityRequestFromSandboxIncludesAllPlacementAxes(t *testing.T) {
	sb := &models.Sandbox{
		CPU:      2,
		MemoryMB: 4096,
		DiskGB:   50,
		Runtime:  "gvisor",
		GPUs:     &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 2},
	}

	got := capacityRequestFromSandbox(sb)

	if got.CPU != 2 || got.MemoryMB != 4096 || got.DiskGB != 50 || got.Runtime != "gvisor" || got.GPUs != 2 || got.GPUVendor != "nvidia" {
		t.Fatalf("capacity request = %+v, want all CPU/memory/disk/runtime/GPU axes populated", got)
	}
}

func TestCreateSandboxRejectsPureServerClusterNode(t *testing.T) {
	svc := New(
		config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil, nil, nil, nil, nil, nil, nil,
	)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"})
	if !errors.Is(err, cluster.ErrNoPlacementTarget) {
		t.Fatalf("CreateSandbox error = %v, want ErrNoPlacementTarget", err)
	}
}
