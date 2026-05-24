package service

import (
	"context"
	"errors"
	"fmt"
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

func TestCreateSandboxRejectsInvalidLargeClusterTopology(t *testing.T) {
	svc := New(
		config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil, nil, nil, nil, nil, nil, nil,
	)
	svc.AttachCluster(&topologyCluster{
		Noop: cluster.NewNoop("node-01", "http://node-01", ""),
		members: []cluster.Member{
			{NodeID: "server-1", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "server-2", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "server-3", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "worker-1", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-2", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-3", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-4", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-5", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-6", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "ingress-1", Role: config.NodeRoleIngress, Alive: true},
			{NodeID: "edge-1", Role: "worker,ingress", Alive: true},
		},
	})

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"})
	if !errors.Is(err, cluster.ErrInvalidTopology) {
		t.Fatalf("CreateSandbox error = %v, want ErrInvalidTopology", err)
	}
}

func TestClusterTopologyRequiresShardAwareIngressForLargeIngressTier(t *testing.T) {
	members := []cluster.Member{
		{NodeID: "server-1", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "server-2", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "server-3", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "worker-1", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "worker-2", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "worker-3", Role: config.NodeRoleWorker, Alive: true},
	}
	for i := 0; i < cluster.MaxReplicatedIngressRouteNodes+1; i++ {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("ingress-%02d", i),
			Role:   config.NodeRoleIngress,
			Alive:  true,
		})
	}

	svc := New(
		config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil, nil, nil, nil, nil, nil, nil,
	)
	svc.AttachCluster(&topologyCluster{Noop: cluster.NewNoop("worker-1", "http://worker-1", ""), members: members})

	err := svc.ClusterTopologyError()
	if !errors.Is(err, cluster.ErrInvalidTopology) {
		t.Fatalf("ClusterTopologyError = %v, want ErrInvalidTopology", err)
	}

	svc.cfg.ClusterShardAwareIngress = true
	if err := svc.ClusterTopologyError(); err != nil {
		t.Fatalf("ClusterTopologyError with shard-aware ingress = %v, want nil", err)
	}
}

type topologyCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *topologyCluster) Members() []cluster.Member {
	return c.members
}
