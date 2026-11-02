package cluster

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression for the 2026-11-02 docker-engine density run: a docker-engine
// worker's sandbox bridge holds 1,023 ports, and it now advertises them as
// the docker_bridge pool. Placement matches pools by runtime, so a worker
// whose bridge is full is skipped for runc and gVisor (they share it) but
// still takes Firecracker, and an all-full fleet answers "at capacity".
func bridgePool(total, free int) capacity.SlotPool {
	return capacity.SlotPool{Name: capacity.SlotPoolDockerBridge, Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor}, Total: total, Free: free}
}

func TestSelectPlacementSkipsDockerEngineWorkerWhoseBridgeIsFull(t *testing.T) {
	metal := slotWorker("worker-metal", 48, containerAndFC, bridgePool(1000, 0), tapPool(256, 10))
	small := slotWorker("worker-small", 4, containerAndFC, bridgePool(1000, 600), tapPool(256, 0))
	c := slotCluster(metal, small)
	for _, tc := range []struct{ runtime, want string }{
		{models.RuntimeDocker, "worker-small"},
		{models.RuntimeGvisor, "worker-small"},
		{models.RuntimeFirecracker, "worker-metal"},
	} {
		for i := 0; i < 20; i++ {
			target, err := c.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: tc.runtime})
			if err != nil {
				t.Fatalf("%s: %v", tc.runtime, err)
			}
			if target.NodeID != tc.want {
				t.Fatalf("%s placed on %s, want %s (the other worker's bridge is full)", tc.runtime, target.NodeID, tc.want)
			}
		}
	}

	full := slotCluster(
		slotWorker("worker-a", 48, containerAndFC, bridgePool(1000, 0)),
		slotWorker("worker-b", 48, containerAndFC, bridgePool(1000, 0)),
	)
	if _, err := full.SelectPlacement(capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker}); !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("every bridge full = %v, want ErrClusterAtCapacity", err)
	}
}
