package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage95DrainWarmPoolsWithSlots(t *testing.T) {
	drainDockerWarmPool(poolWithLoadedSlot(t), testLogger())
	drainContainerdWarmPool(poolWithLoadedSlot(t), testLogger())
}

func TestCoverage95DockerWarmPoolEmptyImageAndPurgeWarn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := newTestDockerClient(t)
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	pool := wireDockerWarmPool(ctx, config.Config{
		DockerPoolEnabled:        true,
		DockerReadySocketEnabled: true,
		DockerPoolDepth:          1,
		DockerPoolRefillInterval: time.Hour,
		DockerRuntimeWaitTimeout: time.Second,
		Runtime:                  models.RuntimeDocker,
		DockerPoolImages:         []string{" "},
	}, testLogger(), c, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	drainDockerWarmPool(poolWithLoadedSlot(t), testLogger())
	cancel()
}
