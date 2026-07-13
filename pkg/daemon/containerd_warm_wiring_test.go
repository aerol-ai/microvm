package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWireContainerdWarmPoolDisabled(t *testing.T) {
	pool := wireContainerdWarmPool(context.Background(), config.Config{}, testLogger(), nil, nil)
	if pool != nil {
		t.Fatal("expected nil when pool disabled")
	}
}

func TestWireContainerdWarmPoolWarnsWhenReadySocketOff(t *testing.T) {
	pool := wireContainerdWarmPool(context.Background(), config.Config{
		ContainerEngine:          models.ContainerEngineContainerd,
		ContainerdPoolEnabled:    true,
		DockerReadySocketEnabled: false,
	}, testLogger(), nil, nil)
	if pool != nil {
		t.Fatal("expected nil when ready socket disabled")
	}
}

func TestWireContainerdWarmPoolEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	driver := cntr.New(cntr.FromDaemonConfig(config.Config{
		ContainerEngine: models.ContainerEngineContainerd,
	}), nil, testLogger())

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	pool := wireContainerdWarmPool(ctx, config.Config{
		ContainerEngine:              models.ContainerEngineContainerd,
		ContainerdPoolEnabled:        true,
		DockerReadySocketEnabled:     true,
		ContainerdPoolDepth:          1,
		ContainerdPoolRefillInterval: time.Hour,
		DockerRuntimeWaitTimeout:     time.Second,
		Runtime:                      models.RuntimeDocker,
		ContainerdPoolImages:         []string{"alpine:3.20"},
	}, testLogger(), driver, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	drainContainerdWarmPool(pool, testLogger())
	cancel()
}

func TestDrainContainerdWarmPoolNil(t *testing.T) {
	drainContainerdWarmPool(nil, testLogger())
}

func TestContainerdEngineWiringStopNil(t *testing.T) {
	var w *containerdEngineWiring
	w.Stop()
}
