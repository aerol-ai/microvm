package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWireDockerWarmPoolDisabled(t *testing.T) {
	pool := wireDockerWarmPool(context.Background(), config.Config{}, testLogger(), nil, nil)
	if pool != nil {
		t.Fatal("expected nil when pool disabled")
	}
}

func TestWireDockerWarmPoolWarnsWhenReadySocketOff(t *testing.T) {
	pool := wireDockerWarmPool(context.Background(), config.Config{
		DockerPoolEnabled:        true,
		DockerReadySocketEnabled: false,
	}, testLogger(), nil, nil)
	if pool != nil {
		t.Fatal("expected nil when ready socket disabled")
	}
}

func TestWireDockerWarmPoolEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	toolbox := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(toolbox, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := docker.New(testLogger(), config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxBinaryPath: toolbox,
		ToolboxPort:       2280,
		HTTPClientTimeout: time.Second,
	}, rules)
	if err != nil {
		t.Fatal(err)
	}

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
		DockerPoolImages:         []string{"alpine:3.20"},
	}, testLogger(), c, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	drainDockerWarmPool(pool, testLogger())
	cancel()
}

func TestDrainDockerWarmPoolNil(t *testing.T) {
	drainDockerWarmPool(nil, testLogger())
}
