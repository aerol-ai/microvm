package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
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

// TestPoolImageResolvers (W3): each engine's resolver asks its engine for
// the key's image, so an unreachable engine is an error the pool keeps its
// slots on, never an empty ID.
func TestPoolImageResolvers(t *testing.T) {
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(t.TempDir(), "no-docker.sock"))
	toolbox := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(toolbox, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := docker.New(testLogger(), config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxBinaryPath: toolbox,
		HTTPClientTimeout: time.Second,
	}, rules)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if id, err := dockerPoolImageResolver(c)(ctx, dockerpool.Key{Image: "alpine:3.20"}); err == nil || id != "" {
		t.Fatalf("docker resolver with no engine = %q %v", id, err)
	}
	d := cntr.New(cntr.Config{Socket: filepath.Join(t.TempDir(), "no-containerd.sock")}, nil, nil)
	if id, err := containerdPoolImageResolver(d)(ctx, dockerpool.Key{Image: "alpine:3.20"}); err == nil || id != "" {
		t.Fatalf("containerd resolver with no engine = %q %v", id, err)
	}
}
