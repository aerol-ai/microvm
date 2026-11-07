package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Whenever the daemon wires the containerd warm pool it must also build the
// containerd driver with the ready socket on: park and adopt both refuse to
// run without it. A single-node host that turned on only
// SB_CONTAINERD_POOL_ENABLED used to get the pool (and its refill loop) but a
// driver with the socket off, so the pool never held a slot and never served a
// create (plan PR #1000, item L2).
func TestContainerdWarmPoolWiringTurnsOnReadySocket(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantPool  bool
		wantReady bool
	}{
		{
			name: "single node, containerd pool only",
			cfg: config.Config{
				ContainerEngine:          models.ContainerEngineContainerd,
				ContainerdPoolEnabled:    true,
				DockerReadySocketEnabled: true,
			},
			wantPool:  true,
			wantReady: true,
		},
		{
			name: "single node, pool off",
			cfg: config.Config{
				ContainerEngine:          models.ContainerEngineContainerd,
				DockerReadySocketEnabled: true,
			},
			wantPool:  false,
			wantReady: false,
		},
		{
			name: "single node, pool on, ready socket kill switch",
			cfg: config.Config{
				ContainerEngine:          models.ContainerEngineContainerd,
				ContainerdPoolEnabled:    true,
				DockerReadySocketEnabled: false,
			},
			wantPool:  false,
			wantReady: false,
		},
		{
			name: "cluster, pool off",
			cfg: config.Config{
				EnableCluster:            true,
				ContainerEngine:          models.ContainerEngineContainerd,
				DockerReadySocketEnabled: true,
			},
			wantPool:  false,
			wantReady: true,
		},
		{
			name: "cluster, pool on",
			cfg: config.Config{
				EnableCluster:            true,
				ContainerEngine:          models.ContainerEngineContainerd,
				ContainerdPoolEnabled:    true,
				DockerReadySocketEnabled: true,
			},
			wantPool:  true,
			wantReady: true,
		},
		{
			name: "docker engine ignores the containerd pool knob",
			cfg: config.Config{
				ContainerEngine:          models.ContainerEngineDocker,
				ContainerdPoolEnabled:    true,
				DockerReadySocketEnabled: true,
			},
			wantPool:  false,
			wantReady: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ContainerdPoolEffective(); got != tc.wantPool {
				t.Fatalf("ContainerdPoolEffective = %v, want %v", got, tc.wantPool)
			}
			if got := cntr.FromDaemonConfig(tc.cfg).ReadyEnabled; got != tc.wantReady {
				t.Fatalf("containerd driver ReadyEnabled = %v, want %v", got, tc.wantReady)
			}
			if tc.cfg.ContainerdPoolEffective() && !cntr.FromDaemonConfig(tc.cfg).ReadyEnabled {
				t.Fatal("warm pool wired but the driver it parks through has the ready socket off")
			}
		})
	}
}

// The refill loop parks through PoolSpawner.Park. On a single-node host with
// only the containerd pool on, the driver the daemon builds must get past the
// ready-socket gate (it then fails offline on the missing toolbox binary, which
// is fine here: the test only proves the gate no longer refuses every park).
func TestContainerdWarmPoolParkPassesReadyGateOnSingleNode(t *testing.T) {
	cfg := config.Config{
		ContainerEngine:             models.ContainerEngineContainerd,
		ContainerdPoolEnabled:       true,
		DockerReadySocketEnabled:    true,
		MountsCredentialsRuntimeDir: t.TempDir(),
		Runtime:                     models.RuntimeDocker,
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
	spawner := &cntr.PoolSpawner{Driver: driver}
	_, err := spawner.Park(context.Background(), "slot-l2", containerdpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker})
	if err == nil {
		t.Fatal("expected an offline park error (no toolbox binary), got nil")
	}
	if strings.Contains(err.Error(), "requires ready socket") {
		t.Fatalf("park refused by the ready-socket gate on a single-node containerd pool host: %v", err)
	}
}
