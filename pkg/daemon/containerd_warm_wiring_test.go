package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
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

// The containerd warm pool must be wired into admission both ways: its ready
// slots count as reclaimable, and a real create that only fits by reclaiming
// them gets them. Without this wiring the fleet engine's pool fills the node
// and every non-pooled create (isolate, gvisor, another image) is refused.
func TestWireContainerdWarmPoolLetsAdmissionReclaimParkedSlots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	driver := cntr.New(cntr.FromDaemonConfig(config.Config{
		ContainerEngine: models.ContainerEngineContainerd,
	}), nil, testLogger())
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 2, MemoryTotalMB: 2048, SupportedRuntimes: []string{models.RuntimeDocker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	pool := wireContainerdWarmPool(ctx, config.Config{
		ContainerEngine:              models.ContainerEngineContainerd,
		ContainerdPoolEnabled:        true,
		DockerReadySocketEnabled:     true,
		ContainerdPoolDepth:          2,
		ContainerdPoolRefillInterval: time.Hour,
		DockerRuntimeWaitTimeout:     time.Second,
		Runtime:                      models.RuntimeDocker,
	}, testLogger(), driver, admitter)
	if pool == nil {
		t.Fatal("expected pool")
	}
	defer drainContainerdWarmPool(pool, testLogger())

	// What a refill tick does: reserve under park:<id>, then record the slot.
	// The slots carry no container, so the background teardown is a no-op.
	key := containerdpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	for _, id := range []string{"park-a", "park-b"} {
		if err := admitter.Admit(capacity.ParkReservationID(id), capacity.Request{CPU: 1, MemoryMB: 1024}); err != nil {
			t.Fatalf("park %s: %v", id, err)
		}
		pool.RecordLoaded(&containerdpool.ParkedSlot{ID: id, Key: key, Handle: &stubParkHandle{alive: true}})
	}
	if snap := admitter.Snapshot(); snap.ParkedSlots != 2 || !snap.CanAdmit {
		t.Fatalf("parked %d, can_admit %v; want 2 reclaimable slots on a host that still admits", snap.ParkedSlots, snap.CanAdmit)
	}

	if err := admitter.Admit("sb-isolate", capacity.Request{CPU: 1, MemoryMB: 1024, Runtime: models.RuntimeDocker}); err != nil {
		t.Fatalf("a real create on a pool-filled host = %v, want it admitted by reclaiming a slot", err)
	}
	if snap := admitter.Snapshot(); snap.ParkedSlots != 1 || snap.ReservedCPU != 2 {
		t.Fatalf("after reclaim: parked %d, reserved %.0f; want 1 slot kept and the sandbox reserved", snap.ParkedSlots, snap.ReservedCPU)
	}
}
