package runtime_test

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	containerdruntime "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/runtime/firecracker"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/docker"
)

func TestAsToolboxAddresserAbsent(t *testing.T) {
	if _, ok := runtime.AsToolboxAddresser(nil); ok {
		t.Fatal("nil runtime has no toolbox address")
	}
}

func TestDockerClientSatisfiesContainerRuntime(t *testing.T) {
	var _ runtime.Runtime = (*docker.Client)(nil)
	var _ runtime.ContainerRuntime = (*docker.Client)(nil)
}

// Docker and containerd re-adopt a warm-pool container on start (it keeps
// the pool's parked env for life); Firecracker re-adopts a guest restored
// from its stopped snapshot (its agent serves nothing without the sandbox's
// token). The service has to find StartWithIdentity on each of them.
func TestContainerAndFirecrackerDriversStartWithIdentity(t *testing.T) {
	var _ runtime.IdentityStarter = (*docker.Client)(nil)
	var _ runtime.IdentityStarter = (*firecracker.Driver)(nil)
	var _ runtime.IdentityStarter = (*containerdruntime.Driver)(nil)
	for name, rt := range map[string]runtime.Runtime{
		"docker": (*docker.Client)(nil), "firecracker": (*firecracker.Driver)(nil),
		"containerd": (*containerdruntime.Driver)(nil),
	} {
		if _, ok := runtime.AsIdentityStarter(rt); !ok {
			t.Fatalf("%s must start with the sandbox's identity", name)
		}
	}
	if _, ok := runtime.AsIdentityStarter((*wasmruntime.Driver)(nil)); ok {
		t.Error("wasm unexpectedly starts with an identity")
	}
}

// Only containerd's warm pool hands a create's env to the toolbox in the
// adopt frame rather than the container spec, so only its start re-sends
// the env on a re-adopt. Docker keeps env off its pool, and a Firecracker
// guest restored from its snapshot still holds its env in memory.
func TestOnlyContainerdStartsWithIdentityEnv(t *testing.T) {
	var _ runtime.EnvIdentityStarter = (*containerdruntime.Driver)(nil)
	if _, ok := runtime.AsEnvIdentityStarter((*containerdruntime.Driver)(nil)); !ok {
		t.Fatal("containerd must re-send the env on a re-adopt")
	}
	for name, rt := range map[string]runtime.Runtime{
		"docker": (*docker.Client)(nil), "firecracker": (*firecracker.Driver)(nil), "wasm": (*wasmruntime.Driver)(nil),
	} {
		if _, ok := runtime.AsEnvIdentityStarter(rt); ok {
			t.Errorf("%s now re-sends env on start: check its pool's env eligibility", name)
		}
	}
}

// The ownership fence freezes in place where the runtime can: the two
// container engines, and Firecracker, each VM in its own group, which it
// also names for the runtime supervisor (FenceGrouper, review N2). WASM
// and isolate cannot: the fence only refuses their sandboxes, and on a
// Kubernetes worker a recreate-policy create of them is refused. This pins
// which is which.
func TestFreezerOptIn(t *testing.T) {
	var _ runtime.Freezer = (*docker.Client)(nil)
	var _ runtime.Freezer = (*containerdruntime.Driver)(nil)
	var _ runtime.Freezer = (*firecracker.Driver)(nil)
	var _ runtime.FenceGrouper = (*firecracker.Driver)(nil)
	for name, rt := range map[string]runtime.Runtime{
		"wasm": (*wasmruntime.Driver)(nil),
	} {
		if _, ok := rt.(runtime.Freezer); ok {
			t.Errorf("%s now implements Freezer: drop it from the fence's refuse-only list", name)
		}
		if _, ok := rt.(runtime.FenceGrouper); ok {
			t.Errorf("%s now names a fence group: let refuseUnfencedRecreate accept it", name)
		}
	}
}

func TestContainerdDriverSatisfiesContainerRuntime(t *testing.T) {
	var _ runtime.Runtime = (*containerdruntime.Driver)(nil)
	var _ runtime.ContainerRuntime = (*containerdruntime.Driver)(nil)
}

func TestFirecrackerDriverSatisfiesContainerRuntime(t *testing.T) {
	var _ runtime.Runtime = (*firecracker.Driver)(nil)
	var _ runtime.ContainerRuntime = (*firecracker.Driver)(nil)
}

func TestWasmDriverSatisfiesRuntimeOnly(t *testing.T) {
	var _ runtime.Runtime = (*wasmruntime.Driver)(nil)
	if _, ok := runtime.AsContainerRuntime((*wasmruntime.Driver)(nil)); ok {
		t.Fatal("wasm driver must not implement ContainerRuntime")
	}
}

// TestNetworkBlockReporterOptIn pins which drivers can answer "was the
// isolation rule actually missing?". Docker and containerd are netrules-backed
// so they report; Firecracker doesn't implement per-IP rules at all and must
// fall through to the plain ApplyNetworkBlockAll path rather than silently
// reporting a bogus false-as-fact. The reconcile drift counter depends on this
// split — a driver that opted in without a real answer would fabricate the
// metric.
func TestNetworkBlockReporterOptIn(t *testing.T) {
	var _ runtime.NetworkBlockReporter = (*docker.Client)(nil)
	var _ runtime.NetworkBlockReporter = (*containerdruntime.Driver)(nil)

	if _, ok := runtime.AsNetworkBlockReporter((*docker.Client)(nil)); !ok {
		t.Error("docker client must implement NetworkBlockReporter")
	}
	if _, ok := runtime.AsNetworkBlockReporter((*containerdruntime.Driver)(nil)); !ok {
		t.Error("containerd driver must implement NetworkBlockReporter")
	}
	if _, ok := runtime.AsNetworkBlockReporter((*firecracker.Driver)(nil)); ok {
		t.Error("firecracker driver must not claim NetworkBlockReporter; it has no per-IP rules to report on")
	}
}
