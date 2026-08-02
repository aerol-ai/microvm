package runtime_test

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	containerdruntime "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/runtime/firecracker"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/docker"
)

func TestDockerClientSatisfiesContainerRuntime(t *testing.T) {
	var _ runtime.Runtime = (*docker.Client)(nil)
	var _ runtime.ContainerRuntime = (*docker.Client)(nil)
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
