package runtime_test

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/runtime/firecracker"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/docker"
)

func TestDockerClientSatisfiesContainerRuntime(t *testing.T) {
	var _ runtime.Runtime = (*docker.Client)(nil)
	var _ runtime.ContainerRuntime = (*docker.Client)(nil)
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
