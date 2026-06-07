package wasm

import (
	"context"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// ModuleResolver resolves a module reference to a local .wasm path.
type ModuleResolver interface {
	Resolve(ctx context.Context, ref string) (*wasmmod.ResolvedModule, error)
}

// WorkerSupervisor owns per-sandbox worker subprocesses.
type WorkerSupervisor interface {
	Ensure(ctx context.Context, sandboxID, socketPath string) error
	Stop(sandboxID string) error
}

// WorkerClient is the IPC surface the driver uses inside a worker subprocess.
type WorkerClient interface {
	Ping(sandboxID string) error
	LoadModule(sandboxID, path string) error
	Instantiate(sandboxID string, caps wasmengine.Capabilities) error
	Invoke(sandboxID, export string) error
	Exec(sandboxID string, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error)
	StopInstance(sandboxID string) error
	Checkpoint(sandboxID, outDir string, meta wasmengine.SnapshotConfig) error
	Restore(sandboxID, dir string, caps wasmengine.Capabilities) error
}

// WorkerClientFactory builds a client for a worker socket path.
type WorkerClientFactory func(socketPath string) WorkerClient

func defaultWorkerClientFactory(socketPath string) WorkerClient {
	return workerClientAdapter{client: worker.NewClient(socketPath)}
}

type workerClientAdapter struct {
	client *worker.Client
}

func (a workerClientAdapter) Ping(sandboxID string) error {
	return a.client.Ping(sandboxID)
}

func (a workerClientAdapter) LoadModule(sandboxID, path string) error {
	return a.client.LoadModule(sandboxID, path)
}

func (a workerClientAdapter) Instantiate(sandboxID string, caps wasmengine.Capabilities) error {
	return a.client.Instantiate(sandboxID, caps)
}

func (a workerClientAdapter) Invoke(sandboxID, export string) error {
	return a.client.Invoke(sandboxID, export)
}

func (a workerClientAdapter) Exec(sandboxID string, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	return a.client.Exec(sandboxID, caps, export)
}

func (a workerClientAdapter) StopInstance(sandboxID string) error {
	return a.client.StopInstance(sandboxID)
}

func (a workerClientAdapter) Checkpoint(sandboxID, outDir string, meta wasmengine.SnapshotConfig) error {
	return a.client.Checkpoint(sandboxID, outDir, meta)
}

func (a workerClientAdapter) Restore(sandboxID, dir string, caps wasmengine.Capabilities) error {
	return a.client.Restore(sandboxID, dir, caps)
}
