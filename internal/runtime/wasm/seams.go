package wasm

import (
	"context"
	"net/http"

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

type WorkerSupervisorSpawnCounter interface {
	SpawnCount(sandboxID string) int
}

// WorkerClient is the IPC surface the driver uses inside a worker subprocess.
type WorkerClient interface {
	Ping(sandboxID string) error
	InstanceLoaded(ctx context.Context, sandboxID string) (bool, error)
	LoadModule(sandboxID, path string, memoryMB int) error
	Instantiate(sandboxID string, caps wasmengine.Capabilities) error
	Invoke(sandboxID, export string) error
	Exec(sandboxID string, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error)
	StopInstance(sandboxID string) error
	Checkpoint(ctx context.Context, sandboxID, outDir string, meta wasmengine.SnapshotConfig) error
	Restore(sandboxID, dir string, caps wasmengine.Capabilities) error
	SetCapability(sandboxID string, caps wasmengine.Capabilities) error
	NetstatsTick(sandboxID string) (bytesIn, bytesOut int64, err error)
	SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) error
	SetListenPort(sandboxID string, port int, host string) error
	ResolvedListenPort(sandboxID string) (int, error)
	ProxyHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error
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

func (a workerClientAdapter) InstanceLoaded(ctx context.Context, sandboxID string) (bool, error) {
	return a.client.InstanceLoaded(ctx, sandboxID)
}

func (a workerClientAdapter) LoadModule(sandboxID, path string, memoryMB int) error {
	return a.client.LoadModule(sandboxID, path, memoryMB)
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

func (a workerClientAdapter) Checkpoint(ctx context.Context, sandboxID, outDir string, meta wasmengine.SnapshotConfig) error {
	return a.client.Checkpoint(ctx, sandboxID, outDir, meta)
}

func (a workerClientAdapter) Restore(sandboxID, dir string, caps wasmengine.Capabilities) error {
	return a.client.Restore(sandboxID, dir, caps)
}

func (a workerClientAdapter) SetCapability(sandboxID string, caps wasmengine.Capabilities) error {
	return a.client.SetCapability(sandboxID, caps)
}

func (a workerClientAdapter) NetstatsTick(sandboxID string) (int64, int64, error) {
	return a.client.NetstatsTick(sandboxID)
}

func (a workerClientAdapter) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) error {
	return a.client.SetNetworkBlocks(sandboxID, blockIngress, blockEgress)
}

func (a workerClientAdapter) SetListenPort(sandboxID string, port int, host string) error {
	return a.client.SetListenPort(sandboxID, port, host)
}

func (a workerClientAdapter) ResolvedListenPort(sandboxID string) (int, error) {
	return a.client.ResolvedListenPort(sandboxID)
}

func (a workerClientAdapter) ProxyHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	return a.client.ProxyHTTP(sandboxID, guestPort, w, r)
}
