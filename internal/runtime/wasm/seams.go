package wasm

import (
	"context"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
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
	LoadModule(sandboxID, path string, memoryMB int) (wasmengine.LoadTimings, error)
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

// workerExecStream is a live streaming run on a worker (*worker.ExecStream).
type workerExecStream interface {
	Recv() (worker.ExecEvent, error)
	WriteStdin(p []byte) error
	CloseStdin() error
	Kill() error
	Close() error
}

// streamingWorkerClient is the optional streaming-exec surface of a worker
// client (issue #535). It is optional so test fakes written before it keep
// compiling; a client without it answers ErrStreamingUnsupported.
type streamingWorkerClient interface {
	StartExec(ctx context.Context, sandboxID string, p worker.ExecStartPayload) (workerExecStream, error)
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

// InstanceStatus also says whose instance the worker holds
// (instanceStatusReader).
func (a workerClientAdapter) InstanceStatus(ctx context.Context, sandboxID string) (worker.InstanceStatus, error) {
	return a.client.InstanceStatus(ctx, sandboxID)
}

func (a workerClientAdapter) LoadModule(sandboxID, path string, memoryMB int) (wasmengine.LoadTimings, error) {
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

// SetEgressPolicy is the optional live-update hook (egressPolicySetter).
func (a workerClientAdapter) SetEgressPolicy(sandboxID string, allowOut, denyOut []string, learn bool) error {
	return a.client.SetEgressPolicy(sandboxID, allowOut, denyOut, learn)
}

// EgressLearned reads a learn-mode recording (egressLearnReader).
func (a workerClientAdapter) EgressLearned(sandboxID string) (egresspolicy.Learned, error) {
	return a.client.EgressLearned(sandboxID)
}

func (a workerClientAdapter) SetListenPort(sandboxID string, port int, host string) error {
	return a.client.SetListenPort(sandboxID, port, host)
}

func (a workerClientAdapter) ResolvedListenPort(sandboxID string) (int, error) {
	return a.client.ResolvedListenPort(sandboxID)
}

// StartExec is the optional streaming-exec hook (streamingWorkerClient).
func (a workerClientAdapter) StartExec(ctx context.Context, sandboxID string, p worker.ExecStartPayload) (workerExecStream, error) {
	st, err := a.client.StartExec(ctx, sandboxID, p)
	if err != nil {
		// Never wrap a nil *ExecStream in a non-nil interface.
		return nil, err
	}
	return st, nil
}

// EntrypointLogs is the optional entrypoint hook (entrypointWorkerClient).
func (a workerClientAdapter) EntrypointLogs(ctx context.Context, sandboxID string, logs bool) (worker.EntrypointLogs, error) {
	return a.client.EntrypointLogs(ctx, sandboxID, logs)
}

// FollowEntrypoint is the optional entrypoint hook (entrypointWorkerClient).
func (a workerClientAdapter) FollowEntrypoint(ctx context.Context, sandboxID string) (worker.EntrypointLogs, workerExecStream, error) {
	logs, st, err := a.client.FollowEntrypoint(ctx, sandboxID)
	if st == nil {
		// Never wrap a nil *ExecStream in a non-nil interface.
		return logs, nil, err
	}
	return logs, st, err
}

func (a workerClientAdapter) ProxyHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	return a.client.ProxyHTTP(sandboxID, guestPort, w, r)
}

// SetListenPorts and ListenPorts give a guest one listener per exposed
// port (listenPortsClient).
func (a workerClientAdapter) SetListenPorts(sandboxID string, ports []int, host string) (worker.ListenPorts, error) {
	return a.client.SetListenPorts(sandboxID, ports, host)
}

func (a workerClientAdapter) ListenPorts(sandboxID string) (worker.ListenPorts, error) {
	return a.client.ListenPorts(sandboxID)
}
