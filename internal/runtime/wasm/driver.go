// Package wasm is the WASM/WASI runtime driver — the third implementation of
// internal/runtime.Runtime (after pkg/docker and internal/runtime/firecracker).
package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/statekv"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Driver implements runtime.Runtime for WASM sandboxes. WASM satisfies only the
// core Runtime interface — not ContainerRuntime (host-mediated networking).
type Driver struct {
	cfg    Config
	logger *slog.Logger

	resolver        ModuleResolver
	supervisor      WorkerSupervisor
	newWorkerClient WorkerClientFactory
	net             *networkGateway
	warmPool        WarmPool
	stateKV         statekv.Store
	// waitListenReady overrides guest TCP readiness polling (tests).
	waitListenReady func(host string, port int) error

	mu   sync.Mutex
	byID map[string]*sandboxInstance

	rehydrate sync.Map // sandboxID -> *sync.Mutex single-flight gates
}

// New constructs a WASM driver. The zero value is not usable.
func New(cfg Config, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Driver{
		cfg:             cfg,
		logger:          logger,
		newWorkerClient: defaultWorkerClientFactory,
		byID:            make(map[string]*sandboxInstance),
	}
	d.net = newNetworkGateway()
	d.net.SetHTTPProxy(d.guestHTTPProxy)
	return d
}

// SetModuleResolver injects the module resolver (pkg/wasmmod.Resolver in production).
func (d *Driver) SetModuleResolver(r ModuleResolver) {
	d.resolver = r
}

// SetWorkerSupervisor injects the worker subprocess supervisor.
func (d *Driver) SetWorkerSupervisor(s WorkerSupervisor) {
	d.supervisor = s
}

// SetWorkerClientFactory overrides worker IPC for tests.
func (d *Driver) SetWorkerClientFactory(f WorkerClientFactory) {
	if f != nil {
		d.newWorkerClient = f
	}
}

// SetStateKV wires the durable host-KV store (§4.6).
func (d *Driver) SetStateKV(kv statekv.Store) {
	d.stateKV = kv
}

func (d *Driver) CreateSnapshot(ctx context.Context, sandboxID, _ string) (string, error) {
	sb := &models.Sandbox{ID: sandboxID}
	path, _, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		return "", err
	}
	return path, nil
}

func (d *Driver) Inspect(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		return nil, nil
	}
	inst = d.refreshWorkerInstanceState(ctx, sandboxID, inst)
	return d.runtimeState(inst), nil
}

func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	instances := make(map[string]*sandboxInstance, len(d.byID))
	for id, inst := range d.byID {
		instances[id] = inst
	}
	d.mu.Unlock()

	out := make(map[string]*models.SandboxRuntimeState, len(instances))
	for id, inst := range instances {
		inst = d.refreshWorkerInstanceState(ctx, id, inst)
		if inst == nil {
			continue
		}
		out[id] = d.runtimeState(inst)
	}
	return out, nil
}

func (d *Driver) refreshWorkerInstanceState(ctx context.Context, sandboxID string, inst *sandboxInstance) *sandboxInstance {
	if inst == nil || strings.TrimSpace(inst.socketPath) == "" {
		return inst
	}
	if count, ok := d.supervisorSpawnCount(d.workerKeyForInstance(sandboxID, inst)); ok {
		if inst.workerSpawnCount > 0 && count != inst.workerSpawnCount {
			return d.markWorkerInstanceStopped(sandboxID, inst)
		}
		if inst.workerSpawnCount == 0 && count > 0 {
			d.mu.Lock()
			if current := d.byID[sandboxID]; current == inst {
				current.workerSpawnCount = count
				inst = current
			}
			d.mu.Unlock()
		}
		return inst
	}
	statusCtx := ctx
	if statusCtx == nil {
		statusCtx = context.Background()
	}
	if _, ok := statusCtx.Deadline(); !ok {
		var cancel context.CancelFunc
		statusCtx, cancel = context.WithTimeout(statusCtx, 2*time.Second)
		defer cancel()
	}
	loaded, err := d.newWorkerClient(inst.socketPath).InstanceLoaded(statusCtx, sandboxID)
	if err != nil || loaded {
		return inst
	}
	return d.markWorkerInstanceStopped(sandboxID, inst)
}

func (d *Driver) markWorkerInstanceStopped(sandboxID string, inst *sandboxInstance) *sandboxInstance {
	d.mu.Lock()
	defer d.mu.Unlock()
	current := d.byID[sandboxID]
	if current != inst {
		return current
	}
	if current.status == models.SandboxStatusStarted || current.status == models.SandboxStatusCreating {
		current.status = models.SandboxStatusStopped
	}
	return current
}

func (d *Driver) supervisorSpawnCount(workerKey string) (int, bool) {
	if d == nil || d.supervisor == nil {
		return 0, false
	}
	counter, ok := d.supervisor.(WorkerSupervisorSpawnCounter)
	if !ok {
		return 0, false
	}
	return counter.SpawnCount(workerKey), true
}

func (d *Driver) workerKeyForInstance(sandboxID string, inst *sandboxInstance) string {
	if inst != nil && strings.TrimSpace(inst.workerKey) != "" {
		return inst.workerKey
	}
	return sandboxID
}

func (d *Driver) noteWorkerSpawnCount(inst *sandboxInstance) {
	if inst == nil {
		return
	}
	key := d.workerKeyForInstance(inst.sandboxID, inst)
	if count, ok := d.supervisorSpawnCount(key); ok {
		inst.workerSpawnCount = count
	}
}

func (d *Driver) Ping(context.Context) error {
	if d.cfg.ModulesDir == "" {
		return fmt.Errorf("wasm runtime: modules dir not configured: %w", models.ErrRuntimeNotImplemented)
	}
	if d.resolver == nil || d.supervisor == nil {
		return fmt.Errorf("wasm runtime: driver not fully wired: %w", models.ErrRuntimeNotImplemented)
	}
	return nil
}

// Ensure Driver still satisfies runtime.Runtime at compile time.
var _ interface {
	Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
	Start(context.Context, string) (*models.SandboxRuntimeState, error)
	Stop(context.Context, string) error
	Destroy(context.Context, *models.Sandbox) error
} = (*Driver)(nil)
