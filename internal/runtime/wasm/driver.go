// Package wasm is the WASM/WASI runtime driver — the third implementation of
// internal/runtime.Runtime (after pkg/docker and internal/runtime/firecracker).
package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

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

func (d *Driver) Inspect(_ context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		return nil, nil
	}
	return d.runtimeState(inst), nil
}

func (d *Driver) ListManaged(_ context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(d.byID))
	for id, inst := range d.byID {
		out[id] = d.runtimeState(inst)
	}
	return out, nil
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
