// Package wasm is the WASM/WASI runtime driver — the third implementation of
// internal/runtime.Runtime (after pkg/docker and internal/runtime/firecracker).
package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

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

	mu   sync.Mutex
	byID map[string]*sandboxInstance
}

// New constructs a WASM driver. The zero value is not usable.
func New(cfg Config, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Driver{
		cfg:             cfg,
		logger:          logger,
		newWorkerClient: defaultWorkerClientFactory,
		net:             newNetworkGateway(),
		byID:            make(map[string]*sandboxInstance),
	}
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

func (d *Driver) notImplemented(method string) error {
	return fmt.Errorf("wasm runtime: %s not implemented (see plans/wasm-runtime.md): %w",
		method, models.ErrRuntimeNotImplemented)
}

func (d *Driver) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", d.notImplemented("CreateSnapshot")
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

func (d *Driver) RemoveImage(context.Context, string) error {
	return d.notImplemented("RemoveImage")
}

// Ensure Driver still satisfies runtime.Runtime at compile time.
var _ interface {
	Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
	Start(context.Context, string) (*models.SandboxRuntimeState, error)
	Stop(context.Context, string) error
	Destroy(context.Context, *models.Sandbox) error
} = (*Driver)(nil)
