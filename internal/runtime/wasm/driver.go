// Package wasm is the WASM/WASI runtime driver — the third implementation of
// internal/runtime.Runtime (after pkg/docker and internal/runtime/firecracker).
//
// Phase 1 lands the package as a skeleton: Driver implements every Runtime
// method; Create and most lifecycle entry points return
// models.ErrRuntimeNotImplemented until the cold path (Phase 2) wires wazero
// through the worker pool (pkg/wasm/worker). Ping and ListManaged are live so
// reconcile and /healthz behave on hosts with SB_ENABLE_WASM=true but zero
// sandboxes.
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

	mu   sync.Mutex
	byID map[string]*models.SandboxRuntimeState
}

// New constructs a WASM driver. The zero value is not usable.
func New(cfg Config, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Driver{
		cfg:    cfg,
		logger: logger,
		byID:   make(map[string]*models.SandboxRuntimeState),
	}
}

func (d *Driver) notImplemented(method string) error {
	return fmt.Errorf("wasm runtime: %s not implemented (see plans/wasm-runtime.md): %w",
		method, models.ErrRuntimeNotImplemented)
}

func (d *Driver) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, d.notImplemented("Create")
}

func (d *Driver) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, d.notImplemented("Start")
}

func (d *Driver) Stop(context.Context, string) error {
	return d.notImplemented("Stop")
}

func (d *Driver) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	d.mu.Lock()
	delete(d.byID, sandbox.ID)
	d.mu.Unlock()
	return nil
}

func (d *Driver) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", d.notImplemented("CreateSnapshot")
}

func (d *Driver) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return d.notImplemented("Resize")
}

func (d *Driver) Inspect(_ context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	state := d.byID[sandboxID]
	d.mu.Unlock()
	if state == nil {
		return nil, nil
	}
	out := *state
	return &out, nil
}

func (d *Driver) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(d.byID))
	for id, state := range d.byID {
		cp := *state
		out[id] = &cp
	}
	return out, nil
}

func (d *Driver) Ping(context.Context) error {
	if d.cfg.ModulesDir == "" {
		return fmt.Errorf("wasm runtime: modules dir not configured: %w", models.ErrRuntimeNotImplemented)
	}
	return nil
}

func (d *Driver) RemoveImage(context.Context, string) error {
	return d.notImplemented("RemoveImage")
}
