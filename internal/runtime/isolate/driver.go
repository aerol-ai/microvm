// Package isolate is the V8-isolate (Workers-model) runtime driver — the
// fifth implementation of internal/runtime.Runtime, after pkg/docker (docker +
// gvisor), internal/runtime/firecracker, and internal/runtime/wasm
// (plans/isolate-runtime.md).
//
// Like WASM, the isolate runtime is host-mediated: it satisfies only the core
// Runtime interface, never ContainerRuntime. Isolates get no IP, no TAP/veth,
// and no per-IP iptables — egress policy is enforced by a host-side proxy the
// driver owns, and inbound HTTP is proxied to the isolate's fetch handler.
//
// Phase 1 (this file) is the dispatch skeleton: every lifecycle method
// returns models.ErrRuntimeNotImplemented so the service layer's fifth
// dispatch branch, daemon wiring, and store schema can land and be proven
// stable before the engine work (Phase 2: pkg/isolate + pkg/jsbundle).
package isolate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Driver implements runtime.Runtime for isolate sandboxes. Isolate satisfies
// only the core Runtime interface — not ContainerRuntime (host-mediated
// networking, same posture as WASM).
type Driver struct {
	cfg    Config
	logger *slog.Logger

	resolver BundleResolver
	warmPool WarmPool

	mu   sync.Mutex
	byID map[string]*models.SandboxRuntimeState
}

// New constructs an isolate driver. The zero value is not usable.
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

// SetBundleResolver injects the JS/TS bundle resolver (pkg/jsbundle in
// production, Phase 2).
func (d *Driver) SetBundleResolver(r BundleResolver) {
	d.resolver = r
}

// SetWarmPool injects the blank-workerd-host pool (internal/pool/isolate,
// Phase 3). Nil (the default) keeps every first-create on the cold spawn path.
func (d *Driver) SetWarmPool(p WarmPool) {
	d.warmPool = p
}

// notImplemented wraps models.ErrRuntimeNotImplemented with the operation so
// an operator seeing the error in a log can tell which call hit the skeleton.
func notImplemented(op string) error {
	return fmt.Errorf("isolate runtime %s: pending plans/isolate-runtime.md Phase 2: %w", op, models.ErrRuntimeNotImplemented)
}

func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, notImplemented("create")
}

func (d *Driver) Start(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	return nil, notImplemented("start")
}

func (d *Driver) Stop(ctx context.Context, sandboxID string) error {
	return notImplemented("stop")
}

// Destroy removes the sandbox's isolate and, when it was the group's last
// member, the group process (Phase 2). Nil is a no-op per the Runtime
// contract — cleanup paths may not have a sandbox record yet.
func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	return notImplemented("destroy")
}

// CreateSnapshot is unsupported by design, not just unimplemented: V8 exposes
// no serialize-a-running-isolate API, so the warm pool is the plan of record
// and any snapshot phase requires an upstream feasibility spike first
// (plans/isolate-runtime.md §4, §13 Q6).
func (d *Driver) CreateSnapshot(ctx context.Context, sandboxID, imageRef string) (string, error) {
	return "", fmt.Errorf("isolate runtime does not support snapshots (plans/isolate-runtime.md §4): %w", models.ErrRuntimeNotImplemented)
}

func (d *Driver) Resize(ctx context.Context, sandboxID string, req models.ResizeSandboxRequest) error {
	return notImplemented("resize")
}

func (d *Driver) Inspect(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	state := d.byID[sandboxID]
	d.mu.Unlock()
	if state == nil {
		return nil, nil
	}
	return state, nil
}

// ListManaged returns the runtime state of every isolate this daemon owns.
// Phase 1 manages none (Create always rejects), so reconcile sees an empty
// map and correctly terminal-izes any stray rows rather than erroring.
func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(d.byID))
	for id, state := range d.byID {
		out[id] = state
	}
	return out, nil
}

// Ping verifies the workerd binary exists. Config load deliberately does not
// stat the path; this is the seam /healthz surfaces it through, mirroring the
// Firecracker driver.
func (d *Driver) Ping(ctx context.Context) error {
	info, err := os.Stat(d.cfg.WorkerdPath)
	if err != nil {
		return fmt.Errorf("workerd binary not usable at %s (SB_ISOLATE_WORKERD_PATH): %w", d.cfg.WorkerdPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("workerd binary path %s is a directory (SB_ISOLATE_WORKERD_PATH)", d.cfg.WorkerdPath)
	}
	return nil
}

// RemoveImage GCs a bundle from the content-addressed store (Phase 2; bundles
// are content-addressed so removal is reference-counted, never destructive to
// a live sandbox).
func (d *Driver) RemoveImage(ctx context.Context, imageRef string) error {
	return notImplemented("remove image")
}
