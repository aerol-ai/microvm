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
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Driver implements runtime.Runtime for isolate sandboxes. Isolate satisfies
// only the core Runtime interface — not ContainerRuntime (host-mediated
// networking, same posture as WASM).
type Driver struct {
	cfg    Config
	logger *slog.Logger

	resolver   BundleResolver
	supervisor HostSupervisor
	warmPool   WarmPool
	net        *networkGateway

	mu   sync.Mutex
	byID map[string]*sandboxRecord

	// groups is the group router: one running host per isolate-group key
	// (§2.1). groupsMu guards it and the single-flight spawn bookkeeping.
	groupsMu sync.Mutex
	groups   map[string]*group
	spawning map[string]chan struct{}
}

// sandboxRecord is the driver's per-sandbox bookkeeping: the runtime state it
// hands back to the service plus the group it was loaded into (so Destroy can
// route the unload and trigger last-member teardown). needsReload is set when
// the idle-TTL reaper tore the group down out from under a still-registered
// sandbox — the next Start/Invoke re-acquires a group and re-pins the bundle.
type sandboxRecord struct {
	state       *models.SandboxRuntimeState
	groupKey    string
	tenantID    string
	bundleRef   string
	egress      EgressPolicy
	needsReload bool
}

// group is one running workerd host plus the group key it serves.
type group struct {
	key      string
	host     GroupHost
	lastUsed time.Time
}

// New constructs an isolate driver. The zero value is not usable.
func New(cfg Config, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Driver{
		cfg:      cfg,
		logger:   logger,
		byID:     make(map[string]*sandboxRecord),
		groups:   make(map[string]*group),
		spawning: make(map[string]chan struct{}),
		net:      newNetworkGateway(),
	}
	// Ingress: Caddy dials the loopback mediator; the mediator calls Invoke
	// on the sandbox's group host (Phase 3 guest_http).
	d.net.SetHTTPProxy(d.guestHTTPProxy)
	return d
}

// SetBundleResolver injects the JS/TS bundle resolver (pkg/jsbundle in
// production, Phase 2).
func (d *Driver) SetBundleResolver(r BundleResolver) {
	d.resolver = r
}

// SetHostSupervisor injects the workerd group supervisor (pkg/isolate in
// production, Phase 2).
func (d *Driver) SetHostSupervisor(s HostSupervisor) {
	d.supervisor = s
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

// Start re-affirms a running isolate, and re-pins the bundle after an idle-TTL
// reap tore the group down. An unknown id is a 404-shaped nil,nil per the
// Runtime contract.
func (d *Driver) Start(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	d.mu.Unlock()
	if rec == nil {
		return nil, nil
	}
	if err := d.ensureLoaded(ctx, sandboxID); err != nil {
		return nil, err
	}
	d.mu.Lock()
	rec = d.byID[sandboxID]
	if rec != nil {
		rec.state.Status = models.SandboxStatusStarted
	}
	d.mu.Unlock()
	if rec == nil {
		return nil, nil
	}
	return rec.state, nil
}

// Stop marks a sandbox stopped but keeps its bundle pinned so a later Start is
// instant. The group process stays up for co-resident sandboxes; true teardown
// is Destroy. Idle groups are reaped by RunIdleReaper.
func (d *Driver) Stop(ctx context.Context, sandboxID string) error {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	if rec != nil {
		rec.state.Status = models.SandboxStatusStopped
	}
	d.mu.Unlock()
	return nil
}

// Destroy removes the sandbox from its group host and, when it was the group's
// last member, tears the group process down (§2.1 last-member teardown). Nil,
// or an unknown sandbox, is a no-op — cleanup paths may run without a record.
func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	d.mu.Lock()
	rec := d.byID[sandbox.ID]
	delete(d.byID, sandbox.ID)
	d.mu.Unlock()
	if rec != nil && rec.groupKey != "" {
		d.releaseFromGroup(rec.groupKey, sandbox.ID)
	}
	if d.net != nil {
		d.net.ReleaseSandbox(sandbox.ID)
	}
	return nil
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
	rec := d.byID[sandboxID]
	d.mu.Unlock()
	if rec == nil {
		return nil, nil
	}
	return rec.state, nil
}

// ListManaged returns the runtime state of every isolate this daemon owns, so
// restart reconcile can match live isolates against persisted rows and
// terminal-ize any strays.
func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(d.byID))
	for id, rec := range d.byID {
		out[id] = rec.state
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
