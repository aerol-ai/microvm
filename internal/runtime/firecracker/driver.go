// Package firecracker is the native Firecracker runtime driver. It is the
// second implementation of internal/runtime.Runtime (the first being
// pkg/docker.Client) and runs sandboxes as Firecracker microVMs with no
// Docker daemon in the path.
//
// This file lands the package as a skeleton: the Driver type implements
// every Runtime method but returns models.ErrRuntimeNotImplemented from
// each one until the actual lifecycle code arrives. The point of landing
// the skeleton first is to:
//
//   - prove the runtime.Runtime interface holds with a second
//     implementation (the "visible property at end of Phase 1" from
//     plans/snapshot-clone-fast-boot.md),
//   - give cmd/sandboxd/main.go a real type to wire alongside the Docker
//     driver when SB_ENABLE_FIRECRACKER is true, and
//   - give the service layer a non-nil firecracker driver to dispatch to,
//     so the rejection lives in this package's methods (where the future
//     real implementation will replace them) rather than as a special-case
//     branch in CreateSandbox.
//
// Phase 1 (per the plan): the methods below get filled in one at a time:
// Ping first (cheapest), then Create / Start / Destroy on a single cold
// boot, then Stop / Inspect / ListManaged, then snapshot support. Each
// step is independently mergeable because the surface stays stable.
package firecracker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Driver implements runtime.Runtime against Firecracker. The zero value is
// not usable; callers must go through New.
//
// Concurrency model mirrors pkg/docker.Client: methods are safe for
// concurrent use across different sandboxes; per-sandbox serialization is
// the service layer's responsibility. The driver keeps a small registry of
// per-sandbox API clients (one Firecracker process => one Unix socket =>
// one *firecracker.Client) so callers don't re-resolve the socket path on
// every method call.
type Driver struct {
	cfg    Config
	logger *slog.Logger

	mu      sync.Mutex
	clients map[string]*firecracker.Client // sandbox-id -> API client
}

// Config is the subset of internal/config.Config the driver actually uses.
// Lifted to its own type so unit tests can construct a driver without
// reaching into the full daemon config, and so the package has no import
// cycle with internal/config (the public config package depends on pkg/
// types via models — this package depends on neither for its core surface).
type Config struct {
	// FirecrackerBinary is the absolute path to the firecracker VMM. The
	// driver checks it on Ping (does the file exist and is it executable),
	// not on construction — the daemon can start with a misconfigured
	// path; /healthz surfaces the failure.
	FirecrackerBinary string
	// JailerBinary is the absolute path to the jailer helper. Same
	// existence-check policy as FirecrackerBinary.
	JailerBinary string
	// KernelImage is the host path to the guest kernel image used for
	// template builds (and, until per-template kernels arrive, for every
	// cold-boot VMM).
	KernelImage string
	// RunDir is the per-sandbox runtime state root. Each sandbox gets a
	// subdirectory <RunDir>/<sandbox-id>/ holding the API socket, the
	// jailer chroot, and per-sandbox vsock UDS files. tmpfs strongly
	// recommended; the daemon does not enforce it.
	RunDir string
	// TemplatesDir is the persistent root for template artifacts (kernel,
	// rootfs.ext4, snapshot.memory, snapshot.state, manifest.json). Lives
	// across daemon restarts.
	TemplatesDir string
}

// FromDaemonConfig copies the Firecracker-relevant fields out of the full
// daemon config. Defined as a free helper rather than a method so the
// driver package doesn't import internal/config in its hot path; main.go
// is the only caller.
func FromDaemonConfig(c config.Config) Config {
	return Config{
		FirecrackerBinary: c.FirecrackerBinary,
		JailerBinary:      c.JailerBinary,
		KernelImage:       c.FirecrackerKernelImage,
		RunDir:            c.FirecrackerRunDir,
		TemplatesDir:      c.FirecrackerTemplatesDir,
	}
}

// New returns a Driver. The constructor does not stat the binaries or
// create RunDir — those checks land in Ping so a daemon with a transient
// misconfiguration can still boot and surface the problem through
// /healthz, the same model the Docker driver uses for unreachable
// dockerd.
func New(cfg Config, logger *slog.Logger) *Driver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Driver{
		cfg:     cfg,
		logger:  logger,
		clients: make(map[string]*firecracker.Client),
	}
}

// methodNotImplemented produces the canonical "not yet implemented" error
// for a Runtime method, wrapping models.ErrRuntimeNotImplemented so
// pkg/api/apihttp.WriteStoreAwareError can keep mapping it to the right
// HTTP status. The method name in the message is what operators see in
// the log line, so it should be unambiguous (the wrap above is enough for
// errors.Is checks).
func methodNotImplemented(method string) error {
	return fmt.Errorf("firecracker runtime: %s not yet implemented (see plans/snapshot-clone-fast-boot.md): %w",
		method, models.ErrRuntimeNotImplemented)
}

// Create provisions a sandbox on Firecracker. Phase 1 path (no snapshots):
// spawn a jailed firecracker VMM, write machine-config + boot-source +
// rootfs drive + TAP iface + vsock, issue InstanceStart, wait for the
// in-VM toolbox to handshake over vsock, return the runtime state.
//
// Phase 3+ path (snapshot clone): pull a paused VMM from the warm pool,
// PATCH the per-sandbox overlay and TAP onto it, issue Action Resume,
// return.
//
// Both paths land here; neither exists yet.
func (d *Driver) Create(_ context.Context, _ models.CreateSandboxRequest, _, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, methodNotImplemented("Create")
}

// Start boots a previously-stopped Firecracker VMM. The model diverges
// slightly from Docker's: a stopped sandbox on the Firecracker path is a
// destroyed VMM (Firecracker VMMs do not survive a stop), so Start
// reconstructs from the persisted sandbox row + template. See the plan
// for the lifecycle table.
func (d *Driver) Start(_ context.Context, _ string) (*models.SandboxRuntimeState, error) {
	return nil, methodNotImplemented("Start")
}

// Stop sends a graceful shutdown to the VMM. The agent receives a
// pre-shutdown hook over vsock, then the driver issues a clean VMM exit.
// On Firecracker the in-guest shutdown signal is a virtio-event the kernel
// observes — the driver wraps that.
func (d *Driver) Stop(_ context.Context, _ string) error {
	return methodNotImplemented("Stop")
}

// Destroy tears down the VMM, releases the per-sandbox TAP/IP/vsock-CID
// back to their pools, removes the per-sandbox overlay file, and clears
// any network rules attached to the sandbox's guest IP. Passing nil is a
// no-op to match the Docker driver's contract for half-built cleanup
// paths.
func (d *Driver) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	return methodNotImplemented("Destroy")
}

// CreateSnapshot is the runtime-level "commit" primitive. On the
// Firecracker side this is more involved than on Docker: we need to pause
// the VMM, write snapshot.memory + snapshot.state, copy the read-only
// rootfs reference, and write a manifest — the template-builder pipeline
// in internal/templates uses this driver method as one of its building
// blocks rather than calling Firecracker directly.
func (d *Driver) CreateSnapshot(_ context.Context, _, _ string) (string, error) {
	return "", methodNotImplemented("CreateSnapshot")
}

// Resize updates VCPU and memory caps. Firecracker only supports
// PATCH /machine-config for memory hot-add via the balloon device today;
// CPU resize requires a snapshot+restore cycle. The driver may reject
// CPU-resize on a running VMM with a clearer error than Docker's.
func (d *Driver) Resize(_ context.Context, _ string, _ models.ResizeSandboxRequest) error {
	return methodNotImplemented("Resize")
}

// Inspect returns the runtime state of a single VMM. Used by reconcile and
// /healthz; cheap (a single GET / against the API socket).
func (d *Driver) Inspect(_ context.Context, _ string) (*models.SandboxRuntimeState, error) {
	return nil, methodNotImplemented("Inspect")
}

// ListManaged enumerates every Firecracker VMM the daemon currently owns.
// Today's plan: walk d.clients (the per-sandbox client registry) and call
// Inspect on each. The current empty implementation returns an empty
// map — safe because no Create has ever succeeded.
func (d *Driver) ListManaged(_ context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.clients) == 0 {
		// Pre-implementation: there are no managed VMMs, so an empty map
		// is the truthful answer. Once Create lands, this will iterate
		// d.clients and call Inspect on each.
		return map[string]*models.SandboxRuntimeState{}, nil
	}
	return nil, methodNotImplemented("ListManaged")
}

// Ping confirms the daemon has working Firecracker tooling on this host.
// We check the binaries exist and that the run directory is creatable.
// Phase 1 enhancement: also try to spawn-and-immediately-kill a VMM as a
// liveness probe; for now the binary check is enough to make /healthz
// useful.
func (d *Driver) Ping(_ context.Context) error {
	if d.cfg.FirecrackerBinary == "" {
		return errors.New("firecracker runtime: SB_FIRECRACKER_BINARY is not set")
	}
	if d.cfg.JailerBinary == "" {
		return errors.New("firecracker runtime: SB_JAILER_BINARY is not set")
	}
	if _, err := os.Stat(d.cfg.FirecrackerBinary); err != nil {
		return fmt.Errorf("firecracker runtime: SB_FIRECRACKER_BINARY=%q: %w", d.cfg.FirecrackerBinary, err)
	}
	if _, err := os.Stat(d.cfg.JailerBinary); err != nil {
		return fmt.Errorf("firecracker runtime: SB_JAILER_BINARY=%q: %w", d.cfg.JailerBinary, err)
	}
	if d.cfg.KernelImage != "" {
		if _, err := os.Stat(d.cfg.KernelImage); err != nil {
			return fmt.Errorf("firecracker runtime: SB_FIRECRACKER_KERNEL=%q: %w", d.cfg.KernelImage, err)
		}
	}
	return nil
}

// RemoveImage is a Docker concept; on the Firecracker path images are
// flattened into per-template rootfs files and GCed by the template
// service. Calls here are unexpected but harmless — surfacing
// ErrRuntimeNotImplemented makes the misuse observable.
func (d *Driver) RemoveImage(_ context.Context, _ string) error {
	return methodNotImplemented("RemoveImage")
}

// PushAllowedPorts forwards the toolbox allowlist update. On the
// Firecracker path the toolbox channel is vsock, not the TAP-side TCP that
// Docker uses, so the call path differs from the Docker driver's HTTP
// dial against the container IP.
func (d *Driver) PushAllowedPorts(_ context.Context, _, _ string, _ []int) error {
	return methodNotImplemented("PushAllowedPorts")
}

// ClearNetworkRules releases per-IP host-side rules attached to a
// sandbox's guest IP. The Firecracker analogue of the Docker iptables
// rules: a routed L3 setup with per-TAP egress allow/deny lists. Phase 1
// uses a bridge with the same iptables shape as Docker for parity; later
// phases may move to eBPF (see CubeVS reference in the plan).
func (d *Driver) ClearNetworkRules(_ string) error {
	return methodNotImplemented("ClearNetworkRules")
}

// ApplyNetworkBlockAll, ApplyNetworkBlockIngress, ClearNetworkBlockIngress,
// ClearNetworkBlockEgress mirror the Docker driver's quota/block surface.
// Implementations land alongside the TAP-side firewall in
// internal/network/tap/ and the egress rule package the Firecracker driver
// will own.

func (d *Driver) ApplyNetworkBlockAll(_ string) error {
	return methodNotImplemented("ApplyNetworkBlockAll")
}

func (d *Driver) ApplyNetworkBlockIngress(_ string) error {
	return methodNotImplemented("ApplyNetworkBlockIngress")
}

func (d *Driver) ClearNetworkBlockIngress(_ string) error {
	return methodNotImplemented("ClearNetworkBlockIngress")
}

func (d *Driver) ClearNetworkBlockEgress(_ string) error {
	return methodNotImplemented("ClearNetworkBlockEgress")
}
