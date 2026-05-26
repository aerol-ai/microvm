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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

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
	// pool is the per-host TAP+IP+vsock-CID allocator. Non-nil only when
	// SetPool has been called from main.go. Unit tests that don't need
	// pool semantics (Ping, ListManaged, Destroy(nil)) leave it nil and
	// the methods cope. Create requires pool to be set.
	pool TapPool

	// Host-environment seams. Production impls are injected by
	// cmd/sandboxd/main.go via the Set* methods; tests construct a
	// Driver with fakes for each. Each seam is independently
	// nil-checked at the point of first use so the failure message can
	// say which adapter was missing.
	rootfs    RootfsBuilder
	tapHost   TapHost
	vsockDial VsockDialer
	// templates resolves a CreateSandboxRequest.TemplateID to the
	// host path of a pre-built rootfs.ext4. Optional: when nil, every
	// Create runs the OCI build pipeline (Phase 1 behavior). Set by
	// main.go via SetTemplateResolver once the template service is
	// constructed. Tests stub it to return a fake rootfs path.
	templates TemplateResolver
	// warmPool is the Phase 4 PR-B warm-VMM pool. Optional: when nil,
	// every snapshot-load Create runs the cold-spawn + LoadSnapshot
	// path; when non-nil, Create.tryAcquireWarm consults the pool
	// before falling back. Production wires this to
	// *internal/pool/vmm.Pool via SetWarmPool from main.go; tests
	// inject a fake satisfying the WarmPool interface.
	warmPool WarmPool
	// sampler is the Phase 5 (PR 5-C) per-VMM RSS sampler. Optional:
	// when nil, none of the lifecycle paths (Create / WarmSpawn /
	// tryAcquireWarm / Destroy) touch the sampler — the field is a
	// concrete pointer rather than an interface so a nil check is a
	// real nil-pointer check, not the typed-nil pitfall capacity's
	// RSSSource wiring already documented in main.go. Capacity sees
	// the same sampler via the RSSSource interface; main.go is
	// responsible for ensuring both halves point at the same instance.
	sampler *RSSSampler

	// spawn is the seam Create uses to construct a VMMHandle for a
	// sandbox. Default impl wraps newVMM (which is the production
	// process supervisor); tests inject a fake. Function-shaped so
	// the contract stays "give me a handle" and nothing more.
	spawn vmmSpawner
	// newClient is the seam Create uses to construct a Firecracker REST
	// client. Default wraps firecracker.New (a thin HTTP-over-UDS
	// client); tests inject a fake that records REST calls without
	// needing a real socket.
	newClient vmmClientFactory

	mu      sync.Mutex
	clients map[string]VMMClient // sandbox-id -> API client
	vmms    map[string]VMMHandle // sandbox-id -> VMM handle (for Destroy)
}

// TapPool is the interface Driver depends on for network allocation.
// Defined here rather than referencing *tap.Pool directly so the runtime
// package has no import dependency on internal/network/tap (which would
// drag the store into the runtime's test binary). main.go injects the
// real *tap.Pool, which satisfies the interface structurally.
type TapPool interface {
	Allocate(ctx context.Context, sandboxID string, now time.Time) (*TapSlot, error)
	Release(ctx context.Context, sandboxID string) error
	Get(ctx context.Context, sandboxID string) (*TapSlot, error)
}

// TapSlot mirrors internal/network/tap.Slot. Re-declared here to keep
// the import-cycle wall up; main.go's adapter converts between the two
// shapes.
type TapSlot struct {
	TapName  string
	CIDR     string
	HostIP   string
	GuestIP  string
	VsockCID uint32
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
	// UseJailer flips the spawn from `firecracker` directly to `jailer`,
	// which chroots+cgroups+drops-priv into JailerUID/JailerGID. Production
	// hosts always set this; dev/CI without root leave it false. When
	// true, vmm.go re-roots a sandbox's runDir under JailerChrootBase
	// rather than RunDir; see jailer.go for the path math.
	UseJailer bool
	// JailerChrootBase is the parent directory under which jailer creates
	// each sandbox's chroot. Canonical layout is
	// <JailerChrootBase>/firecracker/<sandbox-id>/root/.
	JailerChrootBase string
	// JailerUID / JailerGID are the UID/GID the firecracker process drops
	// into inside the jail. Must already exist on the host.
	JailerUID int
	JailerGID int
	// SnapshotVerifyOnLoad gates SHA256 verification of snapshot.memory
	// and snapshot.state immediately before each LoadSnapshot. Default
	// true on production daemons; bypass only for benchmarking the raw
	// load-cost of a known-good snapshot. Mirrors
	// internal/config.Config.FirecrackerSnapshotVerifyOnLoad.
	SnapshotVerifyOnLoad bool
	// OverlayEnabled is the daemon-wide opt-out for the per-sandbox
	// writable overlay drive. Mirrors
	// internal/config.Config.FirecrackerOverlayEnabled. When false,
	// Create rejects any request with OverlaySizeGB > 0.
	OverlayEnabled bool
	// OverlayMkfs makes the driver run mkfs.ext4 -F on each per-
	// sandbox overlay.ext4 right after sparse allocation. Mirrors
	// internal/config.Config.FirecrackerOverlayMkfs. Off by default —
	// the guest is normally expected to mkfs /dev/vdb itself.
	OverlayMkfs bool
	// Mkfs4Bin is the host path to the mkfs.ext4 binary, reused from
	// the OCI builder for the optional host-side overlay format step.
	// Only consulted when OverlayMkfs is true.
	Mkfs4Bin string
	// PostResumeTimeout bounds the best-effort post_resume vsock send
	// (carries host wall clock to the guest for clock+RNG resync).
	// Mirrors internal/config.Config.FirecrackerSnapshotPostResumeTimeout.
	PostResumeTimeout time.Duration
}

// FromDaemonConfig copies the Firecracker-relevant fields out of the full
// daemon config. Defined as a free helper rather than a method so the
// driver package doesn't import internal/config in its hot path; main.go
// is the only caller.
func FromDaemonConfig(c config.Config) Config {
	return Config{
		FirecrackerBinary:    c.FirecrackerBinary,
		JailerBinary:         c.JailerBinary,
		KernelImage:          c.FirecrackerKernelImage,
		RunDir:               c.FirecrackerRunDir,
		TemplatesDir:         c.FirecrackerTemplatesDir,
		UseJailer:            c.UseJailer,
		JailerChrootBase:     c.JailerChrootBase,
		JailerUID:            c.JailerUID,
		JailerGID:            c.JailerGID,
		SnapshotVerifyOnLoad: c.FirecrackerSnapshotVerifyOnLoad,
		OverlayEnabled:       c.FirecrackerOverlayEnabled,
		OverlayMkfs:          c.FirecrackerOverlayMkfs,
		Mkfs4Bin:             c.FirecrackerMkfs4Bin,
		PostResumeTimeout:    c.FirecrackerSnapshotPostResumeTimeout,
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
	d := &Driver{
		cfg:     cfg,
		logger:  logger,
		clients: make(map[string]VMMClient),
		vmms:    make(map[string]VMMHandle),
	}
	// Default spawn function wires the real vmm. Tests overwrite via
	// SetSpawner. The captured logger is used inside newVMM, so the
	// closure here keeps it pinned even after construction.
	d.spawn = func(cfg Config, sandboxID string) (VMMHandle, error) {
		return newVMM(cfg, sandboxID, logger)
	}
	// Default client factory wires the real REST client. Tests override
	// via SetClientFactory.
	d.newClient = func(socketPath string) VMMClient {
		return firecracker.New(socketPath)
	}
	return d
}

// SetPool injects the network-allocation pool. Called once by main.go
// after both the store and the pool have been constructed, before the
// driver is registered with the service. Passing nil clears the
// dependency (used by tests that exercise non-Create methods).
func (d *Driver) SetPool(p TapPool) {
	d.pool = p
}

// SetRootfsBuilder injects the OCI-image-to-rootfs.ext4 builder.
// Production impl is a thin adapter around *pkg/oci.Builder; tests
// inject a fake that touches a file at the requested OutPath.
func (d *Driver) SetRootfsBuilder(b RootfsBuilder) { d.rootfs = b }

// SetTapHost injects the host-side TAP-device manager. Production
// impl is *internal/network/tap.Host; tests inject a recording fake.
func (d *Driver) SetTapHost(h TapHost) { d.tapHost = h }

// SetVsockDialer injects the host-side AF_VSOCK dialer. Production
// impl is the Linux-only NewLinuxVsockDialer(); tests inject a fake
// that returns an in-memory io.ReadWriteCloser pair.
func (d *Driver) SetVsockDialer(v VsockDialer) { d.vsockDial = v }

// SetSpawner overrides the default VMM spawn function. Tests use
// this to swap in a fake handle that records Start/WaitSocket/
// Shutdown calls without exec'ing firecracker.
func (d *Driver) SetSpawner(s vmmSpawner) { d.spawn = s }

// SetClientFactory overrides the default REST-client constructor.
// Tests use this to swap in a fake client recording every REST call.
func (d *Driver) SetClientFactory(f vmmClientFactory) { d.newClient = f }

// SetTemplateResolver injects the Phase 2 template→rootfs lookup. When
// non-nil, Create with req.TemplateID != "" hard-links the resolved
// rootfs into the per-sandbox runDir and skips the OCI pipeline. Nil
// leaves the driver in Phase 1 mode (every Create runs skopeo+umoci+
// mkfs).
func (d *Driver) SetTemplateResolver(t TemplateResolver) { d.templates = t }

// SetRSSSampler injects the Phase 5 per-VMM RSS sampler. When non-nil
// the driver Registers each spawned VMM's PID (cold sandboxes by
// sandbox ID, warm pool slots by slot ID, then re-keyed to sandbox ID
// on warm acquire) and Unregisters on Destroy / warm Shutdown.
// nil leaves admission on nominal accounting — same as a daemon built
// without Phase 5. Tests that exercise lifecycle ordering can use this
// to inspect Register/Unregister calls via the sampler's TotalRSSMB.
func (d *Driver) SetRSSSampler(s *RSSSampler) { d.sampler = s }

// rssRegister is the nil-safe Register helper. Centralised so the
// Create / WarmSpawn / tryAcquireWarm sites can stay one-liners — the
// alternative was repeating "if d.sampler != nil && pid > 0" at every
// call site, which would invite someone to forget the pid > 0 check
// (the sampler already rejects, but a misleading "register failed"
// log line at the call site would still cost time).
func (d *Driver) rssRegister(id string, pid int) {
	if d.sampler == nil || pid <= 0 {
		return
	}
	d.sampler.Register(id, pid)
}

// rssUnregister is the nil-safe Unregister helper. Same rationale as
// rssRegister.
func (d *Driver) rssUnregister(id string) {
	if d.sampler == nil {
		return
	}
	d.sampler.Unregister(id)
}

// TemplateResolver maps a template ID to a *TemplateResolution describing
// where the prepared artifacts live on disk. Implementations are
// responsible for asserting that the template is in a usable state
// (status=ready or ready_no_snapshot) — a non-nil path returned with
// status=pending/failed would crash the VMM at boot. The interface lives
// in this package (rather than re-exporting the service-layer one) so the
// runtime package has no service import.
type TemplateResolver interface {
	Resolve(ctx context.Context, templateID string) (*TemplateResolution, error)
}

// TemplateResolution is the richer return shape the driver needs to
// pick between the cold-boot (link rootfs + boot) and snapshot-load
// (LoadSnapshot + Resume) paths in Create. HasSnapshot=false signals
// the driver to fall back to cold-boot — the rootfs is usable on its
// own, snapshot artifacts are not present. When HasSnapshot=true,
// SnapshotMemoryPath / SnapshotStatePath / SnapshotVsockCID are
// required; SnapshotChecksum is optional (used for integrity
// verification when SnapshotVerifyOnLoad is on).
type TemplateResolution struct {
	RootfsPath         string
	SnapshotMemoryPath string
	SnapshotStatePath  string
	SnapshotChecksum   string
	SnapshotVsockCID   uint32
	HasSnapshot        bool
	// HasOverlay reports whether the template was built with the
	// per-sandbox overlay drive placeholder baked into its snapshot
	// state (Phase 3 PR-B). False for PR-A templates. The driver
	// rejects a snapshot-load request with OverlaySizeGB > 0 against
	// a HasOverlay=false template with a clear "rebuild template"
	// error rather than failing mid-PATCH — Firecracker cannot add a
	// virtio-blk device post-load, only PATCH an existing one's path.
	HasOverlay bool
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
// Cleanup contract — pr-review.md §4: every failure path between an
// acquired resource and the function return must release that
// resource. The implementation uses deferred-with-flag closures so
// every step's cleanup is in scope for every later step's failure.
// The order — pool slot → rootfs staging → host-side TAP → VMM
// process → registry entries — matches the order in which each is
// acquired, so cleanup unwinds in LIFO order.
//
// Boot-path latency — pr-review.md §2: under normal load this issues
// 3 SQLite writes (pool allocation), 1 OCI subprocess pipeline (the
// dominant cost — skopeo+umoci+mkfs.ext4 can be tens of seconds on a
// large image), 3 `ip` shell-outs, 1 firecracker subprocess spawn,
// 6 HTTP-over-UDS calls, and 1 AF_VSOCK dial. The OCI pipeline is the
// only stage with multi-second worst-case latency; per the plan, Phase
// 2 caches the rootfs and skips this stage when a template hit lands.
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	// All seams are required for a real Create. Distinct error messages
	// per missing seam so the operator can localize the wiring bug from
	// a log line.
	if d.pool == nil {
		return nil, fmt.Errorf("firecracker runtime: TAP pool not registered (main.go must call SetPool): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.rootfs == nil {
		return nil, fmt.Errorf("firecracker runtime: rootfs builder not registered (main.go must call SetRootfsBuilder): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.tapHost == nil {
		return nil, fmt.Errorf("firecracker runtime: TAP host manager not registered (main.go must call SetTapHost): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.vsockDial == nil {
		return nil, fmt.Errorf("firecracker runtime: vsock dialer not registered (main.go must call SetVsockDialer): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.cfg.KernelImage == "" {
		return nil, fmt.Errorf("firecracker runtime: KernelImage not configured (SB_FIRECRACKER_KERNEL): %w",
			models.ErrRuntimeNotImplemented)
	}
	if _, err := os.Stat(d.cfg.KernelImage); err != nil {
		return nil, fmt.Errorf("firecracker runtime: kernel %q unreachable: %w",
			d.cfg.KernelImage, err)
	}
	// The service layer's firecracker branch passes a synthesized
	// sandboxID today (see service.go createSandboxFirecracker). The
	// fallback synth here is the last line of defense for direct
	// driver tests that call Create with the empty string — it does not
	// otherwise fire in production.
	allocID := sandboxID
	if allocID == "" {
		allocID = fmt.Sprintf("fc-phase1-%d", time.Now().UnixNano())
	}
	if err := validateSandboxID(allocID); err != nil {
		return nil, fmt.Errorf("firecracker runtime: %w", err)
	}

	// Step 0: overlay-request sanity. Both the daemon-wide opt-out and
	// the wire-level upper bound are checked before any allocation so a
	// bad request fails fast and never leaks a slot. The upper bound
	// mirrors models.CreateSandboxRequest documentation (0–1024). The
	// runtime-vs-template-feature check (HasOverlay) lands later, once
	// the template resolution result is in hand.
	if req.OverlaySizeGB < 0 || req.OverlaySizeGB > 1024 {
		return nil, fmt.Errorf("firecracker runtime: overlay_size_gb=%d out of range [0,1024]", req.OverlaySizeGB)
	}
	if req.OverlaySizeGB > 0 && !d.cfg.OverlayEnabled {
		return nil, fmt.Errorf("firecracker runtime: overlay drive disabled on this daemon (SB_FIRECRACKER_OVERLAY_ENABLED=false)")
	}

	// Step 1: allocate the network slot.
	slot, err := d.pool.Allocate(ctx, allocID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: tap allocate: %w", err)
	}
	released := false
	defer func() {
		if !released {
			if relErr := d.pool.Release(ctx, allocID); relErr != nil {
				d.logger.Warn("firecracker: pool release after error failed",
					"sandbox_id", allocID, "tap", slot.TapName, "error", relErr)
			}
		}
	}()
	d.logger.Info("firecracker create: allocated network slot",
		"sandbox_id", allocID, "tap", slot.TapName,
		"guest_ip", slot.GuestIP, "vsock_cid", slot.VsockCID)

	// Step 1b: Phase 4 warm-VMM pool fast path. Resolve the template
	// early (before cold-spawn) so a pool hit avoids spending the
	// firecracker process + LoadSnapshot wall-clock — that's the
	// ~150ms+ this whole pool exists to skip. On a miss (no template,
	// no snapshot, no pool slot) we fall through to the cold-spawn
	// path unchanged.
	//
	// Template resolution is the only step we move earlier; the rest
	// of Create still expects to resolve+stage inside its existing
	// structure, so we keep the resolved snapshotInfo handy and reuse
	// it below rather than re-resolving.
	var earlySnap *TemplateResolution
	if req.TemplateID != "" && d.templates != nil {
		earlySnap, err = d.templates.Resolve(ctx, req.TemplateID)
		if err != nil {
			return nil, fmt.Errorf("firecracker runtime: template %q resolve: %w", req.TemplateID, err)
		}
	}
	if state, hit, err := d.tryAcquireWarm(ctx, req, allocID, earlySnap, slot, ""); err != nil {
		return nil, err
	} else if hit {
		// Warm path committed the TAP slot to the sandbox; suppress
		// the deferred TAP release.
		released = true
		return state, nil
	}

	// Step 2: spawn the VMM (creates the runDir we need before staging
	// the rootfs). We spawn but do NOT yet Start — the rootfs must be
	// in place inside the runDir before firecracker boots.
	handle, err := d.spawn(d.cfg, allocID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: spawn handle: %w", err)
	}
	vmmStarted := false
	cleanupVMM := func() {
		if vmmStarted {
			_ = handle.Shutdown(context.Background(), 3*time.Second)
		}
		if cErr := handle.Cleanup(); cErr != nil {
			d.logger.Warn("firecracker: vmm cleanup after error failed",
				"sandbox_id", allocID, "error", cErr)
		}
	}
	defer func() {
		if !released {
			cleanupVMM()
		}
	}()

	// Step 3: provision the rootfs.ext4 inside the runDir.
	//
	// Two paths:
	//
	//   - Template hit (Phase 2): req.TemplateID is set and the resolver
	//     returns the host path of a pre-built rootfs. We hard-link
	//     (cheap, same filesystem in the canonical layout) so the
	//     jailer chroot covers it. EXDEV → copy fallback so a
	//     differently-mounted TemplatesDir still works. No OCI pipeline
	//     runs on this Create. This is the boot-path-latency win the
	//     plan calls for.
	//
	//   - Ad-hoc (Phase 1): no TemplateID; run the OCI pipeline as
	//     before. Builds rootfs straight into the runDir so the jailer
	//     chroot already covers it.
	rootfsPath := filepath.Join(handle.RunDir(), rootfsFileName)
	// Snapshot-load path is opt-in per template. When the resolver returns
	// HasSnapshot=true we skip configureVMM + InstanceStart and instead
	// issue LoadSnapshot + Resume on the same paused VMM. The pool slot
	// is still allocated (for TAP) but slot.VsockCID is unused — the
	// guest's CID was baked into the template snapshot at build time and
	// the host dials *that* CID to handshake.
	var (
		snapshotLoadPath bool
		snapshotInfo     *TemplateResolution
	)
	if req.TemplateID != "" {
		if d.templates == nil {
			return nil, fmt.Errorf("firecracker runtime: template resolver not registered (main.go must call SetTemplateResolver): %w",
				models.ErrRuntimeNotImplemented)
		}
		// Reuse the resolution from Step 1b's warm-pool eligibility
		// check. earlySnap is non-nil here because the warm path's
		// eligibility test required req.TemplateID != "" AND
		// d.templates != nil, exactly the same gate as this branch.
		// Re-resolving would double the template-store I/O on every
		// snapshot-load Create.
		src := earlySnap
		if err := linkOrCopyRootfs(src.RootfsPath, rootfsPath); err != nil {
			return nil, fmt.Errorf("firecracker runtime: template stage: %w", err)
		}
		if src.HasSnapshot {
			// PR-A templates (HasOverlay=false) baked no overlay drive
			// into their snapshot state; Firecracker can only PATCH the
			// path of a drive that already exists in the snapshot — it
			// cannot add a new virtio-blk device post-load. Reject up
			// front rather than failing mid-PATCH (which would leave
			// the VMM loaded-but-unable-to-resume). Operator fix is to
			// rebuild the template via POST /v1/templates.
			if req.OverlaySizeGB > 0 && !src.HasOverlay {
				return nil, fmt.Errorf("firecracker runtime: template %q has no overlay drive in its snapshot state; rebuild template via POST /v1/templates to use overlay_size_gb",
					req.TemplateID)
			}
			snapshotLoadPath = true
			snapshotInfo = src
			d.logger.Info("firecracker create: snapshot-load path",
				"sandbox_id", allocID, "template_id", req.TemplateID,
				"template_cid", src.SnapshotVsockCID,
				"unused_slot_cid", slot.VsockCID,
				"overlay_size_gb", req.OverlaySizeGB)
		} else {
			d.logger.Info("firecracker create: staged template rootfs (cold-boot)",
				"sandbox_id", allocID, "template_id", req.TemplateID, "src", src.RootfsPath)
		}
	} else {
		rootfsResult, err := d.rootfs.Build(ctx, RootfsBuildRequest{
			ImageRef: ociImageRefFor(req.Image),
			OutPath:  rootfsPath,
			// MinSizeMiB carries the user's disk request through to mkfs;
			// the OCI builder rounds up to the larger of the image and
			// this floor. Zero (the wire default) means "use whatever the
			// unpacked rootfs needs".
			MinSizeMiB: req.DiskGB * 1024,
			Tag:        "latest",
		})
		if err != nil {
			return nil, fmt.Errorf("firecracker runtime: rootfs build: %w", err)
		}
		defer func() {
			// Clean up the OCI staging directory regardless of success: the
			// rootfs.ext4 has been written into the runDir; we don't need
			// the unpacked OCI bundle after that.
			if cErr := rootfsResult.Cleanup(); cErr != nil {
				d.logger.Warn("firecracker: rootfs staging cleanup failed",
					"sandbox_id", allocID, "error", cErr)
			}
		}()
	}

	// Step 4: bring the host-side TAP up. After this point, error
	// returns must call tapHost.Remove. The flag-and-defer pattern
	// mirrors the pool-release one above.
	if err := d.tapHost.Ensure(ctx, *slot); err != nil {
		return nil, fmt.Errorf("firecracker runtime: tap host ensure %s: %w", slot.TapName, err)
	}
	tapRemoved := false
	defer func() {
		if !released && !tapRemoved {
			if rmErr := d.tapHost.Remove(context.Background(), slot.TapName); rmErr != nil {
				d.logger.Warn("firecracker: tap remove after error failed",
					"sandbox_id", allocID, "tap", slot.TapName, "error", rmErr)
			}
		}
	}()

	// Step 5: start the VMM process and wait for the API socket.
	if err := handle.Start(ctx); err != nil {
		return nil, fmt.Errorf("firecracker runtime: vmm start: %w", err)
	}
	vmmStarted = true
	// The 5s WaitSocket default fits cold-boot firecracker on a healthy
	// host (sub-100ms is typical). The jailer chroot copy step is the
	// only thing that pushes this above 1s; the generous ceiling
	// absorbs it.
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return nil, fmt.Errorf("firecracker runtime: wait api socket: %w (stderr: %s)",
			err, handle.StderrTail())
	}

	// Step 5b: per-sandbox overlay file. Allocated unconditionally when
	// the request asks for one — both cold-boot (PutDrive overlay) and
	// snapshot-load (PatchDrive overlay) consume the same file. Lives
	// in the runDir so the deferred VMM cleanup also drops it; no
	// extra cleanup branch needed (pr-review.md §4). Sparse so a 64
	// GiB overlay request occupies sub-MiB on disk until the guest
	// actually mutates it. When cfg.OverlayMkfs is true, the host
	// formats the file as ext4 here so the guest can mount /dev/vdb
	// directly; default off — see pr-review.md §2 boot-path latency.
	var overlayPath string
	if req.OverlaySizeGB > 0 {
		overlayPath = filepath.Join(handle.RunDir(), overlayFileName)
		if err := allocateSparse(overlayPath, int64(req.OverlaySizeGB)<<30); err != nil {
			return nil, fmt.Errorf("firecracker runtime: overlay alloc: %w", err)
		}
		if d.cfg.OverlayMkfs {
			if d.cfg.Mkfs4Bin == "" {
				return nil, fmt.Errorf("firecracker runtime: SB_FIRECRACKER_OVERLAY_MKFS=true but SB_FIRECRACKER_MKFS_BIN is unset")
			}
			cmd := exec.CommandContext(ctx, d.cfg.Mkfs4Bin, "-F", overlayPath)
			if out, mErr := cmd.CombinedOutput(); mErr != nil {
				return nil, fmt.Errorf("firecracker runtime: mkfs.ext4 overlay: %w (stderr: %s)", mErr, strings.TrimSpace(string(out)))
			}
		}
	}

	// Step 6: REST orchestration. Order matters per the firecracker
	// docs: machine-config and boot-source before drives; drives and
	// network-interfaces before InstanceStart. The snapshot-load path
	// only issues machine-config + LoadSnapshot — everything else is
	// restored from the snapshot state file.
	client := d.newClient(handle.APISocket())
	if snapshotLoadPath {
		if err := d.configureVMMForLoad(ctx, client, snapshotInfo, overlayPath); err != nil {
			return nil, err
		}
	} else {
		if err := d.configureVMM(ctx, client, req, rootfsPath, slot, overlayPath); err != nil {
			return nil, err
		}
	}

	// Step 7: Resume the restored VMM (snapshot-load) OR InstanceStart
	// a freshly-configured one (cold-boot). LoadSnapshot above left the
	// VMM paused (ResumeVM=false) so the driver retains control over
	// when execution actually begins — a Phase 4 (PR-B) hook to PATCH
	// per-sandbox state before resume slots in here.
	if snapshotLoadPath {
		if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionResume}); err != nil {
			return nil, fmt.Errorf("firecracker runtime: action Resume: %w", err)
		}
	} else {
		if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionInstanceStart}); err != nil {
			return nil, fmt.Errorf("firecracker runtime: action InstanceStart: %w", err)
		}
	}

	// Step 8: vsock handshake. The toolbox-in-guest listens on
	// (cid=<guestCID>, port=1024); we dial from the host. A failed
	// handshake here means the guest didn't boot far enough to expose
	// the listener — either the kernel cmdline is wrong, the init
	// binary didn't run, or the vsock device wasn't attached
	// correctly. Surface the error verbatim; the operator's first
	// debug step is to check the firecracker.log for boot diagnostics.
	//
	// On the snapshot-load path the guest's CID is the template's
	// reserved CID (baked into the snapshot at build time), NOT the
	// per-sandbox slot CID. Dialing the slot CID would race a guest
	// that's listening on the template CID and hang until deadline.
	handshakeCID := slot.VsockCID
	if snapshotLoadPath {
		handshakeCID = snapshotInfo.SnapshotVsockCID
	}
	if err := d.vsockHandshake(ctx, handshakeCID); err != nil {
		return nil, fmt.Errorf("firecracker runtime: vsock handshake: %w", err)
	}

	// Step 8b: post-resume quiesce signal (snapshot-load path only).
	// The clone resumed with the template's RNG entropy pool and
	// wall clock — both observably wrong (two clones would draw the
	// same getrandom bytes; logs and TLS handshakes show a backwards
	// time jump). Tell the in-guest toolboxd to reseed the kernel
	// RNG and set CLOCK_REALTIME from the host now. Best-effort:
	// a failed ack here means the guest is using stale entropy/clock,
	// not that the clone is broken, so we log-and-continue. Cold-boot
	// has nothing to resync (kernel just initialized) so skip.
	if snapshotLoadPath {
		postCtx, cancel := context.WithTimeout(ctx, d.cfg.PostResumeTimeout)
		err := d.sendVsockOp(postCtx, handshakeCID, "post_resume", map[string]any{
			"wallclock_unix_ns": time.Now().UnixNano(),
		})
		cancel()
		if err != nil {
			d.logger.Warn("firecracker create: post_resume send failed (continuing)",
				"sandbox_id", allocID, "error", err)
		}
	}

	// All steps succeeded. Register the client + handle so Destroy can
	// find them. Order matters: the map writes happen AFTER we flip
	// `released = true`, so a panic between them still cleans up the
	// half-built state (the deferred closures run on panic).
	released = true
	tapRemoved = false // sandbox-owned now; Destroy will remove
	d.mu.Lock()
	d.clients[allocID] = client
	d.vmms[allocID] = handle
	d.mu.Unlock()

	// Phase 5: tell the RSS sampler about the new VMM so the next
	// sampleOnce includes it in the host-pressure aggregate. Done
	// AFTER the map writes so a sampler tick that races us doesn't
	// see a registered pid the rest of the driver thinks doesn't
	// exist yet. Nil-safe via rssRegister — daemons without Phase 5
	// take no penalty.
	d.rssRegister(allocID, handle.Pid())

	return &models.SandboxRuntimeState{
		SandboxID: allocID,
		// ContainerID is reused as the human-readable identity of the
		// VMM process. Phase 1 doesn't have a container in the strict
		// Docker sense; the firecracker socket path is the closest
		// analogue and is what operators grep for in `ps`.
		ContainerID: handle.APISocket(),
		// ContainerIP is the guest's IP. The service layer's caddy
		// route, network rules, and external API surface use this
		// field opaquely — they don't care whether it's a docker veth
		// peer or a firecracker TAP guest.
		ContainerIP: slot.GuestIP,
		Status:      models.SandboxStatusStarted,
	}, nil
}

// configureVMM issues the cold-boot REST sequence against an
// already-running firecracker VMM. Broken out from Create so the
// happy-path flow stays readable and so future test variants (e.g.
// snapshot-clone) can call it directly.
func (d *Driver) configureVMM(ctx context.Context, client VMMClient, req models.CreateSandboxRequest, rootfsPath string, slot *TapSlot, overlayPath string) error {
	vcpu := vcpuFromRequest(req.CPU)
	if err := client.PutMachineConfig(ctx, firecracker.MachineConfig{
		VcpuCount:  vcpu,
		MemSizeMib: req.MemoryMB,
		// TrackDirtyPages must be on for any VMM we may later
		// snapshot; flipping it post-boot requires a snapshot+restore
		// cycle. Phase 4 will use this; Phase 1 sandboxes don't
		// snapshot but we pay the (small) overhead now for uniformity.
		TrackDirtyPages: true,
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PutMachineConfig: %w", err)
	}
	if err := client.PutBootSource(ctx, firecracker.BootSource{
		KernelImagePath: d.cfg.KernelImage,
		BootArgs:        defaultBootArgs(),
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PutBootSource: %w", err)
	}
	if err := client.PutDrive(ctx, rootDriveID, firecracker.Drive{
		DriveID:      rootDriveID,
		PathOnHost:   rootfsPath,
		IsRootDevice: true,
		// Read-write rootfs in Phase 1 — the ext4 was created
		// per-sandbox and dies with it. Read-only rootfs + per-
		// sandbox overlay is a Phase 2 (template) concern.
		IsReadOnly: false,
		// Writeback caching is required for snapshot-safe overlays;
		// for Phase 1 cold-boot rootfs the cache type is less
		// important, but uniformity here helps Phase 4 reuse.
		CacheType: "Writeback",
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PutDrive root: %w", err)
	}
	// Optional per-sandbox overlay (Phase 3 PR-B). Attaches as
	// /dev/vdb. On cold-boot we PutDrive the freshly-allocated sparse
	// file directly — no PATCH needed because the VMM hasn't booted
	// yet and no snapshot state pins a placeholder path.
	if overlayPath != "" {
		if err := client.PutDrive(ctx, overlayDriveID, firecracker.Drive{
			DriveID:    overlayDriveID,
			PathOnHost: overlayPath,
			IsReadOnly: false,
			CacheType:  "Writeback",
		}); err != nil {
			return fmt.Errorf("firecracker runtime: PutDrive overlay: %w", err)
		}
	}
	if err := client.PutNetworkInterface(ctx, primaryIfaceID, firecracker.NetworkInterface{
		IfaceID:     primaryIfaceID,
		HostDevName: slot.TapName,
		// Static guest MAC derived from the slot so the host's DHCP /
		// static-IP machinery can key off it deterministically.
		// Phase 1 doesn't run DHCP, so this is mostly cosmetic, but
		// pinning the value keeps the guest's `ip addr` output
		// stable across restarts.
		GuestMAC: macFromSlot(slot),
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PutNetworkInterface: %w", err)
	}
	if err := client.PutVsock(ctx, firecracker.Vsock{
		GuestCID: int(slot.VsockCID),
		UDSPath:  hostVsockUDSName, // chroot-relative; jailer resolves it
	}); err != nil {
		return fmt.Errorf("firecracker runtime: PutVsock: %w", err)
	}
	return nil
}

// configureVMMForLoad is the snapshot-load sibling of configureVMM.
// Per the firecracker docs, the ONLY pre-LoadSnapshot REST call allowed
// is PutLogger (optional, debug-only); everything else — machine
// config, boot source, drives, network interfaces, vsock — comes from
// the snapshot state file. Restating any of those would be rejected
// by the API.
//
// Integrity verification happens here, on the host, before the load
// request is issued. A mismatch surfaces immediately as an error
// rather than letting firecracker mmap a corrupt snapshot.memory and
// fault later. The check is gated by SnapshotVerifyOnLoad so operators
// can bypass it for raw-load-cost benchmarking.
//
// EnableDiffSnapshots=true is set unconditionally: it costs nothing
// on the first load and is required for PR-B's per-clone CoW
// (writes hit a dirty bitmap rather than the shared memory file).
// ResumeVM=false keeps the clone paused so Create's caller controls
// when the guest's vCPUs actually start ticking.
func (d *Driver) configureVMMForLoad(ctx context.Context, client VMMClient, snap *TemplateResolution, overlayPath string) error {
	if snap == nil {
		return fmt.Errorf("firecracker runtime: configureVMMForLoad called with nil resolution")
	}
	if d.cfg.SnapshotVerifyOnLoad && snap.SnapshotChecksum != "" {
		if err := verifySnapshotChecksum(snap.SnapshotMemoryPath, snap.SnapshotStatePath, snap.SnapshotChecksum); err != nil {
			return fmt.Errorf("firecracker runtime: snapshot integrity: %w", err)
		}
	}
	if err := client.LoadSnapshot(ctx, firecracker.SnapshotLoad{
		SnapshotPath: snap.SnapshotStatePath,
		MemBackend: &firecracker.MemoryBackend{
			BackendType: "File",
			BackendPath: snap.SnapshotMemoryPath,
		},
		EnableDiffSnapshots: true,
		ResumeVM:            false,
	}); err != nil {
		return fmt.Errorf("firecracker runtime: LoadSnapshot: %w", err)
	}
	// Per-sandbox overlay swap. Firecracker's snapshot state captured
	// the overlay placeholder (1 MiB scratch from the template
	// build); PATCH the path to the per-sandbox file before Resume so
	// the guest's first write hits this clone's own backing store and
	// not the shared placeholder. Drive geometry (read-only flag,
	// cache type) is inherited from the snapshot state — only the
	// path is mutable post-load. The caller has already rejected this
	// request when snap.HasOverlay=false, so a missing placeholder
	// here is a corrupted template, not a user error.
	if overlayPath != "" {
		if err := client.PatchDrive(ctx, overlayDriveID, firecracker.DrivePatch{
			DriveID:    overlayDriveID,
			PathOnHost: overlayPath,
		}); err != nil {
			return fmt.Errorf("firecracker runtime: PatchDrive overlay: %w", err)
		}
	}
	return nil
}

// vsockHandshake dials the in-guest toolbox over AF_VSOCK and exchanges
// a Ping/Ok. The handshake is the canonical proof that the guest
// booted far enough to bring the toolbox up — without this, a guest
// that crashed during init would still register as "Running" because
// the firecracker process is alive.
//
// Protocol wire shape mirrors cmd/toolboxd/vsock.go:
//   - send: {"op":"ping"}\n
//   - recv: {"ok":true}\n
//
// We bound the whole handshake under a 5s deadline derived from ctx
// (or its own deadline if ctx has none). Cold-boot is usually under
// 500ms but the headroom keeps a slow host (CI under load) from
// flaking.
func (d *Driver) vsockHandshake(ctx context.Context, guestCID uint32) error {
	deadline := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < deadline {
			deadline = remaining
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	// The first connect after InstanceStart often races the guest's
	// vsock listener coming up. Retry on connection refused / EAGAIN
	// for up to the deadline. 50ms cadence matches WaitSocket.
	var (
		conn io.ReadWriteCloser
		err  error
	)
	for {
		conn, err = d.vsockDial.Dial(dialCtx, guestCID, defaultVsockPort)
		if err == nil {
			break
		}
		if dialCtx.Err() != nil {
			return fmt.Errorf("vsock dial cid=%d port=%d: %w", guestCID, defaultVsockPort, dialCtx.Err())
		}
		// Bounded sleep so a kernel that's permanently failing
		// doesn't burn the CPU.
		select {
		case <-dialCtx.Done():
			return fmt.Errorf("vsock dial cid=%d port=%d: %w (last error: %v)", guestCID, defaultVsockPort, dialCtx.Err(), err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer conn.Close()

	// Send Ping.
	if _, err := conn.Write([]byte(`{"op":"ping"}` + "\n")); err != nil {
		return fmt.Errorf("vsock write: %w", err)
	}
	// Read one line of response. bufio.Reader.ReadBytes('\n') matches
	// the toolbox's newline-delimited JSON convention.
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("vsock read: %w", err)
	}
	var resp struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("vsock decode: %w (raw=%q)", err, string(line))
	}
	if !resp.Ok {
		if resp.Error == "" {
			resp.Error = "guest returned ok=false"
		}
		return fmt.Errorf("vsock handshake rejected: %s", resp.Error)
	}
	return nil
}

// vcpuFromRequest rounds the user's fractional CPU request to a whole
// vCPU count Firecracker can accept. Firecracker has no CPU-quota
// concept like Docker — it allocates whole vCPUs. We round UP because
// rounding down would silently throttle a workload below what the
// caller paid for.
func vcpuFromRequest(cpu float64) int {
	if cpu <= 0 {
		return 1
	}
	whole := int(cpu)
	if float64(whole) < cpu {
		whole++
	}
	return whole
}

// defaultBootArgs returns the Linux kernel command line for Phase 1
// cold-boot VMMs. Mirrors the firecracker docs' recommended baseline
// plus our toolbox init:
//
//   - console=ttyS0: useful for early-boot panics on the firecracker
//     stdio (cappedBuffer captures these).
//   - reboot=k panic=1: convert kernel panics into a clean VMM exit
//     rather than a hung guest — the driver's cleanup contract relies
//     on the VMM process actually exiting on failure.
//   - pci=off: there's no PCI bus in the firecracker microVM model;
//     leaving it on costs boot time for no benefit.
//   - nomodules: rootfs has no /lib/modules tree.
//   - quiet: suppresses the spammy kernel boot lines.
const baseBootArgs = "console=ttyS0 reboot=k panic=1 pci=off nomodules quiet"

func defaultBootArgs() string {
	// Phase 1 does NOT pass an init= override yet — the kernel runs the
	// guest's normal /sbin/init. The toolbox-in-guest is responsible
	// for bringing up the vsock listener; how exactly that's wired
	// (systemd unit, /etc/inittab line, etc.) is a Phase 2 concern.
	return baseBootArgs
}

// macFromSlot derives a deterministic guest MAC from a Slot. The vsock
// CID is unique per slot per host, so embedding it into the MAC's
// final 4 bytes gives stable, collision-free MACs. The first byte
// (0x02) sets the locally-administered bit per IEEE 802.
func macFromSlot(slot *TapSlot) string {
	return fmt.Sprintf("02:00:00:%02x:%02x:%02x",
		byte(slot.VsockCID>>16),
		byte(slot.VsockCID>>8),
		byte(slot.VsockCID))
}

// ociImageRefFor expands a bare Docker-style image reference into a
// skopeo transport ref. The OCI builder requires the "docker://" (or
// "oci-archive:") prefix; sandbox callers pass refs without it.
//
// Edge cases:
//   - "docker://..." passes through unchanged (caller already
//     specified the transport).
//   - Anything else gets "docker://" prepended.
func ociImageRefFor(ref string) string {
	if ref == "" {
		return ""
	}
	// strings.HasPrefix would work but pulls in the strings package
	// for one comparison; inline the check.
	if len(ref) > 9 && ref[:9] == "docker://" {
		return ref
	}
	if len(ref) > 12 && ref[:12] == "oci-archive:" {
		return ref
	}
	return "docker://" + ref
}

// Start boots a previously-stopped Firecracker VMM. The model diverges
// slightly from Docker's: a stopped sandbox on the Firecracker path is a
// destroyed VMM (Firecracker VMMs do not survive a stop), so Start
// reconstructs from the persisted sandbox row + template. Phase 1
// supports cold-boot create + destroy only; Start is wired in the same
// shape Stop already is so the runtime.Runtime interface stays uniform,
// but Start-from-stopped is not part of Phase 1.
func (d *Driver) Start(_ context.Context, _ string) (*models.SandboxRuntimeState, error) {
	return nil, methodNotImplemented("Start")
}

// Stop sends a graceful shutdown to the VMM. Phase 1 implementation:
// signal SIGTERM to the firecracker process group with a short grace,
// then SIGKILL. The in-guest toolbox receives no pre-shutdown notice
// today (that's a Phase 3 vsock-op); the kernel sees SIGTERM as a
// virtio-disconnect and the guest goes through its normal shutdown
// path.
//
// Stop leaves the per-sandbox TAP, pool slot, and runDir in place —
// Destroy is the only call that releases them. Mirrors the Docker
// driver's Stop/Destroy split.
func (d *Driver) Stop(ctx context.Context, sandboxID string) error {
	d.mu.Lock()
	handle, ok := d.vmms[sandboxID]
	d.mu.Unlock()
	if !ok {
		// Stop on an unknown sandbox is a no-op rather than an error:
		// reconcile may call Stop on rows it has just learned of, and
		// a "missing VMM" condition is the same end state.
		return nil
	}
	if err := handle.Shutdown(ctx, 3*time.Second); err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: %w", sandboxID, err)
	}
	return nil
}

// Destroy tears down the VMM, releases the per-sandbox TAP/IP/vsock-CID
// back to their pools, removes the per-sandbox overlay file, and
// removes the host-side TAP device. Idempotent: calling Destroy on an
// already-destroyed sandbox is a no-op (the maps and the pool will all
// be empty).
//
// Cleanup order — inverse of Create:
//  1. shutdown the VMM (kills the process supervising the guest).
//  2. remove the host-side TAP device.
//  3. release the pool slot back to SQLite.
//  4. drop the per-sandbox runDir.
//  5. unregister from the in-memory maps.
//
// Each step's error is logged and we continue — a partial cleanup is
// better than aborting halfway and leaking resources on a daemon
// restart. The first error encountered is returned at the end so the
// caller can surface it; subsequent errors are logged.
func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	sandboxID := sandbox.ID
	d.mu.Lock()
	handle, hasHandle := d.vmms[sandboxID]
	delete(d.vmms, sandboxID)
	delete(d.clients, sandboxID)
	d.mu.Unlock()

	// Phase 5: tell the RSS sampler the VMM is gone so the next
	// sampleOnce drops its contribution to the host-pressure
	// aggregate. Unregister before Shutdown so a slow Shutdown can't
	// leave the sampler reading a dying pid for one extra tick.
	d.rssUnregister(sandboxID)

	var firstErr error
	rememberErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if hasHandle {
		if err := handle.Shutdown(ctx, 3*time.Second); err != nil {
			d.logger.Warn("firecracker destroy: shutdown failed",
				"sandbox_id", sandboxID, "error", err)
			rememberErr(err)
		}
	}

	// Look up the slot AFTER shutdown so the host-side TAP is removed
	// only after the firecracker process has released it — `ip link
	// delete` on a TAP still owned by a running VMM fails with EBUSY.
	// d.pool may be nil in unit tests that exercise Destroy on a
	// driver constructed without SetPool; treat it as "no slot to
	// release" rather than panicking.
	if d.pool != nil {
		slot, err := d.pool.Get(ctx, sandboxID)
		if err != nil {
			d.logger.Warn("firecracker destroy: pool get failed",
				"sandbox_id", sandboxID, "error", err)
			rememberErr(err)
		}
		if slot != nil && d.tapHost != nil {
			if err := d.tapHost.Remove(ctx, slot.TapName); err != nil {
				d.logger.Warn("firecracker destroy: tap remove failed",
					"sandbox_id", sandboxID, "tap", slot.TapName, "error", err)
				rememberErr(err)
			}
		}
		if err := d.pool.Release(ctx, sandboxID); err != nil {
			d.logger.Warn("firecracker destroy: pool release failed",
				"sandbox_id", sandboxID, "error", err)
			rememberErr(err)
		}
	}

	// Warm-VMM pool release (Phase 4 PR-B). Idempotent on sandboxes
	// that never went through the pool — Release with no row to
	// update is a no-op at the store layer (the WHERE filter just
	// matches zero rows). For sandboxes that DID acquire a warm slot,
	// this moves the row from 'allocated' to 'released'; the GC sweep
	// will drop the row after the TTL. The handle.Shutdown above
	// already brought the firecracker process down, so the pool's GC
	// drain on this row is a no-op for the in-memory handle map (it
	// was emptied at AcquireWithHandle time).
	if d.warmPool != nil {
		if err := d.warmPool.Release(ctx, sandboxID, time.Now().UTC()); err != nil {
			d.logger.Warn("firecracker destroy: warm pool release failed",
				"sandbox_id", sandboxID, "error", err)
			rememberErr(err)
		}
	}

	if hasHandle {
		if err := handle.Cleanup(); err != nil {
			d.logger.Warn("firecracker destroy: vmm cleanup failed",
				"sandbox_id", sandboxID, "error", err)
			rememberErr(err)
		}
	}
	return firstErr
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

// Inspect returns the runtime state of a single VMM. Cheap: one GET /
// against the API socket. Returns nil/nil when the sandbox isn't in
// the driver's registry — mirrors the Docker driver's behavior for a
// recently-destroyed sandbox.
func (d *Driver) Inspect(ctx context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	client, ok := d.clients[sandboxID]
	d.mu.Unlock()
	if !ok {
		return nil, nil
	}
	info, err := client.InstanceInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: inspect %s: %w", sandboxID, err)
	}
	return &models.SandboxRuntimeState{
		SandboxID: sandboxID,
		Status:    statusFromInstanceState(info.State),
	}, nil
}

// ListManaged enumerates every Firecracker VMM the driver knows about.
// Walks the in-memory registry (no SQLite hit) — reconcile uses this
// to compare driver state against the persisted row set.
func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	d.mu.Lock()
	ids := make([]string, 0, len(d.clients))
	clients := make([]VMMClient, 0, len(d.clients))
	for id, c := range d.clients {
		ids = append(ids, id)
		clients = append(clients, c)
	}
	d.mu.Unlock()

	out := make(map[string]*models.SandboxRuntimeState, len(ids))
	for i, id := range ids {
		info, err := clients[i].InstanceInfo(ctx)
		if err != nil {
			// One unreachable VMM doesn't fail the whole walk —
			// reconcile uses this as a snapshot, and a transient API
			// blip shouldn't mark every sandbox as unknown.
			d.logger.Warn("firecracker list_managed: inspect failed",
				"sandbox_id", id, "error", err)
			continue
		}
		out[id] = &models.SandboxRuntimeState{
			SandboxID: id,
			Status:    statusFromInstanceState(info.State),
		}
	}
	return out, nil
}

// statusFromInstanceState maps Firecracker's self-reported VMM state
// strings to our SandboxStatus enum. Unknown values map to "running"
// — better to optimistically reconcile against an in-progress state
// than to mark a sandbox as failed because a future firecracker
// release added a new state name we haven't taught the daemon.
func statusFromInstanceState(state string) models.SandboxStatus {
	switch state {
	case "Running":
		return models.SandboxStatusStarted
	case "Paused":
		return models.SandboxStatusStopped
	case "Not started":
		return models.SandboxStatusStopped
	default:
		return models.SandboxStatusStarted
	}
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

// linkOrCopyRootfs makes dst point at the same bytes as src. Hard-link
// first because it's O(1) and shares the underlying inode — the common
// case where TemplatesDir and RunDir are on the same filesystem (the
// installer's canonical layout). EXDEV (cross-device link) falls back
// to a streamed copy so a TemplatesDir on a different mount still
// works. The dst directory must already exist (the jailer/vmm setup
// path creates the runDir before Create reaches this helper).
//
// Per-sandbox writes don't go through this file — Phase 2 has no
// per-sandbox overlay yet, so the template rootfs is treated as the
// canonical disk. Phase 3 adds the overlay drive and the template
// rootfs becomes read-only in the guest. Until then, in-VM writes
// modify the host-side inode the link points at; the Phase 2 service
// rejects deletion-while-referenced so a guest can't pull the rootfs
// out from under another guest.
func linkOrCopyRootfs(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) && !errors.Is(err, os.ErrPermission) {
		// EXDEV → fall through to copy. ErrPermission also falls through
		// because filesystems like overlayfs and some FUSE mounts reject
		// link() with EPERM even within a single mount; copy is the
		// only path that always works.
		// Any other error (target exists, source missing, etc.) is a real
		// failure the caller should surface.
		return fmt.Errorf("link template rootfs: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open template rootfs: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create staged rootfs: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy template rootfs: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close staged rootfs: %w", err)
	}
	return nil
}
