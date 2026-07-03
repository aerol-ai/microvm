package firecracker

// warmspawn.go implements the Phase 4 PR-B WarmSpawn primitive: spawn
// a firecracker process, issue LoadSnapshot against a template's
// snapshot artifacts, and leave the VMM paused (ResumeVM=false). The
// returned handle is what the warm-VMM pool stores so a later sandbox
// create can claim it, PATCH per-sandbox state onto it, and PATCH /vm
// state=Resumed. Firecracker v1.15 requires TAP rebinding in
// LoadSnapshot.network_overrides, so this pool remains disabled by default
// until the warm path is redesigned around load-time TAP ownership.
//
// Cleanup contract: WarmSpawn is responsible for tearing down the
// firecracker process on any failure path after spawn. Success returns
// a handle whose Shutdown method the pool calls when it ages the slot
// out or the daemon shuts down — pkg/runtime/firecracker/seams.go's
// VMMHandle is the structural match for the *firecracker.vmm we
// produce here.
//
// Why no host TAP at WarmSpawn time: the template's snapshot state
// captures the network interface's host_dev_name pointing at the
// template-build TAP (which was torn down at the end of
// SnapshotTemplate). Firecracker v1.15 no longer lets Acquire patch
// host_dev_name after load, so this path is not suitable for production
// until the warm slot owns a valid load-time network override.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// WarmSpawnRequest is the per-slot input the pool's Spawner hands to
// the runtime. Mirrors vmm.SnapshotInputs from internal/pool/vmm but
// is declared here so the runtime package keeps its zero-imports-from-
// pool-vmm property (the pool imports nothing above store, and the
// runtime adapter — which lives in this package — translates between
// the two shapes).
type WarmSpawnRequest struct {
	SlotID             string
	TemplateID         string
	SnapshotMemoryPath string
	SnapshotStatePath  string
	SnapshotChecksum   string
	VsockCID           uint32
	HasOverlay         bool
}

// WarmHandle is the runtime-side handle the pool stores after a
// successful WarmSpawn. APISocket lets the Acquire-side code (in
// Driver.Create's pool-hit path) construct a fresh REST client
// against the paused VMM; RunDir gives the Acquire code a place to
// drop the per-sandbox overlay file. Shutdown is what the pool calls
// when it ages the slot out.
//
// This intentionally mirrors the existing VMMHandle interface in
// seams.go — the production type satisfies both via embedding. The
// separate name keeps the Spawner contract narrow (no Start /
// WaitSocket / Kill exposure into the pool layer).
type WarmHandle interface {
	APISocket() string
	RunDir() string
	Shutdown(ctx context.Context, grace time.Duration) error
	// Pid is the host PID of the paused firecracker process. PR 5-C
	// needs this so PoolSpawner can hand it to the RSS sampler (warm
	// slots count toward host memory pressure even before they're
	// claimed by a sandbox). See VMMHandle.Pid for the 0-sentinel
	// contract.
	Pid() int
}

// WarmSpawn produces a paused, snapshot-loaded firecracker process
// ready for the pool to hand to the Acquire-side code. The flow
// mirrors Driver.Create's snapshot-load steps up to (but not
// including) Resume:
//
//  1. Allocate a slot rundir via the same spawn seam Create uses
//     (creates the dir, returns a non-started handle).
//  2. Start the VMM process and wait for its API socket.
//  3. Optionally verify the snapshot checksums (SnapshotVerifyOnLoad).
//  4. LoadSnapshot with EnableDiffSnapshots=true, ResumeVM=false.
//  5. Return the handle without resuming — the Acquire code resumes.
//
// On any failure between Start and the final return, the spawned
// firecracker process is torn down and the rundir cleaned up so the
// pool never sees a leaked handle. The contract in spawner.go
// promises this and the GC sweep depends on it.
//
// Acquire-side responsibilities (NOT done here):
//
//   - Allocating the per-sandbox TAP slot. On Firecracker v1.15 this
//     must happen before LoadSnapshot, so the current warm path remains
//     disabled by default.
//
//   - Allocating the per-sandbox overlay file. The snapshot state
//     references the 1 MiB placeholder used at capture time; the
//     Acquire path PATCHes the drive's path_on_host before Resume.
//
//   - Issuing PATCH /vm state=Resumed and the vsock handshake.
func (d *Driver) WarmSpawn(ctx context.Context, req WarmSpawnRequest) (WarmHandle, error) {
	if d.cfg.KernelImage == "" {
		return nil, fmt.Errorf("firecracker warm-spawn: KernelImage not configured (SB_FIRECRACKER_KERNEL): %w",
			models.ErrRuntimeNotImplemented)
	}
	if req.SlotID == "" {
		return nil, errors.New("firecracker warm-spawn: slot id is empty")
	}
	if err := validateSandboxID(req.SlotID); err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: %w", err)
	}
	if req.SnapshotMemoryPath == "" || req.SnapshotStatePath == "" {
		return nil, errors.New("firecracker warm-spawn: snapshot paths are required")
	}
	if req.VsockCID < 3 {
		// Same guard as the template snapshotter; a CID below 3 means
		// the template was built incorrectly and the resulting handle
		// would be unreachable.
		return nil, fmt.Errorf("firecracker warm-spawn: VsockCID=%d is reserved (must be >= 3)", req.VsockCID)
	}

	// Step 1: spawn the VMM (creates the runDir we'll later use as
	// the overlay backing store + as the slot's identity in `ps`).
	handle, err := d.spawn(d.cfg, req.SlotID)
	if err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: spawn handle: %w", err)
	}
	// The cleanup closure is captured before any subsequent step so
	// every error path below can flip cleanupNeeded=true and let
	// defer do the work — same flag-and-defer pattern Driver.Create
	// uses (pr-review.md §4).
	cleanupNeeded := true
	defer func() {
		if !cleanupNeeded {
			return
		}
		// Best-effort process teardown. The VMM may or may not be
		// running depending on where we failed; Shutdown handles
		// both cases (it's a no-op if the process never started).
		_ = handle.Shutdown(context.Background(), 3*time.Second)
		if cErr := handle.Cleanup(); cErr != nil {
			d.logger.Warn("firecracker warm-spawn: cleanup failed",
				"slot_id", req.SlotID, "error", cErr)
		}
	}()

	// Step 2: start the firecracker process and wait for its API
	// socket to appear. The 5s ceiling matches Create's; cold-spawn
	// firecracker is sub-100ms on a healthy host.
	if err := handle.Start(ctx); err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: vmm start: %w", err)
	}
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: wait api socket: %w (stderr: %s)",
			err, handle.StderrTail())
	}

	// Step 3: optional snapshot integrity check. Same gate as
	// Driver.configureVMMForLoad uses — operators can bypass it for
	// raw-load-cost benchmarking via
	// SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD=false.
	//
	// Phase 6 PR-A: on ErrSnapshotCorrupt (checksum mismatch — wrapped
	// by verifySnapshotChecksum) notify the service layer so it can
	// transition the template to UNHEALTHY and kick a rebuild. Without
	// this hook the refill loop would spin forever on the same corrupt
	// template — the lister filters on status=ready and only the
	// service-side MarkSnapshotCorrupt moves the row out of ready.
	if d.cfg.SnapshotVerifyOnLoad && req.SnapshotChecksum != "" {
		if err := d.verifySnapshotForLoad(req.TemplateID, req.SnapshotMemoryPath, req.SnapshotStatePath, req.SnapshotChecksum); err != nil {
			if errors.Is(err, models.ErrSnapshotCorrupt) {
				d.notifyCorrupt(ctx, req.TemplateID, err.Error())
			}
			return nil, fmt.Errorf("firecracker warm-spawn: snapshot integrity: %w", err)
		}
	}

	// Step 4: LoadSnapshot. EnableDiffSnapshots=true unconditionally
	// (matches Driver.configureVMMForLoad — costs nothing on the
	// first load, required for CoW). ResumeVM=false keeps the VMM
	// paused so the Acquire code can PATCH per-sandbox state on top
	// of the snapshot's references before issuing Resume.
	client := d.newClient(handle.APISocket())
	snapshotMemoryPath, snapshotStatePath, err := d.stageSnapshotLoadPaths(handle.RunDir(), req.SnapshotMemoryPath, req.SnapshotStatePath)
	if err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: stage snapshot load artifacts: %w", err)
	}
	if req.HasOverlay {
		overlayPath := filepath.Join(handle.RunDir(), overlayFileName)
		if err := allocateSparse(overlayPath, overlayPlaceholderBytes); err != nil {
			return nil, fmt.Errorf("firecracker warm-spawn: overlay placeholder alloc: %w", err)
		}
		if _, err := d.chrootFilePath(handle.RunDir(), overlayPath, overlayFileName); err != nil {
			return nil, fmt.Errorf("firecracker warm-spawn: stage overlay placeholder: %w", err)
		}
	}
	if err := client.LoadSnapshot(ctx, firecracker.SnapshotLoad{
		SnapshotPath: snapshotStatePath,
		MemBackend: &firecracker.MemoryBackend{
			BackendType: "File",
			BackendPath: snapshotMemoryPath,
		},
		EnableDiffSnapshots: true,
		ResumeVM:            false,
	}); err != nil {
		return nil, fmt.Errorf("firecracker warm-spawn: LoadSnapshot: %w", err)
	}

	d.logger.Info("firecracker warm-spawn: paused VMM ready",
		"slot_id", req.SlotID, "template_id", req.TemplateID,
		"api_socket", handle.APISocket(), "vsock_cid", req.VsockCID)

	// Phase 5: register the warm slot with the RSS sampler under its
	// slot ID. The slot's firecracker process counts toward host memory
	// pressure from this moment, even before any sandbox claims it.
	// tryAcquireWarm re-keys (slotID → sandboxID) on hit; the GC-driven
	// Shutdown path uses warmHandle.Shutdown to clean up the slotID
	// entry. Nil-safe via rssRegister.
	d.rssRegister(req.SlotID, handle.Pid())

	cleanupNeeded = false
	return &warmHandle{handle: handle, driver: d, slotID: req.SlotID}, nil
}

// warmHandle wraps a VMMHandle and exposes only the narrow surface
// the pool consumes. Embedding rather than re-implementing keeps the
// production handle as the single source of truth for Shutdown
// semantics; the pool just sees APISocket / RunDir / Shutdown.
//
// driver + slotID are non-nil only on instances produced by WarmSpawn
// — Shutdown uses them to drop the slot's RSS sampler entry. On the
// GC-driven path the pool calls Shutdown directly without going
// through Driver.Destroy, so the sampler bookkeeping has to live here.
// After tryAcquireWarm re-keys the entry (slotID → sandboxID), an
// eventual Shutdown's Unregister(slotID) is a no-op (the sampler
// treats unknown ids as a no-op).
type warmHandle struct {
	handle VMMHandle
	driver *Driver
	slotID string
}

func (w *warmHandle) APISocket() string { return w.handle.APISocket() }
func (w *warmHandle) RunDir() string    { return w.handle.RunDir() }
func (w *warmHandle) Pid() int          { return w.handle.Pid() }
func (w *warmHandle) Shutdown(ctx context.Context, grace time.Duration) error {
	if w.driver != nil {
		w.driver.rssUnregister(w.slotID)
	}
	if err := w.handle.Shutdown(ctx, grace); err != nil {
		return err
	}
	// Drop the runDir too — the pool's GC sweep deletes the row, but
	// the on-disk firecracker chroot would persist until manual
	// cleanup without this. Best-effort: a stale dir is recoverable.
	if cErr := w.handle.Cleanup(); cErr != nil {
		return fmt.Errorf("warm handle cleanup: %w", cErr)
	}
	return nil
}
