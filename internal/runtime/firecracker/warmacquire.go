package firecracker

// warmacquire.go implements the Phase 4 PR-B Acquire side of the
// warm-VMM pool. Driver.Create calls tryAcquireWarm before the
// cold-spawn path; on a hit, the warm VMM gets PATCH'd with per-sandbox
// state and Resume'd, skipping the spawn + LoadSnapshot wall-clock
// that's the dominant cost of a snapshot-load Create today (~150ms+).
//
// What this file changes about the boot path:
//
//   - Spawn + WaitSocket: skipped. The pool's refill goroutine ran them
//     ahead of time; the slot row already has api_socket pointing at a
//     live, paused firecracker process.
//
//   - LoadSnapshot: skipped. The pool already issued it.
//
//   - PutNetworkInterface vs PatchDrive: the cold-boot path uses Put
//     before InstanceStart; the snapshot-load path uses Patch between
//     LoadSnapshot and Resume. The warm path is structurally the
//     snapshot-load path with the Load step pre-done — same PATCH+Resume
//     contract.
//
// Failure-path consistency (pr-review.md §4): every resource acquired
// in this file (TAP slot, host TAP, overlay file, registry entries) is
// cleaned up in LIFO order on error. The pool slot's row is moved back
// to 'released' so the GC sweep tears the VMM down — there is no path
// here that leaves a slot stuck in 'allocated' without a sandbox owner.

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// WarmPool is the seam Driver.Create uses to consult the warm-VMM
// pool. Production impl is *internal/pool/vmm.Pool; tests inject a
// fake that records Acquire/Release calls without touching SQLite.
//
// Declared as an interface so the runtime package keeps the
// import-cycle wall up the same way the TAP pool's TapPool seam does:
// internal/pool/vmm imports internal/store; the runtime package needs
// the SpawnedHandle/SnapshotInputs shapes (already imported via
// poolspawner.go) but should not depend on the Pool's full surface.
type WarmPool interface {
	AcquireWithHandle(ctx context.Context, templateID, sandboxID string, now time.Time) (*vmmpool.Slot, vmmpool.SpawnedHandle, error)
	Release(ctx context.Context, sandboxID string, now time.Time) error
}

// SetWarmPool injects the warm-VMM pool. Called once by main.go after
// both the pool and the spawner adapter are constructed. Nil leaves
// the driver in pre-pool mode: every snapshot-load Create runs the
// existing cold-spawn + LoadSnapshot path.
func (d *Driver) SetWarmPool(p WarmPool) { d.warmPool = p }

// tryAcquireWarm is Driver.Create's pool-hit fast path. Returns
// (state, true, nil) on hit (caller returns state immediately),
// (nil, false, nil) on miss (caller falls through to cold spawn),
// (nil, false, err) on error (caller surfaces the error).
//
// Eligibility — the warm path applies only when:
//
//  1. The warm pool is wired (d.warmPool != nil).
//  2. The request has a TemplateID.
//  3. The template was resolved and has a snapshot (HasSnapshot=true).
//  4. The overlay request is compatible with the template (the same
//     HasOverlay guard the cold snapshot-load path enforces — a
//     template without an overlay placeholder cannot accept a clone
//     with overlay_size_gb > 0).
//
// All four checks fail-soft to the cold-spawn path rather than erroring
// — operators have no way to know in advance whether a particular
// (template, request) combination will hit the pool, and surfacing
// "missed the pool" as a user-visible error would be a regression
// against the pre-pool behavior the daemon shipped with.
func (d *Driver) tryAcquireWarm(
	ctx context.Context,
	req models.CreateSandboxRequest,
	sandboxID string,
	snap *TemplateResolution,
	tapSlot *TapSlot,
	overlayPath string,
) (*models.SandboxRuntimeState, bool, error) {
	if d.warmPool == nil || req.TemplateID == "" || snap == nil || !snap.HasSnapshot {
		return nil, false, nil
	}
	if req.OverlaySizeGB > 0 && !snap.HasOverlay {
		// Same guard as the cold snapshot-load path. Surfacing this as
		// a hit would lead to a mid-PATCH failure; surfacing it as a
		// miss would silently downgrade the user's overlay request.
		// Returning an error is the only honest move.
		return nil, false, fmt.Errorf("firecracker runtime: template %q has no overlay drive in its snapshot state; rebuild template via POST /v1/templates to use overlay_size_gb",
			req.TemplateID)
	}

	slot, handle, err := d.warmPool.AcquireWithHandle(ctx, req.TemplateID, sandboxID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, vmmpool.ErrNoLoadedSlot) {
			// Empty pool — fall through to cold spawn. Not an error
			// path; the refill goroutine will catch up on its next
			// tick.
			d.logger.Info("firecracker create: warm pool miss",
				"sandbox_id", sandboxID, "template_id", req.TemplateID)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("firecracker runtime: warm pool acquire: %w", err)
	}

	d.logger.Info("firecracker create: warm pool hit",
		"sandbox_id", sandboxID, "template_id", req.TemplateID,
		"slot_id", slot.ID, "api_socket", slot.APISocket,
		"vsock_cid", slot.VsockCID)

	// From here on, any error must release the slot (move row to
	// 'released' so GC drops it AND the handle is Shutdown). The
	// flag-and-defer pattern mirrors the cold-spawn path's pool/tap/vmm
	// cleanup.
	committed := false
	defer func() {
		if committed {
			return
		}
		// Best-effort: release the row + drop the handle. The pool's
		// GC sweep would eventually catch a stuck 'allocated' row, but
		// a fast release frees the slot for the next Acquire instead
		// of waiting on the TTL.
		if relErr := d.warmPool.Release(context.Background(), sandboxID, time.Now().UTC()); relErr != nil {
			d.logger.Warn("firecracker create: warm acquire rollback (pool release)",
				"sandbox_id", sandboxID, "slot_id", slot.ID, "error", relErr)
		}
		if sErr := handle.Shutdown(context.Background(), 3*time.Second); sErr != nil {
			d.logger.Warn("firecracker create: warm acquire rollback (handle shutdown)",
				"sandbox_id", sandboxID, "slot_id", slot.ID, "error", sErr)
		}
	}()

	// Overlay file lives in the warm slot's RunDir so the firecracker
	// process (which runs under that chroot when jailer is enabled)
	// can open it. We're re-using the per-slot RunDir as the sandbox's
	// runtime directory for the lifetime of this Acquire.
	warmOverlayPath := overlayPath
	if req.OverlaySizeGB > 0 {
		warmOverlayPath = filepath.Join(slot.RunDir, overlayFileName)
		if err := allocateSparse(warmOverlayPath, int64(req.OverlaySizeGB)<<30); err != nil {
			return nil, false, fmt.Errorf("firecracker runtime: overlay alloc (warm): %w", err)
		}
		if d.cfg.OverlayMkfs {
			if d.cfg.Mkfs4Bin == "" {
				return nil, false, fmt.Errorf("firecracker runtime: SB_FIRECRACKER_OVERLAY_MKFS=true but SB_FIRECRACKER_MKFS_BIN is unset")
			}
			cmd := exec.CommandContext(ctx, d.cfg.Mkfs4Bin, "-F", warmOverlayPath)
			if out, mErr := cmd.CombinedOutput(); mErr != nil {
				return nil, false, fmt.Errorf("firecracker runtime: mkfs.ext4 overlay (warm): %w (stderr: %s)", mErr, strings.TrimSpace(string(out)))
			}
		}
	}

	// Construct a REST client against the warm slot's live API socket.
	// The pool already loaded the snapshot; this client only issues
	// PATCH + Action(Resume).
	client := d.newClient(slot.APISocket)

	// PATCH NetworkInterface: the snapshot's eth0 references the
	// defunct template-build TAP. Swap it for this sandbox's TAP.
	// Firecracker accepts the PATCH between LoadSnapshot and Resume
	// (the device's mac/iface_id are inherited from the snapshot
	// state; only host_dev_name is mutable post-load).
	if err := client.PutNetworkInterface(ctx, primaryIfaceID, firecracker.NetworkInterface{
		IfaceID:     primaryIfaceID,
		HostDevName: tapSlot.TapName,
	}); err != nil {
		// PutNetworkInterface is the wire op the firecracker REST
		// client uses for both Put (pre-Start) and Patch (post-Load).
		// On the warm path it's a PATCH — the device already exists
		// in the loaded snapshot state.
		return nil, false, fmt.Errorf("firecracker runtime: warm patch network interface: %w", err)
	}

	// PATCH overlay drive: same shape as the cold snapshot-load path.
	// The snapshot baked in the template's placeholder overlay; we
	// swap to this sandbox's per-sandbox file before Resume.
	if warmOverlayPath != "" {
		if err := client.PatchDrive(ctx, overlayDriveID, firecracker.DrivePatch{
			DriveID:    overlayDriveID,
			PathOnHost: warmOverlayPath,
		}); err != nil {
			return nil, false, fmt.Errorf("firecracker runtime: warm patch overlay drive: %w", err)
		}
	}

	// Resume the VMM. From the guest's perspective this is the first
	// instruction after the snapshot was taken — vCPUs start ticking
	// against the new TAP+overlay.
	if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionResume}); err != nil {
		return nil, false, fmt.Errorf("firecracker runtime: warm action Resume: %w", err)
	}

	// Vsock handshake — dial the snapshot's reserved CID. The pool
	// slot's vsock_cid IS the snapshot's CID (RecordLoaded copies it
	// from SnapshotInputs.VsockCID), so slot.VsockCID is what we
	// dial. Dialing tapSlot.VsockCID would race the guest, which is
	// listening on the snapshot's CID baked in at template build.
	if err := d.vsockHandshake(ctx, slot.VsockCID); err != nil {
		return nil, false, fmt.Errorf("firecracker runtime: warm vsock handshake: %w", err)
	}

	// post_resume reseed (RNG + wallclock). Best-effort; same shape
	// as the cold snapshot-load path.
	postCtx, cancel := context.WithTimeout(ctx, d.cfg.PostResumeTimeout)
	if err := d.sendVsockOp(postCtx, slot.VsockCID, "post_resume", map[string]any{
		"wallclock_unix_ns": time.Now().UnixNano(),
	}); err != nil {
		d.logger.Warn("firecracker create: warm post_resume send failed (continuing)",
			"sandbox_id", sandboxID, "error", err)
	}
	cancel()

	// Register the warm handle + client into the driver's map so
	// Destroy finds them. The handle is the SpawnedHandle from the
	// pool — its method set is a strict subset of VMMHandle (no
	// Start/WaitSocket/Kill/Cleanup/StderrTail), so we wrap it in a
	// shim that implements the unused methods as no-ops. The Destroy
	// path only calls Shutdown + Cleanup; both flow through.
	wrapped := &warmDestroyHandle{
		spawned:   handle,
		apiSocket: slot.APISocket,
		runDir:    slot.RunDir,
	}
	d.mu.Lock()
	d.clients[sandboxID] = client
	d.vmms[sandboxID] = wrapped
	d.mu.Unlock()

	// Phase 5: re-key the RSS sampler entry from the warm slot's id
	// to the claiming sandbox's id. WarmSpawn registered the slot
	// under slot.ID so its RSS counted toward host pressure while it
	// sat in the pool; now that a sandbox owns it, sampler metrics
	// (and Destroy's eventual Unregister(sandboxID)) need to follow
	// the sandbox. The pid is unchanged — same firecracker process.
	d.rssUnregister(slot.ID)
	d.rssRegister(sandboxID, handle.Pid())

	committed = true
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: slot.APISocket,
		ContainerIP: tapSlot.GuestIP,
		Status:      models.SandboxStatusStarted,
	}, true, nil
}

// warmDestroyHandle wraps a vmm pool SpawnedHandle into the runtime's
// fuller VMMHandle so the existing Destroy path can drive it
// transparently. The pool's contract gives us APISocket/RunDir/
// Shutdown; the Destroy path needs Start/WaitSocket/Kill/Cleanup/
// StderrTail too — all three of those are no-ops on a warm-acquired
// VMM because the supervisor lives inside the firecracker package
// the pool's PoolSpawner uses, and from this side we only ever ask
// it to stop (Shutdown).
type warmDestroyHandle struct {
	spawned   vmmpool.SpawnedHandle
	apiSocket string
	runDir    string
}

func (h *warmDestroyHandle) APISocket() string             { return h.apiSocket }
func (h *warmDestroyHandle) RunDir() string                { return h.runDir }
func (h *warmDestroyHandle) Pid() int                      { return h.spawned.Pid() }
func (h *warmDestroyHandle) Start(_ context.Context) error { return nil }
func (h *warmDestroyHandle) WaitSocket(_ context.Context, _ time.Duration) error {
	return nil
}
func (h *warmDestroyHandle) Shutdown(ctx context.Context, grace time.Duration) error {
	return h.spawned.Shutdown(ctx, grace)
}
func (h *warmDestroyHandle) Kill() error        { return nil }
func (h *warmDestroyHandle) Cleanup() error     { return nil }
func (h *warmDestroyHandle) StderrTail() string { return "" }
