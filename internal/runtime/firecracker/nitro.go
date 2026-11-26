package firecracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The Nitro backend (plans/security-gaps-m1-m4.md §4.3): the same driver,
// with the VM run as a Nitro Sandbox through /dev/nitro_enclaves instead of
// on KVM, so ordinary (not metal) EC2 machines can run hardware-isolated
// sandboxes. A node is one backend or the other (SB_FIRECRACKER_BACKEND).
//
// What differs, all from Firecracker's Nitro Sandboxes guide
// (docs/nitro-sandboxes in firecracker v1.18+) and the SP-B spike:
//   - PUT /enclave before InstanceStart.
//   - No dirty-page tracking and no CPU template: Firecracker refuses both
//     at InstanceStart. The CPU template is what hides nested
//     virtualization on KVM (nested_virt.go), so it is skipped here.
//   - No memory snapshots and no paused state: no template snapshots, no
//     warm VMM pool, no memory moves. Stop keeps the disks and ends the VM;
//     Start boots it again from them (stopNitro, startNitro).
//   - The guest kernel is an EFI bzImage that needs PCI, so the boot line
//     drops pci=off.
//
// Every place below is a branch on d.nitro(); with the backend at kvm the
// KVM path runs exactly as before.

// nitroMinFirecracker is the first release with Nitro Sandboxes.
var nitroMinFirecracker = [3]int{1, 18, 0}

// nitro reports a driver on the Nitro backend.
func (d *Driver) nitro() bool { return d.cfg.Backend == config.FirecrackerBackendNitro }

// runtimeName is the runtime this driver's VMs are created as: a node
// offers only the name of its own backend.
func (d *Driver) runtimeName() string {
	if d.nitro() {
		return models.RuntimeFirecrackerNitro
	}
	return models.RuntimeFirecracker
}

// checkRuntimeFits refuses a create for the other backend's runtime. The
// service and placement already send each runtime only to a node that
// offers it; this is the driver's own guard, so a KVM create can never boot
// as a Nitro VM (no snapshots, no pause) or the other way round.
func (d *Driver) checkRuntimeFits(runtimeName string) error {
	if runtimeName == "" || runtimeName == d.runtimeName() {
		return nil
	}
	return fmt.Errorf("firecracker runtime: this node runs %q, not %q (SB_FIRECRACKER_BACKEND=%s): %w",
		d.runtimeName(), runtimeName, d.cfg.Backend, models.ErrRuntimeNotImplemented)
}

// errNitroUnsupported is the answer to an operation a Nitro VM cannot do.
// It wraps ErrRuntimeNotImplemented (501), as the isolate runtime's
// snapshot refusal does: the runtime cannot, whatever the caller retries.
func errNitroUnsupported(op string) error {
	return fmt.Errorf("runtime %q cannot %s: AWS Nitro VMs have no memory snapshots and no paused state: %w",
		models.RuntimeFirecrackerNitro, op, models.ErrRuntimeNotImplemented)
}

// errNitroNotYet is the answer to an operation a Nitro VM could do but this
// build does not yet: a disk snapshot (its export boots a helper VM the
// KVM way).
func errNitroNotYet(op string) error {
	return fmt.Errorf("runtime %q cannot %s yet on this build: %w",
		models.RuntimeFirecrackerNitro, op, models.ErrRuntimeNotImplemented)
}

// putEnclave is the last pre-boot call on the Nitro backend. CPU overcommit
// is always on: sandboxes ask for fractions of a CPU, and dedicated cores
// would need even vCPU counts on SMT machines and cap a node at its free
// cores (the SP-B spike ran this way).
func (d *Driver) putEnclave(ctx context.Context, client VMMClient) error {
	if !d.nitro() {
		return nil
	}
	if err := client.PutEnclave(ctx, firecracker.Enclave{
		DirectMode:    d.cfg.NitroMode != config.FirecrackerNitroModeConfidential,
		CPUOvercommit: true,
	}); err != nil {
		return fmt.Errorf("PutEnclave (SB_FIRECRACKER_BACKEND=nitro, mode %s): %w", d.cfg.NitroMode, err)
	}
	return nil
}

// bootArgs is the guest kernel's command line for a cold boot. A Nitro
// guest finds its virtio devices on PCI, so pci=off would leave it with no
// disk, network or vsock.
func (d *Driver) bootArgs(slot *TapSlot) string {
	args := coldBootArgs(slot, d.cfg.ToolboxBinaryPath != "")
	if d.nitro() {
		args = withoutBootArg(args, "pci=off")
	}
	return args
}

func withoutBootArg(args, drop string) string {
	fields := strings.Fields(args)
	out := fields[:0]
	for _, f := range fields {
		if f != drop {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// nitroHealth is RuntimeHealth on the Nitro backend: the binaries are there
// and Firecracker is new enough. KVM's vmgenid check guards the restore of
// a snapshot clone; a Nitro VM is never restored, so it does not apply.
func (d *Driver) nitroHealth(ctx context.Context) error {
	return d.requireFirecrackerVersion(ctx, "the Nitro backend", nitroMinFirecracker[0], nitroMinFirecracker[1], nitroMinFirecracker[2])
}

// adoptRemedyColdStart is the remedy when a Nitro start's agent cannot be
// adopted: its disk holds an agent from before identity delivery.
const adoptRemedyColdStart = "this stopped sandbox's disk holds the old agent; destroy it and create a new one"

// errNitroStartNeedsEnv: a Nitro start boots the guest afresh, so it must
// hand the agent the sandbox's env again (StartWithIdentityEnv). A start
// that cannot is refused, never given a sandbox without its env.
var errNitroStartNeedsEnv = fmt.Errorf("runtime %q: a start must carry the sandbox's env (StartWithIdentityEnv): %w",
	models.RuntimeFirecrackerNitro, models.ErrRuntimeNotImplemented)

// stopNitro is Stop on the Nitro backend: the guest flushes and freezes its
// root filesystem, the VM is ended, and its disks are kept with the VM's
// shape, so Start can boot it again (startNitro). Its memory and running
// programs end, as a container's do; the TAP slot stays the sandbox's, so
// it comes back with the same address.
//
// The freeze must work. A KVM stop goes on without it (the saved memory
// holds the writes not yet on disk); a Nitro stop has no memory to save,
// so it would lose them. A stop whose freeze failed is refused and the
// sandbox runs on; destroying it is always possible.
//
// After the VM is ended, a failure to keep its disks leaves them in the
// VM's run folder (not cleaned) and returns the error: nothing is deleted,
// and Destroy removes the folder as for any sandbox.
func (d *Driver) stopNitro(ctx context.Context, sandboxID string) error {
	if err := validateSandboxID(sandboxID); err != nil {
		return fmt.Errorf("firecracker runtime: stop: %w", err)
	}
	if _, err := d.sandboxSnapshotBase(); err != nil {
		return err
	}
	if d.pool == nil || d.tapHost == nil {
		return fmt.Errorf("firecracker runtime: stop: TAP pool or host manager not registered (main.go must call SetPool and SetTapHost): %w",
			models.ErrRuntimeNotImplemented)
	}
	d.mu.Lock()
	client, hasClient := d.clients[sandboxID]
	handle, hasHandle := d.vmms[sandboxID]
	guestCID := d.guestCID[sandboxID]
	d.mu.Unlock()
	if !hasClient || !hasHandle {
		if _, err := d.readSandboxSnapshotManifest(sandboxID); err == nil {
			return nil // already stopped: a retry
		}
		return fmt.Errorf("firecracker runtime: stop %s: VMM is not registered and no stopped disk exists", sandboxID)
	}
	slot, err := d.pool.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("firecracker runtime: stop %s: tap lookup: %w", sandboxID, err)
	}
	if slot == nil {
		return fmt.Errorf("firecracker runtime: stop %s: tap slot missing; refusing a stop it could not start again", sandboxID)
	}
	if guestCID < 3 {
		guestCID = slot.VsockCID
	}
	vsockPath := filepath.Join(handle.RunDir(), hostVsockUDSName)
	if err := d.sendVsockOp(ctx, vsockPath, guestCID, "pre_snapshot", nil); err != nil {
		d.logger.Warn("firecracker stop: pre_snapshot send failed (continuing)", "sandbox_id", sandboxID, "error", err)
	}
	flush := d.freezeForStop(ctx, sandboxID, vsockPath, guestCID)
	if flush != guestFlushDone {
		// freezeForStop already thawed a failed freeze.
		return fmt.Errorf("firecracker runtime: stop %s: the guest did not flush its disk (%s), so the sandbox keeps running rather than lose its last writes; try again, or destroy it", sandboxID, flush)
	}
	mc, err := client.GetMachineConfig(ctx)
	if err != nil || mc.VcpuCount < 1 || mc.MemSizeMib < 1 {
		d.thawGuest(sandboxID, vsockPath, guestCID)
		if err == nil {
			err = fmt.Errorf("the VMM reported %d vCPUs and %d MiB", mc.VcpuCount, mc.MemSizeMib)
		}
		return fmt.Errorf("firecracker runtime: stop %s: read the VM's shape: %w", sandboxID, err)
	}
	// No paused state and no Ctrl-Alt-Del on Nitro: the VM ends with its
	// process. Its root filesystem is frozen, so the disk is whole.
	if err := handle.Shutdown(ctx, 3*time.Second); err != nil {
		if killErr := handle.Kill(); killErr != nil {
			d.thawGuest(sandboxID, vsockPath, guestCID)
			return fmt.Errorf("firecracker runtime: stop %s: shutdown failed: %w; kill failed: %v", sandboxID, err, killErr)
		}
	}
	d.unregister(sandboxID)
	d.budget.release(sandboxID) // its enclave ended with it
	if err := d.writeStopDir(ctx, sandboxID, handle.RunDir(), func(string) (sandboxSnapshotManifest, []string, error) {
		return sandboxSnapshotManifest{
			Version:    1,
			SandboxID:  sandboxID,
			VsockCID:   guestCID,
			CreatedAt:  time.Now().UTC(),
			GuestFlush: flush,
			Cold:       true,
			VcpuCount:  mc.VcpuCount,
			MemSizeMib: mc.MemSizeMib,
		}, nil, nil
	}); err != nil {
		d.logger.Error("firecracker stop: the VM ended but its disks could not be kept; they stay in its run folder until it is destroyed",
			"sandbox_id", sandboxID, "run_dir", handle.RunDir(), "error", err)
		return err
	}
	if err := d.tapHost.Remove(ctx, slot.TapName); err != nil {
		d.logger.Warn("firecracker stop: tap remove failed", "sandbox_id", sandboxID, "tap", slot.TapName, "error", err)
	}
	if err := handle.Cleanup(); err != nil {
		d.logger.Warn("firecracker stop: vmm cleanup failed", "sandbox_id", sandboxID, "error", err)
	}
	return nil
}

// startNitro is Start of a stopped Nitro sandbox: the cold boot Create
// does, from the disks stopNitro kept, on the sandbox's own TAP slot, then
// the same post-boot steps (network re-applied, env, the sandbox's token).
// The kept disks stay until the next Stop replaces them or Destroy; the VM
// boots from copies, so a failed start leaves them as they were.
func (d *Driver) startNitro(ctx context.Context, sandboxID, toolboxToken string, loadEnv sbruntime.AdoptEnvLoader) (*models.SandboxRuntimeState, error) {
	if loadEnv == nil {
		return nil, errNitroStartNeedsEnv
	}
	if strings.TrimSpace(toolboxToken) == "" {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, errGuestTokenMissing)
	}
	manifest, err := d.readSandboxSnapshotManifest(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, err)
	}
	if !manifest.Cold || manifest.VcpuCount < 1 || manifest.MemSizeMib < 1 {
		return nil, fmt.Errorf("firecracker runtime: start %s: it was not stopped by a Nitro node (no kept disk and VM shape); destroy it and create a new one", sandboxID)
	}
	_, _, _, keptRootfs, keptOverlay, _ := d.sandboxSnapshotPaths(sandboxID)
	if _, err := os.Stat(keptRootfs); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: kept rootfs missing: %w", sandboxID, err)
	}
	if manifest.HasOverlay {
		if _, err := os.Stat(keptOverlay); err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: kept overlay missing: %w", sandboxID, err)
		}
	}
	slot, err := d.pool.Get(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap lookup: %w", sandboxID, err)
	}
	if slot == nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap slot missing; cannot start with the sandbox's address", sandboxID)
	}
	if err := d.budget.reserve(sandboxID, manifest.VcpuCount, manifest.MemSizeMib); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			d.budget.release(sandboxID)
		}
	}()
	handle, err := d.spawn(d.cfg, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: spawn handle: %w", sandboxID, err)
	}
	defer func() {
		if committed {
			return
		}
		_ = handle.Shutdown(context.Background(), 3*time.Second)
		if err := handle.Cleanup(); err != nil {
			d.logger.Warn("firecracker start: vmm cleanup after error failed", "sandbox_id", sandboxID, "error", err)
		}
	}()
	if err := os.MkdirAll(handle.RunDir(), 0o755); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: create runDir %s: %w", sandboxID, handle.RunDir(), err)
	}
	rootfsPath := filepath.Join(stageDirOf(handle), rootfsFileName)
	if err := copyFile(keptRootfs, rootfsPath); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: stage kept rootfs: %w", sandboxID, err)
	}
	var overlayPath string
	if manifest.HasOverlay {
		overlayPath = filepath.Join(stageDirOf(handle), overlayFileName)
		if err := copyFile(keptOverlay, overlayPath); err != nil {
			return nil, fmt.Errorf("firecracker runtime: start %s: stage kept overlay: %w", sandboxID, err)
		}
	}
	if err := d.tapHost.Ensure(ctx, *slot); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: tap host ensure %s: %w", sandboxID, slot.TapName, err)
	}
	tapCommitted := false
	defer func() {
		if tapCommitted {
			return
		}
		if err := d.tapHost.Remove(context.Background(), slot.TapName); err != nil {
			d.logger.Warn("firecracker start: tap remove after error failed", "sandbox_id", sandboxID, "tap", slot.TapName, "error", err)
		}
	}()
	if err := handle.Start(ctx); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: vmm start: %w", sandboxID, err)
	}
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: wait api socket: %w (stderr: %s)", sandboxID, err, handle.StderrTail())
	}
	client := d.newClient(handle.APISocket())
	// vcpuFromRequest(n) is n for a whole n: the VM gets the shape it had.
	shape := models.CreateSandboxRequest{CPU: float64(manifest.VcpuCount), MemoryMB: manifest.MemSizeMib}
	if err := d.configureVMM(ctx, client, shape, rootfsPath, slot, overlayPath); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, err)
	}
	if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionInstanceStart}); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: action InstanceStart: %w", sandboxID, err)
	}
	if err := shareSockets(ctx, handle); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: share the VM's sockets: %w", sandboxID, err)
	}
	vsockPath := filepath.Join(handle.RunDir(), hostVsockUDSName)
	if err := d.vsockHandshake(ctx, vsockPath, slot.VsockCID); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: vsock handshake: %w", sandboxID, err)
	}
	postCtx, cancel := context.WithTimeout(ctx, d.cfg.PostResumeTimeout)
	if err := d.sendVsockOp(postCtx, vsockPath, slot.VsockCID, "post_resume", postResumeData(slot)); err != nil {
		d.logger.Warn("firecracker start: post_resume send failed (continuing)", "sandbox_id", sandboxID, "error", err)
	}
	cancel()
	env, err := loadEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: load env: %w", sandboxID, err)
	}
	if err := d.deliverGuestEnv(ctx, vsockPath, slot.VsockCID, sandboxID, env); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, err)
	}
	if err := d.adoptGuest(ctx, vsockPath, slot.VsockCID, sandboxID, toolboxToken, adoptRemedyColdStart); err != nil {
		return nil, fmt.Errorf("firecracker runtime: start %s: %w", sandboxID, err)
	}
	d.scheduleToolboxTCPProbe("start", sandboxID, slot, false)
	d.register(sandboxID, client, handle, slot.VsockCID, true, d.hostNestedVirt())
	tapCommitted = true
	committed = true
	d.logger.Info("firecracker start: booted again from its kept disk (nitro)", "sandbox_id", sandboxID, "guest_ip", slot.GuestIP, "tap", slot.TapName)
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: handle.APISocket(),
		ContainerIP: slot.GuestIP,
		Status:      models.SandboxStatusStarted,
	}, nil
}
