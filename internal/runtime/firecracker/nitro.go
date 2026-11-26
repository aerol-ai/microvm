package firecracker

import (
	"context"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
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
//     warm VMM pool, no memory moves, and Stop cannot keep memory.
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
// build does not yet: Stop keeping the disk and Start cold-booting from it
// (plan §4.3), and a disk snapshot.
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
