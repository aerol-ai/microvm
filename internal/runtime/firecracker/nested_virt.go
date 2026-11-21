package firecracker

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"runtime"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

// Nested virtualization (a sandbox running a VM of its own) is off unless
// the node sets SB_FIRECRACKER_NESTED_VIRT: every VM this node boots gets
// a CPU config that hides the CPU's virtualization extensions, which keeps
// KVM's nested code (a recurring source of host kernel bugs) out of a
// guest's reach.
//
// A snapshot load restores the CPU flags its VM booted with, and Firecracker
// takes no CPU config on a load. So each saved VM records the setting it
// booted under (firecracker.NestedVirt), and the record follows the VM:
//
//   - A VM booted here (cold boot, a template's snapshot VM, the export
//     helper) gets this node's setting.
//   - A clone of a template snapshot gets the template's, and Create loads
//     only a template whose record matches this node: any other cold-boots
//     while the service saves the template's snapshot again. So a running
//     clone on this node always has this node's setting.
//   - A stopped sandbox keeps the CPU it started with, whatever this node's
//     setting: refusing it would lose the user's sandbox. Starting one that
//     sees nested virtualization on a node that hides it is logged and
//     counted (nestedVirtKeptStarts), and a move refuses to bring one saved
//     with nested virtualization on to such a node.
//   - The record of a running VM is kept in its VM record, so a restarted
//     sandboxd knows it when it later stops the VM.

// hostArch is runtime.GOARCH, replaced in tests. HideNestedVirt is CPUID,
// x86_64 only. arm64 needs nothing: Firecracker never asks KVM for EL2 for
// an arm64 guest, so it has no virtualization extensions to hide.
var hostArch = runtime.GOARCH

// nestedVirtKeptStarts counts starts of a stopped sandbox whose saved VM
// sees nested virtualization on a node that hides it: a VM saved before
// the setting existed, or on a node that allowed it. Each is the user's
// own VM, kept as it was until the sandbox is deleted.
var nestedVirtKeptStarts = expvar.NewInt("aerolvm_firecracker_nested_virt_kept_starts_total")

// errNestedVirtMoveRefused: a move would bring a VM saved with nested
// virtualization on to a node that hides it.
var errNestedVirtMoveRefused = errors.New("the sandbox's VM was saved with nested virtualization on, and this node hides it (SB_FIRECRACKER_NESTED_VIRT=false); move it to a node that allows it, or delete and recreate it")

// hostNestedVirt is the record for a VM this node boots.
func (d *Driver) hostNestedVirt() firecracker.NestedVirt {
	return firecracker.NestedVirtSetting(d.cfg.NestedVirt)
}

// configureGuestCPU hides nested virtualization from a VM this node boots,
// unless the node allows it. Call it after PutMachineConfig and before
// InstanceStart (Firecracker takes a CPU config only before boot, and a
// later PUT /machine-config resets it).
func (d *Driver) configureGuestCPU(ctx context.Context, client VMMClient) error {
	if d.cfg.NestedVirt || hostArch != "amd64" {
		return nil
	}
	if err := client.PutCPUConfig(ctx, firecracker.HideNestedVirt()); err != nil {
		return fmt.Errorf("PutCPUConfig (hide nested virtualization; SB_FIRECRACKER_NESTED_VIRT=true allows it): %w", err)
	}
	return nil
}

// vmNestedVirt is the record of a running VM: what its stop snapshot
// saves. Unknown for a VM a release before the record started.
func (d *Driver) vmNestedVirt(sandboxID string) firecracker.NestedVirt {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nestedVirt[sandboxID]
}

// noteKeptNestedVirt logs and counts the start of a stopped sandbox whose
// saved VM sees nested virtualization on a node that hides it.
func (d *Driver) noteKeptNestedVirt(sandboxID string, saved firecracker.NestedVirt) {
	if d.cfg.NestedVirt || saved == firecracker.NestedVirtOff {
		return
	}
	nestedVirtKeptStarts.Add(1)
	d.logger.Warn("firecracker start: this sandbox keeps nested virtualization; this node hides it from new VMs, but a stopped VM restarts with the CPU it was saved with. Delete and recreate the sandbox to apply the setting",
		"sandbox_id", sandboxID, "saved_nested_virt", nestedVirtLabel(saved))
}

// nestedVirtLabel names a record for a log line.
func nestedVirtLabel(n firecracker.NestedVirt) string {
	if n == firecracker.NestedVirtUnknown {
		return "unknown (saved before the setting was recorded)"
	}
	return string(n)
}

// templateNestedVirtMismatch reports why this node must not load a
// template's snapshot, or "" when it may.
func (d *Driver) templateNestedVirtMismatch(snap *TemplateResolution) string {
	if snap == nil || !snap.HasSnapshot || snap.SnapshotNestedVirt.Matches(d.cfg.NestedVirt) {
		return ""
	}
	return fmt.Sprintf("the template's snapshot was saved with nested virtualization %s, and this node (SB_FIRECRACKER_NESTED_VIRT=%t) boots VMs with it %s; its snapshot is saved again, and creates cold-boot until then",
		nestedVirtLabel(snap.SnapshotNestedVirt), d.cfg.NestedVirt, d.hostNestedVirt())
}
