package firecracker

// NestedVirt records the SB_FIRECRACKER_NESTED_VIRT setting a VM booted
// under. A saved VM (a template's snapshot, a stopped sandbox's) keeps the
// CPU flags it booted with, since a snapshot load restores them, so the
// record travels with the save and is checked against the setting of the
// node that loads it.
type NestedVirt string

const (
	// NestedVirtUnknown: saved before AerolVM recorded the setting. Those
	// VMs booted with whatever the host's KVM offered, which by default
	// includes nested virtualization (kvm_amd and, since Linux 4.20,
	// kvm_intel), so it counts as on.
	NestedVirtUnknown NestedVirt = ""
	// NestedVirtOff: the guest booted with the CPU's virtualization
	// extensions hidden (HideNestedVirt).
	NestedVirtOff NestedVirt = "off"
	// NestedVirtOn: the node allowed nested virtualization, so the guest
	// saw whatever the host's KVM offered.
	NestedVirtOn NestedVirt = "on"
)

// NestedVirtSetting is the record for a VM booted on a node whose
// SB_FIRECRACKER_NESTED_VIRT is allowed.
func NestedVirtSetting(allowed bool) NestedVirt {
	if allowed {
		return NestedVirtOn
	}
	return NestedVirtOff
}

// Matches reports whether a VM saved under n booted the way a node with
// SB_FIRECRACKER_NESTED_VIRT=nodeAllowed boots one. A node that hides
// nested virtualization matches only "off". A node that allows it matches
// anything but "off": an unknown save booted with it visible.
func (n NestedVirt) Matches(nodeAllowed bool) bool {
	if nodeAllowed {
		return n != NestedVirtOff
	}
	return n == NestedVirtOff
}

// HideNestedVirt is the CPU config that hides the CPU's virtualization
// extensions from the guest: Intel VMX (CPUID leaf 0x1, ECX bit 5) and AMD
// SVM (leaf 0x80000001, ECX bit 2). KVM lets a guest turn either on only
// when its CPUID has the flag (CR4.VMXE, EFER.SVME), so with both hidden
// the guest cannot run a guest of its own, and KVM's nested code is out of
// its reach. x86_64 only; both leaves exist on every x86_64 CPU, and
// neither has a subleaf index (flags 0).
func HideNestedVirt() CPUConfig {
	return CPUConfig{CPUIDModifiers: []CPUIDLeafModifier{
		{Leaf: "0x1", Subleaf: "0x0", Modifiers: []CPUIDRegisterModifier{{Register: "ecx", Bitmap: ClearBits(5)}}},
		{Leaf: "0x80000001", Subleaf: "0x0", Modifiers: []CPUIDRegisterModifier{{Register: "ecx", Bitmap: ClearBits(2)}}},
	}}
}
