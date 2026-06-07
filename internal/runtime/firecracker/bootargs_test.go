package firecracker

import (
	"strings"
	"testing"
)

// TestBootArgsKeepACPI is a security-relevant regression guard, not a
// formatting check. Firecracker exposes its VM Generation ID (vmgenid) via
// ACPI; a guest kernel with CONFIG_VMGENID reseeds the CRNG from it on
// snapshot restore *before userspace runs*, which is the only mechanism that
// closes the entropy window the post_resume reseed cannot (the guest is live
// between Action(Resume) and the post_resume ack — see Hazard 2 /
// "Entropy window" in the Snapshot Clone Correctness doc). Passing acpi=off
// on the kernel command line would silently kill that pre-userspace reseed
// and reintroduce duplicate-entropy-across-clones with no error. This test
// fails loudly if a future edit to baseBootArgs adds it.
func TestBootArgsKeepACPI(t *testing.T) {
	args := defaultBootArgs()

	if strings.Contains(args, "acpi=off") {
		t.Fatalf("boot args must not disable ACPI (vmgenid CRNG reseed depends on it): %q", args)
	}
	// off=acpi / acpi = off style variants aren't valid kernel cmdline, but
	// guard the obvious near-miss of a stray "acpi" key set to a disabling
	// value so the intent ("ACPI stays available for vmgenid") is explicit.
	if strings.Contains(args, "acpi=0") || strings.Contains(args, "noacpi") {
		t.Fatalf("boot args must keep ACPI available for vmgenid: %q", args)
	}
}
