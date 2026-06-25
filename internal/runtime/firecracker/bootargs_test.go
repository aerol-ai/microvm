package firecracker

import (
	"runtime"
	"strings"
	"testing"
)

// TestBootArgsKeepVMGenidDelivery is a security-relevant regression guard, not a
// formatting check. Firecracker exposes its VM Generation ID (vmgenid) via ACPI
// on x86 and via FDT on aarch64; a guest kernel with CONFIG_VMGENID reseeds the
// CRNG from it on snapshot restore *before userspace runs*, which is the only
// mechanism that closes the entropy window the post_resume reseed cannot (the
// guest is live between PATCH /vm state=Resumed and the post_resume ack -- see Hazard 2 /
// "Entropy window" in the Snapshot Clone Correctness doc). Passing acpi=off on
// x86 would silently kill that pre-userspace reseed. This test fails loudly if
// a future edit to baseBootArgs breaks the arch-appropriate vmgenid delivery path.
func TestBootArgsKeepVMGenidDelivery(t *testing.T) {
	args := defaultBootArgs()

	switch runtime.GOARCH {
	case "arm64":
		if !strings.Contains(args, "console=ttyAMA0") {
			t.Fatalf("arm64 boot args must use ttyAMA0 console: %q", args)
		}
		if strings.Contains(args, "acpi=off") || strings.Contains(args, "acpi=0") || strings.Contains(args, "noacpi") {
			t.Fatalf("arm64 boot args must not disable ACPI-style vmgenid delivery: %q", args)
		}
	default:
		if strings.Contains(args, "acpi=off") {
			t.Fatalf("boot args must not disable ACPI (vmgenid CRNG reseed depends on it): %q", args)
		}
		if strings.Contains(args, "acpi=0") || strings.Contains(args, "noacpi") {
			t.Fatalf("boot args must keep ACPI available for vmgenid: %q", args)
		}
		if !strings.Contains(args, "console=ttyS0") {
			t.Fatalf("amd64 boot args must use ttyS0 console: %q", args)
		}
	}
}

func TestBaseBootArgsForArch(t *testing.T) {
	if got := baseBootArgsFor("amd64"); got != baseBootArgsAMD64 {
		t.Fatalf("amd64 = %q, want %q", got, baseBootArgsAMD64)
	}
	if got := baseBootArgsFor("arm64"); got != baseBootArgsARM64 {
		t.Fatalf("arm64 = %q, want %q", got, baseBootArgsARM64)
	}
}
