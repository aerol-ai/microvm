//go:build linux

package main

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReseedRandomForcesCRNGReseed verifies ReseedRandom credits the pool
// (RNDADDENTROPY) AND forces an immediate reseed (RNDRESEEDCRNG), in that
// order. The ordering matters: crediting after the forced reseed would
// leave the CRNG one interval behind. The ioctl seam is stubbed so the
// test needs neither a real kernel nor CAP_SYS_ADMIN.
func TestReseedRandomForcesCRNGReseed(t *testing.T) {
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })

	var requests []uintptr
	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		requests = append(requests, request)
		return 0
	}

	if err := (linuxQuiesceOps{}).ReseedRandom(); err != nil {
		t.Fatalf("ReseedRandom: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("ioctl call count = %d, want 2 (RNDADDENTROPY, RNDRESEEDCRNG)", len(requests))
	}
	if requests[0] != uintptr(unix.RNDADDENTROPY) {
		t.Errorf("first ioctl = %#x, want RNDADDENTROPY %#x", requests[0], uintptr(unix.RNDADDENTROPY))
	}
	if requests[1] != uintptr(unix.RNDRESEEDCRNG) {
		t.Errorf("second ioctl = %#x, want RNDRESEEDCRNG %#x", requests[1], uintptr(unix.RNDRESEEDCRNG))
	}
}

// TestReseedRandomToleratesOldKernel asserts a missing RNDRESEEDCRNG
// (kernels < 5.10 answer ENOTTY) is a soft degrade, not a failure: the
// entropy was already credited by RNDADDENTROPY.
func TestReseedRandomToleratesOldKernel(t *testing.T) {
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })

	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDRESEEDCRNG) {
			return syscall.ENOTTY
		}
		return 0
	}

	if err := (linuxQuiesceOps{}).ReseedRandom(); err != nil {
		t.Fatalf("ReseedRandom should tolerate missing RNDRESEEDCRNG: %v", err)
	}
}

// TestReseedRandomSurfacesAddEntropyFailure asserts the load-bearing op
// (RNDADDENTROPY) failing is surfaced — a clone with no fresh entropy is
// the bug we are guarding against.
func TestReseedRandomSurfacesAddEntropyFailure(t *testing.T) {
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })

	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDADDENTROPY) {
			return syscall.EPERM
		}
		return 0
	}

	if err := (linuxQuiesceOps{}).ReseedRandom(); err == nil {
		t.Fatal("ReseedRandom should surface RNDADDENTROPY failure, got nil")
	}
}
