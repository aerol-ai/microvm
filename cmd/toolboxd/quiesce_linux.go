//go:build linux

package main

// quiesce_linux.go is the Linux-only kernel-state resync layer for the
// vsock post_resume handler (Phase 3 PR-B). Two operations:
//
//   - SetWallclock: every snapshot clone resumes with the wall clock
//     pinned to the template's build time. Visible in logs and TLS
//     handshakes as a backwards jump. unix.ClockSettime forces
//     CLOCK_REALTIME to host-now; CAP_SYS_TIME is satisfied because
//     toolboxd runs as root inside the sandbox.
//
//   - ReseedRandom: every snapshot clone resumes with the template's
//     /dev/urandom entropy pool. Two clones of the same template
//     would draw identical bytes from getrandom(0), a real crypto
//     bug. RNDADDENTROPY forces the kernel to bump its entropy
//     estimate AND mix the supplied bytes into the input pool, so
//     the next getrandom reseeds the CSPRNG. Fresh entropy comes
//     from the host-attached virtio-rng device via /dev/random.

import (
	"crypto/rand"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxQuiesceOps is the concrete quiesceOps used inside the sandbox.
// Holds no state — all ops are syscalls against the running kernel.
type linuxQuiesceOps struct{}

// ReseedRandom mixes 32 fresh bytes of entropy into the kernel input
// pool and credits them as 256 bits. Forces the next getrandom call to
// reseed the CSPRNG so two clones drawing entropy after resume see
// distinct streams. Errors are returned but the caller logs and
// continues — a sandbox without fresh entropy is degraded, not broken.
func (linuxQuiesceOps) ReseedRandom() error {
	const entropyBytes = 32
	var buf [entropyBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Errorf("read entropy: %w", err)
	}

	// struct rnd_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
	// from <linux/random.h>. The header counts bits; we credited
	// entropyBytes * 8.
	const headerBytes = 8
	payload := make([]byte, headerBytes+entropyBytes)
	*(*int32)(unsafe.Pointer(&payload[0])) = int32(entropyBytes * 8)
	*(*int32)(unsafe.Pointer(&payload[4])) = int32(entropyBytes)
	copy(payload[headerBytes:], buf[:])

	f, err := os.OpenFile("/dev/random", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /dev/random: %w", err)
	}
	defer f.Close()
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(unix.RNDADDENTROPY),
		uintptr(unsafe.Pointer(&payload[0])),
	); errno != 0 {
		return fmt.Errorf("ioctl RNDADDENTROPY: %w", errno)
	}
	return nil
}

// SetWallclock pushes the kernel's CLOCK_REALTIME to the host-provided
// unix-ns timestamp. The host sends time.Now() at the moment of
// post_resume dispatch; sub-ms jitter is fine. The clock can jump
// either direction since the resume gap is positive but may be hours
// (overnight templates) or minutes (warm clones).
func (linuxQuiesceOps) SetWallclock(unixNs int64) error {
	if unixNs <= 0 {
		return fmt.Errorf("wallclock_unix_ns=%d is not positive", unixNs)
	}
	ts := unix.NsecToTimespec(unixNs)
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return fmt.Errorf("clock_settime: %w", err)
	}
	return nil
}

// newQuiesceOps returns the platform-specific quiesce implementation.
// Linux gets real syscalls; other platforms get the stub from
// quiesce_other.go.
func newQuiesceOps() quiesceOps { return linuxQuiesceOps{} }
