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
//     bug. RNDADDENTROPY credits the kernel input pool with fresh
//     bytes; RNDRESEEDCRNG then forces the CRNG to consume them
//     immediately so the next getrandom returns a clone-distinct
//     stream. Fresh entropy comes from the host-attached virtio-rng
//     device via /dev/random.

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctlPtr is the syscall seam ReseedRandom uses for both the
// RNDADDENTROPY and RNDRESEEDCRNG ioctls. A package var so the linux
// unit test (quiesce_linux_test.go) can assert both fire — in order —
// without a real kernel or CAP_SYS_ADMIN. Production wires the real
// SYS_IOCTL.
var ioctlPtr = func(fd, request, arg uintptr) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, arg)
	return errno
}

// linuxQuiesceOps is the concrete quiesceOps used inside the sandbox.
// Holds no state — all ops are syscalls against the running kernel.
type linuxQuiesceOps struct{}

// ReseedRandom mixes 32 fresh bytes of entropy into the kernel input
// pool and then forces the CRNG to reseed from it, so two clones drawing
// entropy after resume see distinct streams. Errors are returned but the
// caller logs and continues — a sandbox without fresh entropy is
// degraded, not broken.
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

	// Step 1: credit the input pool. This is the load-bearing op — if it
	// fails the clone has no fresh entropy, so surface the error.
	if errno := ioctlPtr(
		f.Fd(),
		uintptr(unix.RNDADDENTROPY),
		uintptr(unsafe.Pointer(&payload[0])),
	); errno != 0 {
		return fmt.Errorf("ioctl RNDADDENTROPY: %w", errno)
	}

	// Step 2: force an immediate CRNG reseed. RNDADDENTROPY only credits
	// the pool; on kernels < 5.18 the CRNG may not reseed from it until
	// its own interval elapses, leaving a window where two clones'
	// getrandom() still return the pre-snapshot stream. RNDRESEEDCRNG
	// (Linux >= 5.10) closes that window. The request arg is ignored.
	// Older kernels lack the ioctl and answer ENOTTY/EINVAL — tolerate
	// that: the entropy is already credited and the CRNG will reseed on
	// schedule, so it's a soft degrade, not a failure.
	if errno := ioctlPtr(f.Fd(), uintptr(unix.RNDRESEEDCRNG), 0); errno != 0 &&
		errno != syscall.ENOTTY && errno != syscall.EINVAL {
		return fmt.Errorf("ioctl RNDRESEEDCRNG: %w", errno)
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

func (linuxQuiesceOps) ConfigureNetwork(cfg guestNetworkConfig) error {
	if cfg.GuestIP == "" || cfg.GatewayIP == "" || cfg.PrefixLen <= 0 {
		return fmt.Errorf("incomplete network config: %+v", cfg)
	}
	iface, err := firstNonLoopbackInterface()
	if err != nil {
		return err
	}

	if ipBin, err := lookNetworkBinary("ip"); err == nil {
		_ = runNetworkCmd(ipBin, "link", "set", "lo", "up")
		_ = runNetworkCmd(ipBin, "link", "set", iface, "up")
		addr := fmt.Sprintf("%s/%d", cfg.GuestIP, cfg.PrefixLen)
		if err := runNetworkCmdIgnoreExists(ipBin, "addr", "add", addr, "dev", iface); err != nil {
			return err
		}
		_ = runNetworkCmd(ipBin, "route", "replace", "default", "via", cfg.GatewayIP, "dev", iface)
		return nil
	}

	ifconfigBin, err := lookNetworkBinary("ifconfig")
	if err != nil {
		return fmt.Errorf("no ip or ifconfig binary found")
	}
	_ = runNetworkCmd(ifconfigBin, "lo", "up")
	if cfg.Netmask != "" {
		if err := runNetworkCmd(ifconfigBin, iface, cfg.GuestIP, "netmask", cfg.Netmask, "up"); err != nil {
			return err
		}
	} else if err := runNetworkCmd(ifconfigBin, iface, cfg.GuestIP, "up"); err != nil {
		return err
	}
	if routeBin, err := lookNetworkBinary("route"); err == nil {
		_ = runNetworkCmdIgnoreExists(routeBin, "add", "default", "gw", cfg.GatewayIP, iface)
	}
	return nil
}

func firstNonLoopbackInterface() (string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", fmt.Errorf("read /sys/class/net: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "" && name != "lo" {
			return name, nil
		}
	}
	return "", fmt.Errorf("no non-loopback interface found")
}

func runNetworkCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runNetworkCmdIgnoreExists(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(strings.ToLower(text), "exists") {
		return nil
	}
	return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, text)
}

func lookNetworkBinary(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/sbin", "/bin", "/usr/sbin", "/usr/bin"} {
		p := dir + "/" + name
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

// newQuiesceOps returns the platform-specific quiesce implementation.
// Linux gets real syscalls; other platforms get the stub from
// quiesce_other.go.
func newQuiesceOps() quiesceOps { return linuxQuiesceOps{} }
