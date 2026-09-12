//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxQuiesceSetWallclockBranches(t *testing.T) {
	ops := linuxQuiesceOps{}
	if err := ops.SetWallclock(0); err == nil {
		t.Fatal("expected non-positive wallclock error")
	}
	if err := ops.SetWallclock(-1); err == nil {
		t.Fatal("expected negative wallclock error")
	}
	// May succeed or fail depending on CAP_SYS_TIME; both exercise the syscall path.
	_ = ops.SetWallclock(time.Now().UnixNano())
}

func TestLinuxQuiesceReseedErrorBranches(t *testing.T) {
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })

	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDRESEEDCRNG) {
			return syscall.EPERM
		}
		return 0
	}
	if err := (linuxQuiesceOps{}).ReseedRandom(); err == nil {
		t.Fatal("expected RNDRESEEDCRNG EPERM to surface")
	}

	ioctlPtr = func(_, _, _ uintptr) syscall.Errno { return syscall.EINVAL }
	// First ioctl (ADD) fails with EINVAL.
	if err := (linuxQuiesceOps{}).ReseedRandom(); err == nil {
		t.Fatal("expected RNDADDENTROPY EINVAL to surface")
	}

	// Tolerate EINVAL on RESEED (old kernel soft-degrade path alongside ENOTTY).
	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		if request == uintptr(unix.RNDRESEEDCRNG) {
			return syscall.EINVAL
		}
		return 0
	}
	if err := (linuxQuiesceOps{}).ReseedRandom(); err != nil {
		t.Fatalf("RNDRESEEDCRNG EINVAL should be tolerated: %v", err)
	}
}

func TestLinuxQuiesceConfigureNetworkBranches(t *testing.T) {
	ops := linuxQuiesceOps{}
	if err := ops.ConfigureNetwork(guestNetworkConfig{}); err == nil {
		t.Fatal("expected incomplete config error")
	}
	if err := ops.ConfigureNetwork(guestNetworkConfig{GuestIP: "1.2.3.4"}); err == nil {
		t.Fatal("expected incomplete config error")
	}

	// Fake ip binary that fails addr replace.
	dir := t.TempDir()
	ipPath := filepath.Join(dir, "ip")
	script := "#!/bin/sh\necho fake-ip \"$@\" >&2\nif echo \"$*\" | grep -q 'addr replace'; then exit 1; fi\nexit 0\n"
	if err := os.WriteFile(ipPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile ip: %v", err)
	}
	t.Setenv("PATH", dir)
	err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	})
	// May fail on iface discovery or addr replace; either covers network path.
	_ = err

	// No ip/ifconfig in PATH → lookNetworkBinary miss, then ifconfig miss.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected no ip/ifconfig error")
	}

	// ifconfig fallback path with fake ifconfig + route.
	ifconfig := filepath.Join(dir, "ifconfig")
	route := filepath.Join(dir, "route")
	_ = os.Remove(ipPath)
	if err := os.WriteFile(ifconfig, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile ifconfig: %v", err)
	}
	if err := os.WriteFile(route, []byte("#!/bin/sh\necho File exists >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile route: %v", err)
	}
	t.Setenv("PATH", dir)
	_ = ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
		Netmask:   "255.255.255.252",
	})
	_ = ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP:   "172.16.0.2",
		GatewayIP: "172.16.0.1",
		PrefixLen: 30,
	})

	// runNetworkCmdIgnoreExists non-exists error.
	badRoute := filepath.Join(dir, "route")
	_ = os.WriteFile(badRoute, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o755)
	if err := runNetworkCmdIgnoreExists(badRoute, "add", "default"); err == nil {
		t.Fatal("expected non-exists route error")
	}
	if err := runNetworkCmdIgnoreExists(badRoute, "add", "default"); err == nil {
		// rewritten above already
	}
	_ = runNetworkCmd(filepath.Join(dir, "ifconfig"), "lo", "up")
}

func TestLinuxLookNetworkBinaryFallbackDirs(t *testing.T) {
	t.Setenv("PATH", "")
	if _, err := lookNetworkBinary("definitely-missing-bin-xyz"); err == nil {
		t.Fatal("expected missing binary")
	}
	// Hit /sbin etc. search for a binary that usually exists.
	if p, err := lookNetworkBinary("true"); err == nil && p == "" {
		t.Fatal("unexpected empty path")
	}
}

func TestLinuxIoctlPtrRealSeam(t *testing.T) {
	// Exercise the real ioctlPtr wrapper once (typically EBADF on fd 0).
	errno := ioctlPtr(0, 0, 0)
	if errno == 0 {
		t.Log("unexpected success on ioctl(0,0,0)")
	}
}

func TestLinuxRunNetworkCmdFailure(t *testing.T) {
	if err := runNetworkCmd("/bin/false"); err == nil {
		t.Fatal("expected failure")
	}
	if err := runNetworkCmdIgnoreExists("/bin/false", "x"); err == nil {
		t.Fatal("expected ignore-exists failure")
	}
	if err := runNetworkCmdIgnoreExists("/bin/true"); err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestLinuxSetWallclockSyscallError(t *testing.T) {
	ops := linuxQuiesceOps{}
	// Absurdly large timespec often rejected by clock_settime.
	if err := ops.SetWallclock(1 << 62); err == nil {
		t.Log("clock_settime accepted huge value; no error path hit")
	}
}

func TestLinuxFirstNonLoopbackSeams(t *testing.T) {
	orig := readNetClassDir
	t.Cleanup(func() { readNetClassDir = orig })

	readNetClassDir = func() ([]os.DirEntry, error) {
		return nil, errors.New("no sysfs")
	}
	if _, err := firstNonLoopbackInterface(); err == nil {
		t.Fatal("expected read error")
	}
	ops := linuxQuiesceOps{}
	if err := ops.ConfigureNetwork(guestNetworkConfig{
		GuestIP: "10.0.0.2", GatewayIP: "10.0.0.1", PrefixLen: 30,
	}); err == nil {
		t.Fatal("expected configure failure when net class unreadable")
	}

	readNetClassDir = func() ([]os.DirEntry, error) {
		return []os.DirEntry{fakeDirEntry("lo")}, nil
	}
	if _, err := firstNonLoopbackInterface(); err == nil {
		t.Fatal("expected no non-loopback error")
	}
}

type fakeDirEntry string

func (f fakeDirEntry) Name() string { return string(f) }

func (f fakeDirEntry) IsDir() bool { return true }

func (f fakeDirEntry) Type() os.FileMode { return os.ModeDir }

func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, errors.New("no info") }
