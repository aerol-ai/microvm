//go:build linux

package hostnet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netns"
)

func TestDisableIPv6InNetnsMissingPath(t *testing.T) {
	fakeIPv6Conf(t)
	if err := DisableIPv6InNetns(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("a netns path that does not exist must fail")
	}
}

// A path that is not a network namespace opens but cannot be entered: the
// error surfaces and the calling thread is still in its own namespace.
func TestDisableIPv6InNetnsNotANetns(t *testing.T) {
	root := fakeIPv6Conf(t)
	f := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := netns.Get()
	if err != nil {
		t.Skipf("no netns handle: %v", err)
	}
	defer before.Close()
	if err := DisableIPv6InNetns(f); err == nil {
		t.Fatal("entering a plain file must fail")
	}
	after, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if !before.Equal(after) {
		t.Fatal("the caller's thread changed network namespace")
	}
	if got := readDisable(t, root, "all"); got != "0" {
		t.Fatalf("nothing may be written when the netns cannot be entered: all=%q", got)
	}
}

// fakeNetns stands in for setns: handles are fds on /dev/null,
// Set records what it was asked and fails the calls in failSet (1-based).
type fakeNetns struct {
	sets    int
	failSet map[int]bool
	getErr  error
}

func (f *fakeNetns) install(t *testing.T) {
	t.Helper()
	// A raw fd, not an *os.File: the handle's Close owns it, and no
	// finalizer may close it a second time.
	open := func() (netns.NsHandle, error) {
		fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return netns.None(), err
		}
		return netns.NsHandle(fd), nil
	}
	origFrom, origCur, origSet := nsFromPath, nsCurrent, nsSet
	nsFromPath = func(path string) (netns.NsHandle, error) {
		if strings.Contains(path, "missing") {
			return netns.None(), errors.New("no such file")
		}
		return open()
	}
	nsCurrent = func() (netns.NsHandle, error) {
		if f.getErr != nil {
			return netns.None(), f.getErr
		}
		return open()
	}
	nsSet = func(netns.NsHandle) error {
		f.sets++
		if f.failSet[f.sets] {
			return errors.New("setns: operation not permitted")
		}
		return nil
	}
	t.Cleanup(func() { nsFromPath, nsCurrent, nsSet = origFrom, origCur, origSet })
}

// The write happens between entering the sandbox's namespace and returning
// to the host's: both sets, in that order, around both files.
func TestDisableIPv6InNetnsEntersWritesReturns(t *testing.T) {
	root := fakeIPv6Conf(t)
	f := &fakeNetns{}
	f.install(t)
	if err := DisableIPv6InNetns("/run/netns/aerol-netns-1"); err != nil {
		t.Fatal(err)
	}
	if f.sets != 2 {
		t.Fatalf("setns calls = %d, want enter and return", f.sets)
	}
	for _, c := range []string{"all", "default"} {
		if got := readDisable(t, root, c); got != "1" {
			t.Fatalf("%s = %q", c, got)
		}
	}
}

func TestDisableIPv6InNetnsFailures(t *testing.T) {
	fakeIPv6Conf(t)
	f := &fakeNetns{}
	f.install(t)
	if err := DisableIPv6InNetns("/run/netns/missing"); err == nil || !strings.Contains(err.Error(), "open netns") {
		t.Fatalf("missing netns = %v", err)
	}
	f.getErr = errors.New("no /proc/self/ns/net")
	if err := DisableIPv6InNetns("/run/netns/x"); err == nil || !strings.Contains(err.Error(), "host netns") {
		t.Fatalf("no host handle = %v", err)
	}
	f.getErr = nil
	f.sets, f.failSet = 0, map[int]bool{1: true}
	if err := DisableIPv6InNetns("/run/netns/x"); err == nil || !strings.Contains(err.Error(), "enter netns") {
		t.Fatalf("enter refused = %v", err)
	}
	// The thread cannot get back to the host namespace: the error says so,
	// and the goroutine keeps its thread locked so the runtime retires it.
	f.sets, f.failSet = 0, map[int]bool{2: true}
	if err := DisableIPv6InNetns("/run/netns/x"); err == nil || !strings.Contains(err.Error(), "return to the host netns") {
		t.Fatalf("return refused = %v", err)
	}
}

// A write that fails (here: /dev/full, which refuses every write) is an
// error, never a silent pass.
func TestWriteDisableIPv6WriteError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	if err := writeDisableIPv6("/dev/full"); err == nil || !strings.Contains(err.Error(), "write /dev/full") {
		t.Fatalf("writeDisableIPv6(/dev/full) = %v", err)
	}
}
