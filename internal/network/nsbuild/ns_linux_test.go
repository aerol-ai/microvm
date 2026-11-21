//go:build linux

package nsbuild

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Checks of the in-process namespace steps that need no CAP_SYS_ADMIN, and,
// as root in a privileged container, the real thing. The netns pool's own
// tests (internal/network/netns) cover them through netns.Host too.

// TestDeleteNamed: a missing file is success, a plain file goes, and a
// file unlink refuses (a folder stands in) is reported, so the pool parks
// the slot instead of reusing a name whose file is still there.
func TestDeleteNamed(t *testing.T) {
	root := t.TempDir()
	if err := DeleteNamed(root, "never-made"); err != nil {
		t.Fatalf("delete of a missing netns: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain"), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := DeleteNamed(root, "plain"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "stuck", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := DeleteNamed(root, "stuck"); err == nil || !strings.Contains(err.Error(), "remove netns file") {
		t.Fatalf("delete of a file unlink refuses: %v", err)
	}
}

// TestLoopbackUpNeedsANetns: a missing path or a plain file is an error,
// never a silent no-op.
func TestLoopbackUpNeedsANetns(t *testing.T) {
	root := t.TempDir()
	if err := LoopbackUp(filepath.Join(root, "missing")); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("loopback in a missing netns: %v", err)
	}
	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := LoopbackUp(plain); err == nil {
		t.Fatal("loopback in a plain file: want an error")
	}
}

// TestCreateNamedFailsCleanly: a create that cannot make its folder, or
// (unprivileged) cannot share it, fails with no file left behind.
func TestCreateNamedFailsCleanly(t *testing.T) {
	t.Run("root is a file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(root, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CreateNamed(root, "sb-1"); err == nil || !strings.Contains(err.Error(), "create netns dir") {
			t.Fatalf("create under a file: %v", err)
		}
	})
	t.Run("unprivileged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("as root the create succeeds: TestNamespaceLifecycle covers it")
		}
		root := t.TempDir()
		if err := CreateNamed(root, "sb-1"); err == nil {
			t.Fatal("unprivileged create: want an error")
		}
		if _, err := os.Stat(filepath.Join(root, "sb-1")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed create left a file behind: %v", err)
		}
	})
}

// Without CAP_SYS_ADMIN the unshare fails before the thread leaves its
// namespace: it is home, so bindNewNetns unlocks it, and the error names
// the step. (The way back after a real unshare is in
// TestBindReturnsTheThread.)
func TestBindNewNetnsUnprivilegedStaysHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the unshare succeeds: TestBindReturnsTheThread covers it")
	}
	path := filepath.Join(t.TempDir(), "sb-1")
	if err := bindNewNetns(path, nil); err == nil || !strings.Contains(err.Error(), "unshare a new netns") {
		t.Fatalf("unprivileged bind = %v, want the unshare error", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	home, err := bindNewNetnsOnThread(path, nil)
	if !home || err == nil {
		t.Fatalf("unprivileged bind on this thread = home %v, %v; want home with an error", home, err)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Ino
}

// TestNamespaceLifecycle, as root: a create binds a new namespace (an
// existing one is success), loopback comes up in it, and a delete removes
// it, twice over.
func TestNamespaceLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	root := t.TempDir()
	t.Cleanup(func() { _ = unix.Unmount(root, unix.MNT_DETACH) })
	if err := CreateNamed(root, "sb-1"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "sb-1")
	first := inode(t, path)
	if first == inode(t, "/proc/self/ns/net") {
		t.Fatal("the namespace is this process's own")
	}
	if err := CreateNamed(root, "sb-1"); err != nil || inode(t, path) != first {
		t.Fatalf("a second create: %v; it must keep the namespace", err)
	}
	if err := LoopbackUp(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := DeleteNamed(root, "sb-1"); err != nil {
			t.Fatalf("delete %d: %v", i+1, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("namespace file left: %v", err)
	}
}

// TestBindReturnsTheThread, as root: the thread that made a namespace is
// back in its own before it is unlocked (bindNewNetnsOnThread reports
// home).
func TestBindReturnsTheThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	path := filepath.Join(t.TempDir(), "bound")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(path, unix.MNT_DETACH) })
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before := inode(t, "/proc/thread-self/ns/net")
	home, err := bindNewNetnsOnThread(path, nil)
	if err != nil || !home {
		t.Fatalf("bind = home %v, %v", home, err)
	}
	if got := inode(t, "/proc/thread-self/ns/net"); got != before {
		t.Fatal("the thread that made the namespace was left in it")
	}
	if inode(t, path) == before {
		t.Fatal("the file is bound to the thread's own namespace, not a new one")
	}
}
