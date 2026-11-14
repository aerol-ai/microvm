//go:build linux

package netns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Unprivileged checks of the in-process namespace steps (host_linux.go):
// everything that needs no CAP_SYS_ADMIN, under a temp root. The real
// create, loopback and delete are in host_kernel_test.go (kerneltest tag,
// root in a privileged container).

// TestDeleteNamedNetnsIsIdempotent: a missing file is success, and a file
// under the root (not a mount here) is removed, from the Host's own root.
func TestDeleteNamedNetnsIsIdempotent(t *testing.T) {
	root := t.TempDir()
	h := &Host{NetnsRoot: root}
	if err := h.deleteNetns(context.Background(), "never-made"); err != nil {
		t.Fatalf("delete of a missing netns: %v", err)
	}
	path := filepath.Join(root, "sb-file")
	if err := os.WriteFile(path, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := h.deleteNetns(context.Background(), "sb-file"); err != nil {
			t.Fatalf("delete %d: %v", i+1, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("netns file still there after delete: %v", err)
	}
}

// TestDeleteNamedNetnsReportsAFileItCannotRemove: anything but "missing"
// is an error now, so the pool parks the slot instead of reusing a name
// whose file is still on the node. A directory stands in for the file
// unlink refuses (EISDIR).
func TestDeleteNamedNetnsReportsAFileItCannotRemove(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "stuck", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := deleteNamedNetns(root, "stuck")
	if err == nil || !strings.Contains(err.Error(), "remove netns file") {
		t.Fatalf("delete of a file unlink refuses: %v, want an error", err)
	}
}

// TestLoopbackUpInNeedsANetns: lo is set up only inside a real namespace;
// a missing path or a plain file is an error, never a silent no-op.
func TestLoopbackUpInNeedsANetns(t *testing.T) {
	root := t.TempDir()
	h := &Host{NetnsRoot: root}
	err := h.bringLoopbackUp(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), filepath.Join(root, "missing")) {
		t.Fatalf("loopback in a missing netns: %v, want an error naming %s", err, filepath.Join(root, "missing"))
	}
	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := loopbackUpIn(plain); err == nil {
		t.Fatal("loopback in a plain file: want an error")
	}
}

// TestCreateNamedNetnsFailsCleanly: a create that cannot share the root
// (no CAP_SYS_ADMIN) or cannot make the root at all fails before any file
// exists, so nothing is left for the next build of that name to trip on.
func TestCreateNamedNetnsFailsCleanly(t *testing.T) {
	t.Run("root is a file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(root, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := createNamedNetns(root, "sb-1"); err == nil || !strings.Contains(err.Error(), "create netns dir") {
			t.Fatalf("create under a file: %v, want a dir error", err)
		}
	})
	t.Run("unprivileged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("as root the create succeeds: TestKernelHostNetnsLifecycle covers it")
		}
		root := t.TempDir()
		h := &Host{NetnsRoot: root}
		if err := h.createNetns(context.Background(), "sb-1"); err == nil {
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
// TestKernelHostBindReturnsTheThread.)
func TestBindNewNetnsUnprivilegedStaysHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the unshare succeeds: TestKernelHostBindReturnsTheThread covers it")
	}
	path := filepath.Join(t.TempDir(), "sb-1")
	if err := bindNewNetns(path); err == nil || !strings.Contains(err.Error(), "unshare a new netns") {
		t.Fatalf("unprivileged bind = %v, want the unshare error", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	home, err := bindNewNetnsOnThread(path)
	if !home || err == nil {
		t.Fatalf("unprivileged bind on this thread = home %v, %v; want home with an error", home, err)
	}
}
