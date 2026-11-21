//go:build linux

package containerd

// Regression tests for the third review: a broken child that leaves a folder
// chain far past the depth cap is refused at once, but os.RemoveAll then held
// one descriptor per level (93,163 at once for a 100,000-level chain) and,
// under a 4096 limit, failed and left the tree in /tmp. Cleanup now holds a
// bounded number, and the daemon sweeps leftovers at start.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// deepChainLevels is as deep as a unit test can build and remove in a few
// seconds: far past what os.RemoveAll can open under the limits below.
const deepChainLevels = 30_000

// makeChainAt makes a chain of folders named "a", levels deep, under the
// folder open on fd, holding two descriptors at a time, with a file every
// thousand levels and at the bottom.
func makeChainAt(fd, levels int) error {
	cur, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	for i := range levels {
		if i%1000 == 0 {
			f, err := unix.Openat(cur, "f", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o444)
			if err != nil {
				unix.Close(cur)
				return err
			}
			unix.Close(f)
		}
		if err := unix.Mkdirat(cur, "a", 0o755); err != nil {
			unix.Close(cur)
			return err
		}
		next, err := unix.Openat(cur, "a", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		unix.Close(cur)
		if err != nil {
			return err
		}
		cur = next
	}
	f, err := unix.Openat(cur, "f", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o444)
	if err == nil {
		unix.Close(f)
	}
	unix.Close(cur)
	return err
}

func makeChain(t *testing.T, dir string, levels int) {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := makeChainAt(fd, levels); err != nil {
		t.Fatal(err)
	}
}

// lowFileLimit lowers this process's open-file limit to what it has open
// now plus extra, until the test ends. Children started meanwhile inherit it.
func lowFileLimit(t *testing.T, extra uint64) {
	t.Helper()
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	open, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip(err)
	}
	low := orig
	low.Cur = uint64(len(open)) + extra
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig) })
}

// A 30,000-level chain: os.RemoveAll cannot remove it under a limit of 40
// more descriptors; removeTreeBounded can, in bounded time.
func TestRemoveTreeBoundedDeepChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "context")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	makeChain(t, dir, deepChainLevels)
	lowFileLimit(t, removeTreeWindow+8)

	if err := os.RemoveAll(dir); err == nil {
		t.Fatal("os.RemoveAll managed under the limit, so this proves nothing")
	}
	start := time.Now()
	if err := removeTreeBounded(dir, removeTreeWindow); err != nil {
		t.Fatalf("removeTreeBounded: %v", err)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("removing %d levels took %v", deepChainLevels, took)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the tree is still there: %v", err)
	}
}

// A wide tree with a tiny window: siblings, read-only files, and links,
// which are removed as names and never followed.
func TestRemoveTreeBoundedLinksAndSiblings(t *testing.T) {
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "keep")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "context")
	for i := range 4 {
		sub := filepath.Join(dir, fmt.Sprintf("s%d", i), "x", "y", "z")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := range 3 {
			if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", j)), []byte("x"), 0o444); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(victimDir, filepath.Join(sub, "out")); err != nil {
			t.Fatal(err)
		}
	}
	// A name the hoisting would pick first is taken already.
	if err := os.WriteFile(filepath.Join(dir, ".aerolvm-rm-1"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBounded(dir, 2); err != nil {
		t.Fatalf("removeTreeBounded: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the tree is still there: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a link was followed: %v", err)
	}

	// Not there; a link (removed, target kept); a file.
	if err := removeTreeBounded(filepath.Join(t.TempDir(), "missing"), 2); err != nil {
		t.Fatalf("missing: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(victimDir, link); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBounded(link, 2); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the link is still there: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the link's target went: %v", err)
	}
}

// End to end: a broken child leaves a 30,000-level chain. The lockdown
// refuses it at the depth cap, and the cleanup removes it under a limit far
// below what os.RemoveAll would need (the lockdown holds at most one
// descriptor per level up to the cap).
func TestUnpackContextInChildRemovesADeepChain(t *testing.T) {
	ids := childUnpackFixture(t)
	maker := writeScript(t, worldDir(t), "deep-child",
		"exec /usr/bin/env "+unpackTestHelperEnv+"=deepchain "+unpackTestExe+"\n")
	orig := contextUnpackExe
	t.Cleanup(func() { contextUnpackExe = orig })
	contextUnpackExe = func() (string, error) { return maker, nil }
	dir := filepath.Join(t.TempDir(), "context")
	lowFileLimit(t, uint64(maxContextDepth)+64)

	start := time.Now()
	err := unpackContextInChild(context.Background(), nil, dir, ids.uidBase, ids.gidBase)
	if err == nil || !strings.Contains(err.Error(), "nested deeper than 256 folders") {
		t.Fatalf("unpack = %v; want the chain refused", err)
	}
	if took := time.Since(start); took > 60*time.Second {
		t.Fatalf("refusing and removing %d levels took %v", deepChainLevels, took)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the chain is still there: %v", err)
	}
}

// At start the daemon removes the build folders a previous run left, and
// only those: folders with the name, owned by this user; never a link with
// the name, nor what it points at.
func TestSweepBuildDirs(t *testing.T) {
	tmp := t.TempDir()
	victimDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(victimDir, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(tmp, buildDirPrefix+"old")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	makeChain(t, old, 5000)
	keep := []string{filepath.Join(tmp, buildDirPrefix+"file"), filepath.Join(tmp, buildDirPrefix+"link"), filepath.Join(tmp, "other")}
	if err := os.WriteFile(keep[0], []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, keep[1]); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keep[2], 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		foreign := filepath.Join(tmp, buildDirPrefix+"foreign")
		if err := os.Mkdir(foreign, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(foreign, 1234, 1234); err != nil {
			t.Fatal(err)
		}
		keep = append(keep, foreign)
	}

	var logs bytes.Buffer
	b := NewBuildKitBuilder("", "", slog.New(slog.NewTextHandler(&logs, nil)))
	t.Setenv("TMPDIR", tmp)
	select {
	case <-b.SweepBuildDirs():
	case <-time.After(30 * time.Second):
		t.Fatal("the sweep did not finish")
	}
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Fatalf("the leftover is still there: %v", err)
	}
	for _, path := range keep {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("the sweep removed %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(victimDir, "keep")); err != nil {
		t.Fatalf("the sweep followed a link: %v", err)
	}
	if !strings.Contains(logs.String(), "removed a leftover image-build folder") {
		t.Fatalf("logged %q", logs.String())
	}

	// One it cannot remove is reported, not fatal. Only a user that is not
	// root can be kept out of its own folder.
	if os.Geteuid() == 0 {
		return
	}
	stuck := filepath.Join(tmp, buildDirPrefix+"stuck")
	locked := filepath.Join(stuck, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	logs.Reset()
	<-b.SweepBuildDirs()
	if !strings.Contains(logs.String(), "could not remove a leftover image-build folder") {
		t.Fatalf("logged %q", logs.String())
	}
}
