//go:build linux

package rootd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// imageLayers lays out two image layers under a snapshots folder, as
// containerd's overlayfs snapshotter does, and the helper's empty folder.
func imageLayers(t *testing.T) (snaps, l1, l2, empty string) {
	t.Helper()
	snaps = filepath.Join(t.TempDir(), "snapshots")
	l1, l2 = filepath.Join(snaps, "1", "fs"), filepath.Join(snaps, "2", "fs")
	within(t, l1, map[string]string{"etc/passwd": "base:x:1:1::/:/bin/sh\n", "etc/group": "base:x:1:\n"})
	within(t, l2, map[string]string{"etc/passwd": "app:x:1000:1000::/:/bin/sh\n", "usr/bin/x": "x"})
	empty = filepath.Join(t.TempDir(), "imageroot")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	return snaps, l1, l2, empty
}

// mainThread names a file of the process's main thread in /proc: the
// thread Go never ends.
func mainThread(name string) string {
	return fmt.Sprintf("/proc/%d/task/%d/%s", os.Getpid(), os.Getpid(), name)
}

// mountIDOf is the id of the mount fd is on (statx STATX_MNT_ID, Linux
// 5.8): the first field of the mount's line in a mountinfo table.
func mountIDOf(fd int) (uint64, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &st); err != nil {
		return 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("no mount id from statx")
	}
	return st.Mnt_id, nil
}

// inTable reports whether mount id has a line in the mountinfo table.
func inTable(table string, id uint64) bool {
	raw, err := os.ReadFile(table)
	if err != nil {
		return false
	}
	prefix := strconv.FormatUint(id, 10) + " "
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// mountTmpfs mounts a small tmpfs on a new folder dir, unmounted at the
// test's end, and returns its mount id.
func mountTmpfs(t *testing.T, dir string) uint64 {
	t.Helper()
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "size=64k"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	id, err := mountIDOf(fd)
	if err != nil {
		t.Skipf("mount ids: %v", err)
	}
	return id
}

// TestReadImageFilesLeavesTheProcessAlone (#1400 review): reads of an
// image's users leave the helper's main thread as it was, at GOMAXPROCS 1,
// 2, 4 and 8, whether the reads run on the caller's goroutine or eight at
// a time on fresh goroutines, as the helper runs them. After every batch
// the main thread is in the process's mount namespace and working folder,
// and at the end its mount table drops a mount the host removed and shows
// one the host made.
//
// The reader once took a mount namespace of its own on a locked thread
// and let the goroutine exit locked. Go ends such a thread, except the
// main thread, which it parks for good: a read that ran there left the
// main thread in a stale copy of the mount table. A test's goroutine
// starts on the main thread, so the first direct read below ran there.
func TestReadImageFilesLeavesTheProcessAlone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (mounts)")
	}
	snaps, l1, l2, empty := imageLayers(t)
	// Stands for a sandbox's /run/netns/<id> bind: made before the reads,
	// removed by the host after them.
	pin := filepath.Join(t.TempDir(), "pin")
	pinID := mountTmpfs(t, pin)
	ns, err := os.Readlink(mainThread("ns/mnt"))
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Readlink(mainThread("cwd"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		if got, _ := os.Readlink(mainThread("ns/mnt")); got != ns {
			t.Fatalf("%s: the main thread is in mount namespace %s, the process's is %s", when, got, ns)
		}
		if got, _ := os.Readlink(mainThread("cwd")); got != cwd {
			t.Fatalf("%s: the main thread's working folder is %s, was %s", when, got, cwd)
		}
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	for _, procs := range []int{1, 2, 4, 8} {
		runtime.GOMAXPROCS(procs)
		for i := range 50 {
			if _, err := readImageFiles(snaps, empty, []string{l2, l1}); err != nil {
				t.Fatal(err)
			}
			check(fmt.Sprintf("GOMAXPROCS=%d, direct read %d", procs, i+1))
		}
		errs := make(chan error, 64)
		var wg sync.WaitGroup
		for i := range 64 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := readImageFiles(snaps, empty, []string{l2, l1}); err != nil {
					errs <- err
				}
			}()
			if i%8 == 7 {
				wg.Wait()
			}
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		check(fmt.Sprintf("GOMAXPROCS=%d, 64 reads on goroutines", procs))
	}
	if err := unix.Unmount(pin, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if inTable(mainThread("mountinfo"), pinID) {
		t.Fatal("a mount the host removed stays in the main thread's table")
	}
	later := mountTmpfs(t, filepath.Join(t.TempDir(), "later"))
	if !inTable(mainThread("mountinfo"), later) {
		t.Fatal("a mount the host made after the reads is not in the main thread's table")
	}
}
