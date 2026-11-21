//go:build linux

package mounts

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The folder of a sandbox's mounts is removed only once nothing is mounted
// under it, and never by following a mount point: os.RemoveAll walks into a
// live mount and deletes the storage's own files. This version uses real
// mounts, so it needs root and AEROLVM_REAL_MOUNT_TESTS=1 and make test
// never mounts anything on the host. Run it in a throwaway container:
//
//	docker run --rm --privileged -v "$PWD":/src -w /src \
//	  -e AEROLVM_REAL_MOUNT_TESTS=1 golang:1.26.11 \
//	  go test -count=1 -run RealMount ./pkg/mounts/
//
// Both cases are mounts a sandboxd did not track: a helper's mount a
// previous sandboxd left, which a stop or destroy can reach before the
// reconcile adopts it. A bind of a folder on the same device as the mount
// root is the case a device check alone misses.
func TestUnmountAllRealMountKeepsTheStorage(t *testing.T) {
	if os.Getenv("AEROLVM_REAL_MOUNT_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and AEROLVM_REAL_MOUNT_TESTS=1; run it in a privileged container")
	}
	run := func(t *testing.T, args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, out)
		}
	}
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) string
	}{
		{"bind on the same device", func(t *testing.T) string { return t.TempDir() }},
		{"bind of its own device", func(t *testing.T) string {
			dir := t.TempDir()
			run(t, "mount", "-t", "tmpfs", "tmpfs", dir)
			t.Cleanup(func() { _ = exec.Command("umount", "-l", dir).Run() })
			return dir
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, nil)
			store := tc.store(t)
			kept := filepath.Join(store, "keep.txt")
			if err := os.WriteFile(kept, []byte("the user's data"), 0o644); err != nil {
				t.Fatal(err)
			}
			hostPath := m.hostPath("sb-live", 0)
			if err := os.MkdirAll(hostPath, 0o700); err != nil {
				t.Fatal(err)
			}
			run(t, "mount", "--bind", store, hostPath)
			t.Cleanup(func() { _ = exec.Command("umount", "-l", hostPath).Run() })

			_ = m.UnmountAll("sb-live") // not tracked: a previous sandboxd made it

			if _, err := os.Stat(kept); err != nil {
				t.Fatalf("UnmountAll deleted the storage's files through a live mount: %v", err)
			}
			if mountedAt(t, hostPath) {
				t.Fatalf("%s is still mounted", hostPath)
			}
			if _, err := os.Stat(filepath.Join(m.rootDir, "sb-live")); !os.IsNotExist(err) {
				t.Fatalf("the sandbox's mount folder is still there: %v", err)
			}
		})
	}
}

func mountedAt(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}
