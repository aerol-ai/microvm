package wasm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestCov96WriteSnapshotDirTempDirCreateFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permission")
	}
	parent := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	err := WriteSnapshotDir(filepath.Join(parent, "mem.snap"), SnapshotCapture{Memory: []byte("m")})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("WriteSnapshotDir = %v, want permission error from the staging dir", err)
	}
}

// RemoveAll(dst) cannot clear a destination holding a read-only subtree, so
// the final rename onto the non-empty directory fails and the staged copy is
// discarded.
func TestCov96WriteSnapshotDirRenameFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permission")
	}
	parent := t.TempDir()
	dst := filepath.Join(parent, "mem.snap")
	locked := filepath.Join(dst, "locked")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	if err := WriteSnapshotDir(dst, SnapshotCapture{Memory: []byte("m")}); err == nil {
		t.Fatal("WriteSnapshotDir = nil, want rename onto a non-empty destination to fail")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".mem.snap-") {
			t.Fatalf("staging dir %s leaked after rename failure", e.Name())
		}
	}
}

// cov96DeepDir creates a directory under base whose absolute path is exactly
// total bytes long, using components short enough for any filesystem.
func cov96DeepDir(t *testing.T, base string, total int) string {
	t.Helper()
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	p := base
	for len(p) < total {
		n := total - len(p) - 1
		if n > 200 {
			n = 200
		}
		if n < 1 {
			t.Fatalf("cannot reach length %d from %d", total, len(p))
		}
		// Leave room for one more component rather than stranding a
		// 1-byte gap the separator alone would overshoot.
		if rest := total - len(p) - 1 - n; rest == 1 {
			n--
		}
		p = filepath.Join(p, strings.Repeat("d", n))
	}
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatalf("mkdir deep dir (%d bytes): %v", len(p), err)
	}
	return p
}

// The staging dir name leaves each artifact path a different distance from
// PATH_MAX (config.json and memory.zstd are both 11 bytes, globals.cbor 12,
// wasi-state.cbor 15). Sliding the parent's length across that window makes
// each individually-lengthed artifact write fail with ENAMETOOLONG after the
// ones before it succeeded; the random staging suffix varies in width, so a
// few attempts per length cover every offset.
func TestCov96WriteSnapshotDirArtifactWriteFails(t *testing.T) {
	var pathMax int
	switch runtime.GOOS {
	case "darwin":
		pathMax = 1024
	case "linux":
		pathMax = 4096
	default:
		t.Skipf("PATH_MAX not known for %s", runtime.GOOS)
	}
	// Resolve symlinks (macOS /var -> /private/var) so the kernel sees the
	// same length we computed.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{configFileName: false, globalsFileName: false, wasiStateFileName: false}
	root := filepath.Join(base, "r")
	for total := pathMax - 48; total < pathMax-len("/.mem.snap-")-1; total++ {
		parent := cov96DeepDir(t, root, total)
		for attempt := 0; attempt < 8; attempt++ {
			err := WriteSnapshotDir(filepath.Join(parent, "s"), SnapshotCapture{Memory: []byte("m")})
			var pe *fs.PathError
			if !errors.As(err, &pe) || !errors.Is(err, syscall.ENAMETOOLONG) {
				continue
			}
			if _, tracked := want[filepath.Base(pe.Path)]; tracked {
				want[filepath.Base(pe.Path)] = true
			}
		}
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
	}
	for name, hit := range want {
		if !hit {
			t.Errorf("never observed a failed write of %s", name)
		}
	}
	leftovers, _ := filepath.Glob(filepath.Join(base, "*"))
	if len(leftovers) != 0 {
		t.Fatalf("leftover entries under base: %v", leftovers)
	}
}
