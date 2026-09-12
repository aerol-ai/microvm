//go:build linux

package isolate

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// jailDevNodes are the character devices a runtime expects to find. workerd
// reads entropy through getrandom(2), but libc and V8 fall back to
// /dev/urandom, and a missing /dev/null turns a harmless redirect into a
// crash. Nothing else: no tty, no block devices.
var jailDevNodes = []struct {
	name         string
	major, minor uint32
	mode         uint32
}{
	{"null", 1, 3, 0o666},
	{"zero", 1, 5, 0o666},
	{"random", 1, 8, 0o666},
	{"urandom", 1, 9, 0o666},
}

// makeDevNodes creates the device nodes in dir (root only).
func makeDevNodes(dir string) error {
	for _, n := range jailDevNodes {
		path := filepath.Join(dir, n.name)
		_ = os.Remove(path)
		dev := unix.Mkdev(n.major, n.minor)
		if err := unix.Mknod(path, unix.S_IFCHR|n.mode, int(dev)); err != nil {
			return fmt.Errorf("isolate jail: mknod %s: %w", path, err)
		}
		if err := os.Chmod(path, os.FileMode(n.mode)); err != nil {
			return err
		}
	}
	return nil
}

// cloneDevNode recreates a device node from the base tree in a group tree.
func cloneDevNode(src, dst string) error {
	var st unix.Stat_t
	if err := unix.Stat(src, &st); err != nil {
		return err
	}
	_ = os.Remove(dst)
	if err := unix.Mknod(dst, st.Mode, int(st.Rdev)); err != nil {
		return fmt.Errorf("isolate jail: mknod %s: %w", dst, err)
	}
	return os.Chmod(dst, os.FileMode(st.Mode&0o777))
}

func runningAsRoot() bool { return os.Geteuid() == 0 }
