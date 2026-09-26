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

// makeDevNodes creates the device nodes in dir. Root + CAP_MKNOD produces
// real character devices; unprivileged hosts (CI, unit tests) get empty
// regular placeholders so PrepareJailBase can still build the tree.
// applyJail refuses to realize without root, so a production jail never
// starts on these stand-ins.
func makeDevNodes(dir string) error {
	for _, n := range jailDevNodes {
		path := filepath.Join(dir, n.name)
		_ = os.Remove(path)
		dev := unix.Mkdev(n.major, n.minor)
		if err := unix.Mknod(path, unix.S_IFCHR|n.mode, int(dev)); err != nil {
			if err == unix.EPERM || err == unix.EACCES {
				f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, os.FileMode(n.mode))
				if ferr != nil {
					return fmt.Errorf("isolate jail: mknod %s: %w (placeholder: %v)", path, err, ferr)
				}
				_ = f.Close()
				continue
			}
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

// mountNoexecTmpfs covers a jail-writable directory so a process that still
// has execve (the shim's one exec into workerd) cannot write a binary there
// and run it. nosuid/nodev are the usual extra bits.
func mountNoexecTmpfs(dir string, uid, gid int) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("isolate jail: noexec tmpfs dir %q must be absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	opts := fmt.Sprintf("size=64M,mode=0700,uid=%d,gid=%d", uid, gid)
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("isolate jail: noexec tmpfs on %s: %w", dir, err)
	}
	return nil
}

func unmountNoexecMounts(dirs []string) {
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = unix.Unmount(dirs[i], unix.MNT_DETACH)
	}
}
