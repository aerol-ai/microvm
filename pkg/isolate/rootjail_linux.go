//go:build linux

package isolate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// mountJailTmpfs mounts a noexec tmpfs on dir, owned by uid and gid with
// mode, unless one is already there.
func mountJailTmpfs(dir string, uid, gid int, mode uint32) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("isolate jail: tmpfs dir %q must be absolute", dir)
	}
	if mounted(dir) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	opts := fmt.Sprintf("size=64M,mode=%04o,uid=%d,gid=%d", mode&0o7777, uid, gid)
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("isolate jail: noexec tmpfs on %s: %w", dir, err)
	}
	return nil
}

// mounted reports whether dir is the root of a mount: it sits on another
// device than its parent. A missing dir is not.
func mounted(dir string) bool {
	var st, parent unix.Stat_t
	if unix.Lstat(dir, &st) != nil || unix.Lstat(filepath.Dir(dir), &parent) != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Dev != parent.Dev
}

// setJailProcAttr gives the shim what applyJail gives it, the cgroup
// aside: a process group of its own and a PID namespace of its own.
func setJailProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Cloneflags: jailCloneflags()}
}
