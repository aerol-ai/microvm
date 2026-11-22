//go:build linux

package rootd

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// startInGroup starts cmd inside the cgroup at dir (clone3 with
// CLONE_INTO_CGROUP), so it is never in the helper's group, not even for an
// instant: a swap waits for the helper's group to empty.
func startInGroup(cmd *exec.Cmd, dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = fd
	return cmd.Start()
}

// setOwnPIDNamespace starts cmd as PID 1 of a PID namespace of its own: a
// host signals nothing outside it, and no other host can name it.
func setOwnPIDNamespace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWPID
}
