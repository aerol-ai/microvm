//go:build !linux

package rootd

import (
	"errors"
	"os/exec"

	"golang.org/x/sys/unix"
)

// pathHandle is a no-follow lstat-able handle where there is no O_PATH: a
// read-only open, which a socket refuses, so tests stand in for sockets
// with regular files.
func pathHandle(dir int, name string) (int, error) {
	return unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

func chmodPath(fd, gid int, mode uint32) error {
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, mode)
}

func makeFilesystemAttr(*exec.Cmd, uint32, int) error {
	return errors.New("root helper: making a filesystem in a user namespace needs Linux")
}

func fchownAny(fd, uid, gid int) error { return unix.Fchown(fd, uid, gid) }

func fchmodAny(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }
