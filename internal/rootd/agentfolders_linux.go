//go:build linux

package rootd

import (
	"golang.org/x/sys/unix"
)

// openEntry opens one entry of the folder dfd without following a link
// (O_PATH|O_NOFOLLOW: no open side effects on a device or a FIFO, and a
// link gives a handle on the link itself) and reads its stat from that
// handle.
func openEntry(dfd int, name string) (*entry, error) {
	fd, err := unix.Openat(dfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	e := &entry{dfd: dfd, name: name, fd: fd}
	if err := unix.Fstat(fd, &e.st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return e, nil
}

func (e *entry) close() { _ = unix.Close(e.fd) }

// chown changes the owner through the handle (AT_EMPTY_PATH works on an
// O_PATH handle, where fchown gives EBADF).
func (e *entry) chown(uid, gid uint32) error {
	u, g, err := ownerIDs(uid, gid)
	if err != nil {
		return err
	}
	return unix.Fchownat(e.fd, "", u, g, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// mountRoot reports whether the entry is the root of a mount, a bind mount
// from the same disk included. Kernels before 5.8 do not say
// (STATX_ATTR_MOUNT_ROOT missing from the mask); there the device check
// alone decides.
func (e *entry) mountRoot() bool {
	var stx unix.Statx_t
	if err := unix.Statx(e.fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &stx); err != nil {
		return false
	}
	return stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT != 0 && stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0
}

// openDir opens the entry, a folder, to read: through its handle, so it is
// the folder looked at, never another one renamed into its place.
func (e *entry) openDir(uint64) (int, error) {
	return unix.Openat(e.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}
