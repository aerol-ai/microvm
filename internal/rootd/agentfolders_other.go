//go:build !linux

package rootd

import (
	"golang.org/x/sys/unix"
)

// The helper runs on Linux only; this is so the walk's tests run on a
// developer's Mac. There is no O_PATH here: the entry is looked at and
// changed by name, with no link followed, and a folder opened is checked
// to be the one looked at.

func openEntry(dfd int, name string) (*entry, error) {
	e := &entry{dfd: dfd, name: name, fd: -1}
	if err := unix.Fstatat(dfd, name, &e.st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *entry) close() {}

func (e *entry) chown(uid, gid uint32) error {
	u, g, err := ownerIDs(uid, gid)
	if err != nil {
		return err
	}
	return unix.Fchownat(e.dfd, e.name, u, g, unix.AT_SYMLINK_NOFOLLOW)
}

func (e *entry) mountRoot() bool { return false }

func (e *entry) openDir(dev uint64) (int, error) {
	sub, err := unix.Openat(e.dfd, e.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(sub, &st); err != nil || uint64(st.Dev) != dev || st.Ino != e.st.Ino {
		_ = unix.Close(sub)
		return -1, nil
	}
	return sub, nil
}
