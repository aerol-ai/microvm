//go:build linux

package procid

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// resolveInRoot opens p inside root with RESOLVE_IN_ROOT, so absolute
// symlinks in the sandbox resolve against its root, never the host's.
func resolveInRoot(root, p string) (FileID, error) {
	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return FileID{}, fmt.Errorf("procid: sandbox root: %w", err)
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat2(dirfd, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return FileID{}, fmt.Errorf("procid: %s in the sandbox: %w", p, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return FileID{}, err
	}
	return FileID{Dev: uint64(st.Dev), Ino: st.Ino}, nil
}
