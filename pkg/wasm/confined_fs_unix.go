//go:build unix

package wasm

import (
	"os"
	"path"
	"strings"
	"syscall"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"golang.org/x/sys/unix"
)

func withPlatformOflag(oflag experimentalsys.Oflag, flag int) int {
	if oflag&experimentalsys.O_DIRECTORY != 0 {
		flag |= syscall.O_DIRECTORY
	}
	if oflag&experimentalsys.O_DSYNC != 0 {
		flag |= syscall.O_DSYNC
	}
	if oflag&experimentalsys.O_NONBLOCK != 0 {
		flag |= syscall.O_NONBLOCK
	}
	// O_RSYNC is not defined on darwin; wazero's DirFS drops it too.
	return flag
}

// splitParent splits an os.Root name into the directory that holds its last
// element and that element, and reports whether the name ended in a slash.
func splitParent(name string) (dir, base string, trailingSlash bool) {
	trimmed := strings.TrimRight(name, "/")
	trailingSlash = len(trimmed) != len(name)
	if trimmed == "" || trimmed == "." {
		return ".", ".", trailingSlash
	}
	dir, base = path.Split(trimmed)
	dir = strings.TrimRight(dir, "/")
	if dir == "" {
		dir = "."
	}
	return dir, base, trailingSlash
}

// atParent opens the directory holding name's last element through root and
// calls op with that directory's descriptor and the last element. os.Root
// resolves the directory, so the descriptor is inside the root, and op's *at
// call looks up one name in it without following a final symlink: neither
// half can be redirected by a concurrent rename.
func atParent(root *os.Root, name string, op func(dirfd int, base string) error) error {
	dir, base, _ := splitParent(name)
	if base == ".." {
		// wazero cleans paths and refuses "..", so this is unreachable; keep
		// the *at calls from ever being handed a name that climbs.
		return syscall.EPERM
	}
	d, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	rc, err := d.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = op(int(fd), base) }); err != nil {
		return err
	}
	return opErr
}

func isDirAt(dirfd int, base string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

// unlinkInRoot removes a non-directory, like unlink(2). os.Root.Remove would
// also remove an empty directory, which unlink must refuse.
func unlinkInRoot(root *os.Root, name string) experimentalsys.Errno {
	_, _, trailingSlash := splitParent(name)
	return rootErrno(atParent(root, name, func(dirfd int, base string) error {
		if trailingSlash {
			// "x/" names a directory; unlink of a file named so is ENOTDIR.
			if dir, err := isDirAt(dirfd, base); err != nil {
				return err
			} else if !dir {
				return syscall.ENOTDIR
			}
		}
		err := unix.Unlinkat(dirfd, base, 0)
		if err == unix.EPERM {
			// darwin answers EPERM for a directory; WASI expects EISDIR,
			// as wazero's DirFS maps it.
			if dir, e := isDirAt(dirfd, base); e == nil && dir {
				return syscall.EISDIR
			}
		}
		return err
	}))
}

// rmdirInRoot removes an empty directory, like rmdir(2).
func rmdirInRoot(root *os.Root, name string) experimentalsys.Errno {
	return rootErrno(atParent(root, name, func(dirfd int, base string) error {
		return unix.Unlinkat(dirfd, base, unix.AT_REMOVEDIR)
	}))
}

// renameInRoot renames like rename(2), which may replace an empty directory.
// os.Root.Rename refuses that, and guests built on wasi-libc expect it.
func renameInRoot(root *os.Root, from, to string) experimentalsys.Errno {
	_, _, fromSlash := splitParent(from)
	_, _, toSlash := splitParent(to)
	return rootErrno(atParent(root, from, func(oldfd int, oldBase string) error {
		return atParent(root, to, func(newfd int, newBase string) error {
			if fromSlash || toSlash {
				if dir, err := isDirAt(oldfd, oldBase); err != nil {
					return err
				} else if !dir {
					return syscall.ENOTDIR
				}
			}
			return unix.Renameat(oldfd, oldBase, newfd, newBase)
		})
	}))
}

func setNonblockFile(f *os.File, enable bool) experimentalsys.Errno {
	return controlFile(f, func(fd int) error { return unix.SetNonblock(fd, enable) })
}

// controlFile runs op with f's descriptor, keeping f alive and open for the
// call.
func controlFile(f *os.File, op func(fd int) error) experimentalsys.Errno {
	rc, err := f.SyscallConn()
	if err != nil {
		return experimentalsys.UnwrapOSError(err)
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = op(int(fd)) }); err != nil {
		return experimentalsys.UnwrapOSError(err)
	}
	return experimentalsys.UnwrapOSError(opErr)
}
