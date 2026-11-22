//go:build unix

package wasm

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// sharedLinkInto links the sealed entries of the shared version folder src
// into ownerDir/version, making that folder for the worker when it is
// missing. ownerDir's parent is root's, so ownerDir itself is opened by
// path; everything under it is the worker's and is reached by descriptor
// with no link followed, and the links are made with linkat relative to
// those descriptors.
func (d *Driver) sharedLinkInto(src, ownerDir, version string) error {
	srcFD, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(srcFD)
	ownerFD, err := unix.Open(ownerDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(ownerFD)
	if err := unix.Mkdirat(ownerFD, version, 0o700); err == nil {
		if d.split() {
			if err := shareAt(ownerFD, version, d.cfg.Worker.GID); err != nil {
				return err
			}
		} else if d.workerOwns() {
			if err := unix.Fchownat(ownerFD, version, d.cfg.Worker.UID, d.cfg.Worker.GID, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return err
	}
	dstFD, err := unix.Openat(ownerFD, version, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dstFD)
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode().Perm() != 0o444 {
			continue
		}
		if err := unix.Linkat(srcFD, e.Name(), dstFD, e.Name(), 0); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	return nil
}

// sharedCompiled reports whether the shared cache holds digest's entries
// from this compiler, by its marker (writeSharedMarker). Only what root
// alone could have written counts: the shared folder, the marker and each
// entry it names must be this process's, the folder closed to others, the
// marker a plain file with one name, and each entry a sealed (0444) plain
// file, none reached through a link. Anything else, or a missing entry
// (an operator cleared the cache), means compile again.
func (d *Driver) sharedCompiled(digest string) bool {
	shared := d.sharedCacheDir()
	if shared == "" || digest == "" {
		return false
	}
	dirFD, err := unix.Open(shared, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dirFD)
	euid := os.Geteuid()
	var st unix.Stat_t
	if unix.Fstat(dirFD, &st) != nil || int(st.Uid) != euid || st.Mode&0o077 != 0 {
		return false
	}
	fd, err := unix.Openat(dirFD, sharedMarkerName(digest), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "shared marker")
	defer f.Close()
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		int(st.Uid) != euid || st.Mode&0o077 != 0 || st.Size > sharedMarkerMax {
		return false
	}
	text, err := io.ReadAll(io.LimitReader(f, sharedMarkerMax))
	if err != nil {
		return false
	}
	entries, ok := parseSharedMarker(string(text), digest)
	if !ok {
		return false
	}
	for _, e := range entries {
		version, _, _ := strings.Cut(e, "/")
		if unix.Fstatat(dirFD, version, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != euid {
			return false
		}
		if unix.Fstatat(dirFD, e, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
			int(st.Uid) != euid || st.Mode&0o7777 != 0o444 {
			return false
		}
	}
	return true
}

// shareAt gives the folder name in dirFD to the worker's group, setgid and
// 0770 (split.go handToWorker), through the folder itself, opened with no
// link followed: the worker can write dirFD's folder, and could put a link
// at the name between the make and the change.
func shareAt(dirFD int, name string, gid int) error {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, unix.S_ISGID|0o770)
}
