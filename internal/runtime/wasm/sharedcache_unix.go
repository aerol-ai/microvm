//go:build unix

package wasm

import (
	"errors"
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
		if d.workerOwns() {
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
