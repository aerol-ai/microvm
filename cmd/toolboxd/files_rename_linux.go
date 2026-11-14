//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames src to dst unless dst exists, in one step the
// kernel decides (renameat2 RENAME_NOREPLACE), so of two callers racing for
// one name exactly one wins and the other gets fs.ErrExist.
func renameNoReplace(src, dst string) error {
	err := unix.Renameat2(unix.AT_FDCWD, src, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		// A filesystem or kernel without the flag. EINVAL is also rename's
		// answer to a folder moved into itself, which the fallback's own
		// rename reports again.
		return renameNoReplaceFallback(src, dst)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	return nil
}
