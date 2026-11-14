//go:build darwin

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace is the macOS form of the Linux renameat2 RENAME_NOREPLACE
// (renamex_np RENAME_EXCL). toolboxd ships for Linux; this keeps the
// overwrite guard race-safe where the unit tests run on a Mac.
func renameNoReplace(src, dst string) error {
	err := unix.RenamexNp(src, dst, unix.RENAME_EXCL)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return renameNoReplaceFallback(src, dst)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	return nil
}
