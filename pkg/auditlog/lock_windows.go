//go:build windows

package auditlog

import (
	"os"

	"golang.org/x/sys/windows"
)

// The daemon that writes audit files only runs on Linux, but aerolvm
// imports this package to verify chains offline and ships for Windows, so
// the lock must compile there. LockFileEx gives the same exclusive,
// whole-file advisory lock flock does.

func lockExclusive(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func unlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
