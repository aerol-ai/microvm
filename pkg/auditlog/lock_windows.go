//go:build windows

package auditlog

import (
	"errors"
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

// tryLockExclusive takes the lock only if no one holds it (ErrLockBusy).
func tryLockExclusive(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLockBusy
	}
	return err
}

func unlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// openNoFollow: Windows opens have no such flag to ask for.
const openNoFollow = 0
