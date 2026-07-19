//go:build windows

package catalogue

import (
	"os"

	"golang.org/x/sys/windows"
)

func windowsLock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

func windowsUnlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}

func flockExclusive(f *os.File) error { return windowsLock(f) }
func flockUnlock(f *os.File) error    { return windowsUnlock(f) }
