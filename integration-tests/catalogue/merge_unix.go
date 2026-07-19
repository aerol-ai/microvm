//go:build !windows

package catalogue

import (
	"os"
	"syscall"
)

func unixFlockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unixFlockUnlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func flockExclusive(f *os.File) error { return unixFlockExclusive(f) }
func flockUnlock(f *os.File) error    { return unixFlockUnlock(f) }
