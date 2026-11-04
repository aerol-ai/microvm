//go:build unix

package auditlog

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockExclusive(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }

func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
