//go:build unix

package auditlog

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockExclusive(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }

// openNoFollow refuses a symlink in an open's last component.
const openNoFollow = unix.O_NOFOLLOW

func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
