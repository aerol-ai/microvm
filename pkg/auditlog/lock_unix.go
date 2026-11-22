//go:build unix

package auditlog

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockExclusive(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }

// tryLockExclusive takes the lock only if no one holds it (ErrLockBusy).
func tryLockExclusive(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrLockBusy
	}
	return err
}

// openNoFollow refuses a symlink in an open's last component.
const openNoFollow = unix.O_NOFOLLOW

func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
