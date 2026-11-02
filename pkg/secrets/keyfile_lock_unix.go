//go:build unix

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockKeyFile takes an exclusive lock that every writer of the key file at
// path holds across its read, compare and rename: the daemon's rewrap and
// `sandboxd key` run in different processes, and a rename alone makes each
// write atomic but not a read-compare-write (two writers that read the same
// file would both succeed and one change would be lost). The lock is on a
// stable sidecar, never on the file the rename replaces.
func lockKeyFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open key file lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		lf.Close()
	}, nil
}
