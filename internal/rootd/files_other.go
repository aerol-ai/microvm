//go:build !linux

package rootd

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// mkfifoAt makes a FIFO at name in dir. x/sys has no mkfifoat off Linux,
// where only tests run the helper, so it goes by path there.
func mkfifoAt(_ int, dir, name string, mode uint32) error {
	return unix.Mkfifo(filepath.Join(dir, name), mode)
}
