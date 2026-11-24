//go:build unix

package raftlogdir

import (
	"os"
	"syscall"
)

// openRecord opens path without following a link (ELOOP) and without
// waiting on a FIFO or a device.
func openRecord(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
