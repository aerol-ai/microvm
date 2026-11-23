//go:build unix

package ownerlease

import (
	"os"
	"syscall"
)

// openNoFollow opens path for reading with no link followed at its last
// element (ELOOP for a link) and without waiting on a pipe.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
