//go:build !linux

package hostproc

import (
	"errors"
	"os"
	"syscall"
)

// Cgroups and pidfds are Linux only; elsewhere a process stays where
// sandboxd started it and dies with it.

func openCgroupDir(string, string) (*os.File, error) {
	return nil, errors.New("cgroups are Linux only")
}

func setCgroupFD(*syscall.SysProcAttr, int) {}

// Open cannot hold a process off Linux.
func Open(int, uint64) (Process, error) { return nil, ErrUnsupported }
