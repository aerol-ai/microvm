//go:build !linux

package mounts

import (
	"errors"
	"os"
	"syscall"
)

// Cgroups are Linux only; elsewhere a helper stays where sandboxd started it.

func openHelperCgroup(string) (*os.File, error) {
	return nil, errors.New("cgroups are Linux only")
}

func setCgroupFD(*syscall.SysProcAttr, int) {}
