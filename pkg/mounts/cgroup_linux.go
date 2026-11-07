//go:build linux

package mounts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openHelperCgroup makes the helpers' cgroup under root and opens it for
// clone. cgroup v2 only: v1 has no CLONE_INTO_CGROUP and no single tree to
// leave sandboxd's unit through.
func openHelperCgroup(root string) (*os.File, error) {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("no cgroup v2 hierarchy at %s: %w", root, err)
	}
	dir := filepath.Join(root, helperCgroupName)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	// The kernel makes cgroup.procs with the cgroup, so a missing one means
	// dir is not a cgroup.
	if _, err := os.Stat(filepath.Join(dir, "cgroup.procs")); err != nil {
		return nil, fmt.Errorf("%s is not a cgroup: %w", dir, err)
	}
	return os.Open(dir)
}

// setCgroupFD makes the clone start the process in the cgroup open at fd
// (clone3 with CLONE_INTO_CGROUP, Linux 5.7+).
func setCgroupFD(attr *syscall.SysProcAttr, fd int) {
	attr.UseCgroupFD = true
	attr.CgroupFD = fd
}
