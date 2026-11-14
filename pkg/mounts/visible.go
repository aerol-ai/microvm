package mounts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Visibility (finding F13). In the Kubernetes worker pod, sandboxd (the
// agent container) runs the mount helpers, while containerd and runsc (the
// runtime container) build the sandbox. Each container has its own mount
// namespace, and a mount made in the agent reaches the runtime only through
// a volume both mount with two-way (Bidirectional) propagation. Without
// that, the runtime bound the empty folder under the mount: the create
// succeeded, and the sandbox wrote to local disk instead of the external
// store. So with a runtime pid file set, MountAll answers only once each
// mount is the same file in the runtime's mount namespace, seen through
// /proc/<pid>/root, as it is here.

// ErrMountNotVisible is a mount the container runtime cannot see.
var ErrMountNotVisible = errors.New("the mount is not visible to the container runtime")

// checkVisible reports whether hostPath, as the runtime's mount namespace
// sees it, is the mount sandboxd sees: the same device and inode. A mount
// that did not propagate shows the folder under it, another device. With
// no runtime pid file, there is nothing to check (one mount namespace).
func (m *Manager) checkVisible(hostPath string) error {
	if m.runtimePIDFile == "" {
		return nil
	}
	raw, err := os.ReadFile(m.runtimePIDFile)
	if err != nil {
		return fmt.Errorf("%w: cannot read the runtime's pid: %v", ErrMountNotVisible, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("%w: %s holds no pid: %q", ErrMountNotVisible, m.runtimePIDFile, strings.TrimSpace(string(raw)))
	}
	// Only a path below the mounts root is ever looked at, here or through
	// the runtime's root: a mount point is always one.
	clean := filepath.Clean(hostPath)
	if !strings.HasPrefix(clean, filepath.Clean(m.rootDir)+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s is not below the mounts folder %s", ErrMountNotVisible, hostPath, m.rootDir)
	}
	mine, err := os.Stat(clean)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMountNotVisible, err)
	}
	theirs, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "root", clean))
	if err != nil {
		return fmt.Errorf("%w: %s as the runtime (pid %d) sees it: %v", ErrMountNotVisible, hostPath, pid, err)
	}
	if !os.SameFile(mine, theirs) {
		return fmt.Errorf("%w: the runtime (pid %d) sees the folder under %s, not the mount; "+
			"the mounts folder needs two-way mount propagation in both containers", ErrMountNotVisible, pid, hostPath)
	}
	// The same file proves nothing when the pid is a process in this
	// container's own mount namespace. That is what a pod without one
	// shared process namespace gives: the runtime wrote its pid as its
	// namespace numbers it (1), and pid 1 here is this container's own
	// first process. The daemon refuses mounts in such a pod
	// (mountsOffReason); this keeps the check honest on its own.
	selfNS, err := os.Stat(filepath.Join(procRoot, "self", "ns", "mnt"))
	if err != nil {
		return fmt.Errorf("%w: cannot read this container's mount namespace: %v", ErrMountNotVisible, err)
	}
	theirNS, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "mnt"))
	if err != nil {
		return fmt.Errorf("%w: cannot read the runtime's (pid %d) mount namespace: %v", ErrMountNotVisible, pid, err)
	}
	if os.SameFile(selfNS, theirNS) {
		return fmt.Errorf("%w: pid %d from %s is in sandboxd's own mount namespace, so the check would see only itself; "+
			"the worker pod must share one process namespace", ErrMountNotVisible, pid, m.runtimePIDFile)
	}
	return nil
}
