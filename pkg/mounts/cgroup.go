package mounts

import (
	"log/slog"
	"os"
	"sync"
)

// Mount helpers outlive sandboxd the way Firecracker VMs do (the aerolvm-vmm
// cgroup, internal/runtime/firecracker/vmm_adopt.go). systemd stops sandboxd
// by killing every process in its unit's cgroup (KillMode=control-group), so
// a helper started there died with every restart and upgrade, and every
// external-storage mount of every running sandbox went with it. Three parts
// keep them serving instead:
//
//   - spawnHelper starts each helper in a cgroup of its own,
//     helperCgroupName under the cgroup v2 root, outside sandboxd's unit.
//   - Its output goes to a file, not a pipe sandboxd reads (helperOutput).
//   - At boot, Reestablish adopts a helper still serving a sandbox's mount
//     instead of mounting it again (adopt.go).
//
// On a host without cgroup v2, or where sandboxd may not create the cgroup,
// helpers start where they did before and die with sandboxd as before; the
// reason is logged once.

// helperCgroupName is the cgroup, under the cgroup v2 root, every mount
// helper runs in.
const helperCgroupName = "aerolvm-mounts"

// helperCgroupRoot is the cgroup v2 mount. A var so tests never touch the
// host's cgroups (main_test.go).
var helperCgroupRoot = "/sys/fs/cgroup"

// openCgroupDir makes and opens the helpers' cgroup under a root. A var so
// tests can stand in a directory.
var openCgroupDir = openHelperCgroup

// helperCgroup is the cgroup helpers start in. It is set up on the first
// helper start, not at daemon start: most nodes never mount external
// storage. Once off, it stays off for the life of the process.
type helperCgroup struct {
	logger *slog.Logger
	root   string

	setup   sync.Once
	logOnce sync.Once

	mu sync.Mutex
	// dir is the open cgroup directory, passed to clone. It is never closed
	// once opened: a concurrent start may be using its descriptor number,
	// and one descriptor for the process's life costs nothing.
	dir *os.File
	off bool
}

func newHelperCgroup(logger *slog.Logger, root string) *helperCgroup {
	return &helperCgroup{logger: logger, root: root}
}

// fd returns the cgroup directory descriptor to start a helper in, or false
// when helpers stay in sandboxd's cgroup.
func (c *helperCgroup) fd() (int, bool) {
	if c == nil {
		return 0, false
	}
	c.setup.Do(func() {
		dir, err := openCgroupDir(c.root)
		if err != nil {
			c.disable(err)
			return
		}
		c.mu.Lock()
		c.dir = dir
		c.mu.Unlock()
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.off || c.dir == nil {
		return 0, false
	}
	return int(c.dir.Fd()), true
}

// disable turns the cgroup off for good and logs why, once.
func (c *helperCgroup) disable(err error) {
	c.mu.Lock()
	c.off = true
	c.mu.Unlock()
	c.logOnce.Do(func() {
		c.logger.Warn("mount helpers run in sandboxd's cgroup: external-storage mounts will stop when sandboxd restarts",
			"cgroup", c.root+"/"+helperCgroupName, "error", err)
	})
}

// procsFile is the cgroup's member list.
func (c *helperCgroup) procsFile() string {
	if c == nil {
		return ""
	}
	return c.root + "/" + helperCgroupName + "/cgroup.procs"
}
