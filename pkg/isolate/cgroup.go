package isolate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroup v2 for group processes. The jail's resource caps are group-level
// (plans/isolate-runtime.md §2.1): one cgroup per workerd process under a
// daemon-owned parent, with cpu.max and memory.max from the group's caps, so
// a hot-looping tenant can degrade its own siblings but not the node. The
// process is placed at clone time (SysProcAttr.UseCgroupFD) so there is no
// window where it runs uncapped.
//
// The filesystem layout is the only Linux-specific part and it is plain
// files, so cgroupFS takes its root as a parameter and the tests drive it
// against a temp directory.

const (
	// DefaultCgroupRoot is the daemon's parent cgroup for isolate groups.
	DefaultCgroupRoot = "/sys/fs/cgroup/aerolvm-isolate"
	cgroupPeriodUS    = 100000
)

type cgroupFS struct {
	root string
}

// ensure creates (or reuses) root/name with the given caps and returns its
// path. The parent's controllers are enabled on first use; a parent that
// cannot enable cpu and memory is an error, not a silent no-cap.
func (c cgroupFS) ensure(name string, cpu float64, memMB int) (string, error) {
	if c.root == "" || !filepath.IsAbs(c.root) {
		return "", fmt.Errorf("isolate jail: cgroup root %q must be absolute", c.root)
	}
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return "", fmt.Errorf("isolate jail: invalid cgroup name %q", name)
	}
	if err := os.MkdirAll(c.root, 0o755); err != nil {
		return "", fmt.Errorf("isolate jail: cgroup root: %w", err)
	}
	if err := c.enableControllers(); err != nil {
		return "", err
	}
	dir := filepath.Join(c.root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("isolate jail: cgroup %s: %w", name, err)
	}
	if err := c.applyCaps(dir, cpu, memMB); err != nil {
		return "", err
	}
	return dir, nil
}

// enableControllers turns cpu, memory and pids on for children of root. On
// a real cgroupfs the file exists and lists what the parent delegated; a
// write that the kernel rejects (controller not available upward) surfaces
// as an error here.
func (c cgroupFS) enableControllers() error {
	path := filepath.Join(c.root, "cgroup.subtree_control")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Not a cgroup mount (tests, or an unusual host): nothing to enable
			// and nothing to enforce with; caps are then advisory.
			return nil
		}
		return err
	}
	// One write: cgroupfs accepts a space-separated list, and a plain file
	// (tests) then holds the whole set too.
	if err := writeControl(path, "+cpu +memory +pids"); err != nil {
		return fmt.Errorf("isolate jail: enable cgroup controllers under %s: %w", c.root, err)
	}
	return nil
}

// applyCaps writes the caps into an existing cgroup. Zero means unlimited on
// that axis ("max"), which is also what a warm blank host starts with until a
// tenant claims it.
func (c cgroupFS) applyCaps(dir string, cpu float64, memMB int) error {
	if cpu < 0 || memMB < 0 {
		return errors.New("isolate jail: cgroup caps must be >= 0")
	}
	cpuMax := "max " + strconv.Itoa(cgroupPeriodUS)
	if cpu > 0 {
		cpuMax = strconv.FormatInt(int64(cpu*cgroupPeriodUS), 10) + " " + strconv.Itoa(cgroupPeriodUS)
	}
	memMax := "max"
	if memMB > 0 {
		memMax = strconv.FormatInt(int64(memMB)<<20, 10)
	}
	if err := writeControl(filepath.Join(dir, "cpu.max"), cpuMax); err != nil {
		return fmt.Errorf("isolate jail: cpu.max: %w", err)
	}
	if err := writeControl(filepath.Join(dir, "memory.max"), memMax); err != nil {
		return fmt.Errorf("isolate jail: memory.max: %w", err)
	}
	return nil
}

// remove deletes an (empty) cgroup. The kernel refuses while a process is
// still inside, so callers wait for the process first.
func (c cgroupFS) remove(dir string) error {
	if dir == "" || filepath.Dir(dir) != filepath.Clean(c.root) {
		return fmt.Errorf("isolate jail: refusing to remove cgroup %q", dir)
	}
	// cgroupfs directories hold only control files, which cannot be unlinked
	// (EPERM, ignored) and vanish with the rmdir; on a plain directory
	// (tests) the same names are real files and must go first.
	for _, ctl := range []string{"cpu.max", "memory.max", "cgroup.subtree_control", "cgroup.procs"} {
		_ = os.Remove(filepath.Join(dir, ctl))
	}
	err := os.Remove(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// writeControl writes a cgroup control value. Control files always exist on
// cgroupfs (where a write replaces the value); on a plain directory (tests)
// they are created and truncated so a shorter value never leaves a tail.
func writeControl(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		// Some kernfs versions refuse O_TRUNC on control files; the write
		// itself replaces the value there.
		f, err = os.OpenFile(path, os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
	}
	_, werr := f.WriteString(value + "\n")
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
