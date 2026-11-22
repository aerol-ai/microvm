package rootd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// cgroupHostKernel is the HostKernel over cgroup v2 files: root is the
// helper's host-process cgroup parent, on the cgroup mount. Only Start and
// the fallback kill need Linux (hosts_linux.go); the rest is plain files,
// which tests drive on a temp folder.
type cgroupHostKernel struct {
	root string
}

// hostKillWait bounds how long Kill waits for a group to empty.
var hostKillWait = 10 * time.Second

func (k cgroupHostKernel) dir(group string) (string, error) {
	if group == "" || filepath.IsAbs(group) || filepath.Clean(group) != group || strings.HasPrefix(group, "..") {
		return "", fmt.Errorf("host group %q is not a group under the host-process parent", group)
	}
	return filepath.Join(k.root, filepath.FromSlash(group)), nil
}

func (k cgroupHostKernel) EnsureGroup(group string) error {
	dir, err := k.dir(group)
	if err != nil {
		return err
	}
	if _, err := os.Stat(k.root); err != nil {
		return fmt.Errorf("host-process cgroup parent %s: %w", k.root, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return nil
}

// SetLimits turns the cpu, memory and pids controllers on for the hosts of
// the group's kind, then writes the limits. Zero on an axis is "max".
func (k cgroupHostKernel) SetLimits(group string, l rootpolicy.HostLimits) error {
	dir, err := k.dir(group)
	if err != nil {
		return err
	}
	if err := writeExisting(filepath.Join(filepath.Dir(dir), "cgroup.subtree_control"), "+cpu +memory +pids"); err != nil {
		return fmt.Errorf("turn on cpu, memory and pids for %s: %w", filepath.Dir(group), err)
	}
	cpu := "max 100000"
	if l.CPUMillis > 0 {
		cpu = strconv.FormatUint(uint64(l.CPUMillis)*100, 10) + " 100000"
	}
	mem := "max"
	if l.MemoryMB > 0 {
		mem = strconv.FormatUint(l.MemoryMB<<20, 10)
	}
	pids := "max"
	if l.Pids > 0 {
		pids = strconv.FormatUint(uint64(l.Pids), 10)
	}
	for _, f := range []struct{ name, value string }{{"cpu.max", cpu}, {"memory.max", mem}, {"pids.max", pids}} {
		if err := writeExisting(filepath.Join(dir, f.name), f.value); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return nil
}

func (k cgroupHostKernel) Procs(group string) ([]int, error) {
	dir, err := k.dir(group)
	if err != nil {
		return nil, err
	}
	return hostproc.ReadPIDs(filepath.Join(dir, "cgroup.procs"))
}

// Kill kills the group's processes, by cgroup.kill where the kernel has it
// (5.14) and one pidfd at a time where not, and waits for the group to
// empty.
func (k cgroupHostKernel) Kill(ctx context.Context, group string) error {
	dir, err := k.dir(group)
	if err != nil {
		return err
	}
	if err := writeExisting(filepath.Join(dir, "cgroup.kill"), "1"); err != nil {
		procs, perr := k.Procs(group)
		if perr != nil {
			return perr
		}
		for _, pid := range procs {
			if p, _, err := hostproc.OpenPID(pid); err == nil {
				_ = p.Signal(syscall.SIGKILL)
				_ = p.Close()
			}
		}
	}
	deadline := time.Now().Add(hostKillWait)
	for {
		procs, err := k.Procs(group)
		if err != nil {
			return err
		}
		if len(procs) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("group %s still holds %v after a kill", group, procs)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// RemoveGroup removes an empty group. Right after its last process exits
// the kernel may still count the group populated for a moment (the exit is
// not fully torn down), and refuses the removal with EBUSY: it is tried
// again, for up to hostKillWait.
func (k cgroupHostKernel) RemoveGroup(group string) error {
	dir, err := k.dir(group)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(hostKillWait)
	for {
		err := os.Remove(dir)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, syscall.EBUSY) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (k cgroupHostKernel) Groups(parent string) ([]string, error) {
	dir, err := k.dir(parent)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func (k cgroupHostKernel) StartTicks(pid int) (uint64, error) { return hostproc.StartTicks(pid) }

func (k cgroupHostKernel) Start(cmd *exec.Cmd, group string) error {
	dir, err := k.dir(group)
	if err != nil {
		return err
	}
	return startInGroup(cmd, dir)
}
