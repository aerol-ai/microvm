// Package gvisorpids caps how many tasks (processes and threads) a gVisor
// sandbox may run, inside the sandbox's own kernel (the runsc sentry).
//
// Why it exists. runsc applies the OCI linux.resources.pids.limit only to the
// HOST cgroup that holds the sentry and its helpers (runsc/cgroup, pids.set);
// the sentry's own cgroupfs pids controller starts at "max" and runsc/boot
// never seeds it from the spec. Under the default systrap platform every
// sandbox process with its own address space is backed by a host stub process
// plus a sysmsg thread, so a fork bomb uses about two host tasks per sandbox
// task and reaches the host pids.max at roughly half of it. The next stub
// clone fails with EAGAIN, mm.Fork returns that as a plain Go error, and
// kernel.ExtractErrno panics on it ("Unknown syscall 220 error: createStub:
// failed to get clone" on arm64; 220 is clone there, 56 on amd64): the whole
// sentry dies, toolboxd with it (UC-320).
//
// A pids.max inside the sentry is checked by Task.Clone before the new task
// starts, so the bomb gets EAGAIN from fork, as on runc, and the sandbox
// stays up. The driver passes the cap to toolboxd (PID 1) in EnvVar, toolboxd
// writes it with Apply before it reports ready, and the host cgroup is sized
// by Limits so the sentry's own cap always trips first.
package gvisorpids

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// EnvVar carries the sentry task cap from the driver to toolboxd.
const EnvVar = "SB_GVISOR_PIDS_MAX"

const (
	// tasksPerMiB bounds the cap by the sandbox's memory. A sleeping sandbox
	// process costs about 0.4 MiB of the sandbox's host memory under systrap
	// (stub process, sysmsg thread and sentry state; measured with runsc
	// release-20261026.0: 1,500 sleeping processes held 604 MB). A 1 GiB
	// sandbox is OOM-killed whole at about 2,400 of them, which ends the
	// sandbox just as the pids panic does, so one task per MiB keeps a full
	// bomb at about 40% of the memory limit.
	tasksPerMiB = 1
	// minTasks keeps a small sandbox usable: toolboxd's own threads count.
	minTasks = 128
	// hostTasksPerTask is the host tasks one sandbox task can hold under
	// systrap: a single-threaded process is a stub process plus one sysmsg
	// thread; extra threads of one process share its stub.
	hostTasksPerTask = 2
	// hostHeadroom covers the sentry's and gofer's own Go threads and the
	// systrap stub pool, which are not sandbox tasks (28 at idle).
	hostHeadroom = 1024
)

// Limits returns the task cap for the sentry and the pids limit for the
// sandbox's host cgroup. pidsLimit is the node's SB_SANDBOX_PIDS_LIMIT and
// caps the sentry, as it caps a runc sandbox; memoryMB lowers it so a full
// bomb fits in the sandbox's memory. The host limit is what the sentry needs
// at that cap, so the host cgroup never refuses a clone first. Both are zero
// when pidsLimit is zero (unlimited).
func Limits(pidsLimit int64, memoryMB int) (sentry, host int64) {
	if pidsLimit <= 0 {
		return 0, 0
	}
	sentry = pidsLimit
	if memoryMB > 0 {
		sentry = min(sentry, max(int64(memoryMB)*tasksPerMiB, minTasks))
	}
	return sentry, hostTasksPerTask*sentry + hostHeadroom
}

// ForRuntime returns the pids limit for a sandbox's host cgroup and the env
// that has toolboxd cap the sandbox inside gVisor, for the OCI runtime binary
// a driver resolved ("runsc" is gVisor; "" and "runc" are runc). runc
// enforces the node's limit itself, so it gets that limit and no env. runsc
// applies the spec's limit only to the host cgroup, so the cap moves into the
// sentry and the host cgroup is sized to hold it (Limits).
func ForRuntime(ociRuntime string, pidsLimit int64, memoryMB int) (host int64, env []string) {
	if ociRuntime != "runsc" {
		return pidsLimit, nil
	}
	sentry, host := Limits(pidsLimit, memoryMB)
	if sentry <= 0 {
		return host, nil
	}
	return host, []string{EnvVar + "=" + strconv.FormatInt(sentry, 10)}
}

// pidsMaxPaths are where a container's own pids.max sits inside gVisor:
// runsc's default in-sandbox cgroup v1 layout binds the container's cgroup
// at /sys/fs/cgroup/pids, and --in-sandbox-cgroup=v2 at /sys/fs/cgroup.
var pidsMaxPaths = []string{
	"sys/fs/cgroup/pids/pids.max",
	"sys/fs/cgroup/pids.max",
}

// ErrNoPidsController means no pids.max was found under root: the sandbox
// has no cgroup mount, or the runtime is not gVisor.
var ErrNoPidsController = errors.New("no pids.max under /sys/fs/cgroup")

// Apply sets the container's pids.max under root to limit and returns the
// file it set. It never raises a limit that is already at or below limit.
func Apply(root string, limit int64) (string, error) {
	if limit <= 0 {
		return "", fmt.Errorf("pids limit must be above 0, got %d", limit)
	}
	for _, rel := range pidsMaxPaths {
		path := filepath.Join(root, rel)
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return path, err
		}
		if cur, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && cur <= limit {
			return path, nil
		}
		return path, writeExisting(path, strconv.FormatInt(limit, 10))
	}
	return "", ErrNoPidsController
}

// writeExisting writes val to a control file that must already exist (no
// O_CREATE: a missing file means no controller, not a file to make). O_TRUNC
// is what a shell's ">" sends; gVisor's cgroupfs accepts it.
func writeExisting(path, val string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(val); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
