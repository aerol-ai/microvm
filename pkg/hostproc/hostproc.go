// Package hostproc is what a process needs to outlive sandboxd and be taken
// over by the next one: a cgroup outside sandboxd's unit to start in, and a
// way to find and hold it again at boot.
//
// systemd stops sandboxd by killing every process in the unit's cgroup
// (KillMode=control-group), and every node upgrade restarts sandboxd. A
// process sandboxd starts there dies with it. Firecracker VMs (aerolvm-vmm)
// and mount helpers (aerolvm-mounts) already leave the unit; WASM workers
// and V8-isolate group hosts use this package to do the same. The
// Firecracker and mount code keep their own copies of these helpers for
// now; they predate this package.
//
// Three parts:
//
//   - Cgroup starts a process inside a cgroup of its own under the cgroup v2
//     root (clone3 with CLONE_INTO_CGROUP), so it is never in the unit's
//     cgroup, not even for an instant before a move.
//   - Open holds a running process by a pidfd, checked against its start
//     time, so a signal can never reach a later process with the same pid.
//   - StartTicks, BootID and Cmdline name a process for good: a pid is
//     reused, a (boot, pid, start) triple is not.
//
// On a host without cgroup v2, or where sandboxd may not make the cgroup,
// processes start where they did before and die with sandboxd as before;
// the reason is logged once.
package hostproc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrGone: the process exited, or its pid now names another process.
	ErrGone = errors.New("process is gone")
	// ErrUnsupported: this host cannot hand a process to the next sandboxd
	// (not Linux).
	ErrUnsupported = errors.New("processes do not outlive sandboxd on this host")
)

// Host seams. Vars so tests never touch the host's procfs or cgroups.
var (
	// ProcRoot is procfs.
	ProcRoot = "/proc"
	// CgroupRoot is the cgroup v2 mount.
	CgroupRoot = "/sys/fs/cgroup"
)

// Process is a running process this sandboxd did not start, held so a
// signal reaches it and no later process with the same pid.
type Process interface {
	Pid() int
	Signal(sig syscall.Signal) error
	// Done is closed once the process has exited.
	Done() <-chan struct{}
	Close() error
}

// Cgroup is the cgroup, under the cgroup v2 root, that a kind of process
// starts in. It is set up on the first start, not at daemon start: a node
// may never run that kind of process. Once off, it stays off for the life
// of the sandboxd process.
type Cgroup struct {
	logger *slog.Logger
	root   string
	name   string
	// what names the processes in the one log line a disabled cgroup
	// writes ("WASM workers").
	what string

	setup   sync.Once
	logOnce sync.Once

	mu sync.Mutex
	// dir is the open cgroup directory, passed to clone. It is never
	// closed once open: a concurrent start may be using its descriptor
	// number, and one descriptor for the process's life costs nothing.
	dir *os.File
	off bool
}

// NewCgroup returns the cgroup name under root (CgroupRoot when empty).
func NewCgroup(logger *slog.Logger, root, name, what string) *Cgroup {
	if logger == nil {
		logger = slog.Default()
	}
	if root == "" {
		root = CgroupRoot
	}
	return &Cgroup{logger: logger, root: root, name: name, what: what}
}

// Path is the cgroup's directory.
func (c *Cgroup) Path() string {
	if c == nil {
		return ""
	}
	return filepath.Join(c.root, c.name)
}

// FD returns the cgroup directory descriptor to start a process in, or
// false when processes stay in sandboxd's cgroup.
func (c *Cgroup) FD() (int, bool) {
	if c == nil {
		return 0, false
	}
	c.setup.Do(func() {
		dir, err := openCgroupDir(c.root, c.name)
		if err != nil {
			c.Disable(err)
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

// Active reports whether processes start in the cgroup: they then outlive
// sandboxd. It sets the cgroup up when no start has yet.
func (c *Cgroup) Active() bool {
	_, ok := c.FD()
	return ok
}

// Disable turns the cgroup off for good and logs why, once.
func (c *Cgroup) Disable(err error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.off = true
	c.mu.Unlock()
	c.logOnce.Do(func() {
		c.logger.Warn(c.what+" run in sandboxd's cgroup: they will stop when sandboxd restarts",
			"cgroup", c.Path(), "error", err)
	})
}

// Start starts the command newCmd builds inside the cgroup when it can.
// Either the cgroup or the command can make a start fail, and a plain start
// tells which: when it works, the cgroup was the problem, so it is turned
// off for good and processes start as they did before. newCmd is called a
// second time for that plain start, since an exec.Cmd is used once.
func (c *Cgroup) Start(newCmd func() (*exec.Cmd, error)) (*exec.Cmd, error) {
	cmd, err := newCmd()
	if err != nil {
		return nil, err
	}
	fd, ok := c.FD()
	if !ok {
		return cmd, startCmd(cmd)
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	setCgroupFD(cmd.SysProcAttr, fd)
	cgErr := startCmd(cmd)
	if cgErr == nil {
		return cmd, nil
	}
	plain, err := newCmd()
	if err != nil {
		return nil, err
	}
	if err := startCmd(plain); err != nil {
		return nil, err
	}
	c.Disable(fmt.Errorf("start %s in the cgroup: %w", filepath.Base(plain.Path), cgErr))
	return plain, nil
}

// startCmd starts a command. Tests replace it to see which cgroup a process
// would start in.
var startCmd = func(cmd *exec.Cmd) error { return cmd.Start() }

// PIDs lists the cgroup's processes. A cgroup that was never made has none.
func (c *Cgroup) PIDs() ([]int, error) {
	if c == nil {
		return nil, nil
	}
	return ReadPIDs(filepath.Join(c.Path(), "cgroup.procs"))
}

// ReadPIDs reads a cgroup.procs file. A missing file lists nothing.
func ReadPIDs(path string) ([]int, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(string(raw)) {
		if pid, err := strconv.Atoi(field); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// StartTicks is when pid started, in clock ticks after boot (field 22 of
// /proc/<pid>/stat).
func StartTicks(pid int) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(ProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	// The command name (field 2) is in parentheses and may hold spaces and
	// parentheses itself; the fields after it start past the last ')'.
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, fmt.Errorf("pid %d: malformed stat", pid)
	}
	fields := strings.Fields(string(raw[end+1:]))
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, fmt.Errorf("pid %d: short stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// BootID identifies this boot of the host.
func BootID() (string, error) {
	raw, err := os.ReadFile(filepath.Join(ProcRoot, "sys/kernel/random/boot_id"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// Cmdline is pid's argv.
func Cmdline(pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(ProcRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\x00"), nil
}

// OpenPID holds pid as it is now: it reads its start time and opens it
// against that, so a process that exits in between is never taken for it.
func OpenPID(pid int) (Process, uint64, error) {
	ticks, err := StartTicks(pid)
	if err != nil {
		return nil, 0, fmt.Errorf("pid %d: %w: %v", pid, ErrGone, err)
	}
	p, err := Open(pid, ticks)
	if err != nil {
		return nil, 0, err
	}
	return p, ticks, nil
}

// Stop ends p: SIGTERM, then SIGKILL after grace. It waits for the exit and
// releases p.
func Stop(p Process, grace time.Duration) {
	if p == nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	select {
	case <-p.Done():
	case <-time.After(grace):
		_ = p.Signal(syscall.SIGKILL)
		<-p.Done()
	}
	_ = p.Close()
}
