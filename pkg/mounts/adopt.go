package mounts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Adoption: a sandboxd that restarts finds the helpers of its running
// sandboxes still serving (cgroup.go). Mounting such a sandbox again would
// start a second helper on a path the first still holds, and a container
// already bound to the first could never see the second. So Reestablish
// takes each live mount over as it is: the mountpoint must be live and,
// for a FUSE mount, exactly one process (helperFor) must run the very
// command the sandbox's spec builds today. Anything else at that path (a
// dead FUSE mount, a helper running other arguments) is cleared and mounted
// afresh.

var (
	// errProcessGone: the process exited, or its pid now names another.
	errProcessGone = errors.New("process is gone")
	// errAdoptionUnsupported: this host cannot hand a helper to the next
	// sandboxd (not Linux).
	errAdoptionUnsupported = errors.New("mount helpers do not outlive sandboxd on this host")
	// errAdoptedToolExited is an adopted helper's exit. Its exit status went
	// to init, which reaped it, so there is no status to report.
	errAdoptedToolExited = errors.New("adopted mount tool exited")
)

// procRoot is procfs. A var so tests can stand in a directory.
var procRoot = "/proc"

// openHelperProcess opens a listed helper if it still runs argv (a pidfd on
// Linux). A var so tests can stand in a process.
var openHelperProcess = openHelperPidfd

// liveProcess is a running helper this sandboxd did not start.
type liveProcess interface {
	Pid() int
	Signal(sig syscall.Signal) error
	// Done is closed once the process has exited.
	Done() <-chan struct{}
	Close() error
}

// helperProcess is a process that may be a mount helper.
type helperProcess struct {
	pid  int
	ppid int // 0 when unknown
	argv []string
}

// listHelperProcesses lists the processes a helper could be: the members of
// the helpers' cgroup when it exists, else every process (a host where the
// cgroup could not be made, where a helper outlives sandboxd only without
// systemd).
func (m *Manager) listHelperProcesses() []helperProcess {
	pids, err := readPIDs(m.cgroup.procsFile())
	if err != nil {
		pids = allPIDs(procRoot)
	}
	out := make([]helperProcess, 0, len(pids))
	for _, pid := range pids {
		argv, err := readCmdline(pid)
		if err != nil || len(argv) == 0 || argv[0] == "" {
			continue // gone, or a kernel thread
		}
		out = append(out, helperProcess{pid: pid, ppid: readPPID(pid), argv: argv})
	}
	return out
}

// readPIDs reads a cgroup.procs file.
func readPIDs(path string) ([]int, error) {
	if path == "" {
		return nil, fs.ErrNotExist
	}
	raw, err := os.ReadFile(path)
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

// allPIDs lists every process under root.
func allPIDs(root string) []int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 && e.IsDir() {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readCmdline is pid's argv.
func readCmdline(pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\x00"), nil
}

// readPPID is pid's parent (field 4 of /proc/<pid>/stat), or 0.
func readPPID(pid int) int {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	// The command name (field 2) is in parentheses and may hold spaces and
	// parentheses itself; the fields after it start past the last ')'.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// helperFor picks the one process running planArgv. A process the helper
// has just forked carries the helper's argv until it execs (sshfs starting
// ssh, again on every reconnect), so a match whose parent is another match
// is that child, not a second helper. Two unrelated matches are two helpers
// on one path: nil, and the path is cleared and mounted afresh.
func helperFor(helpers []helperProcess, planArgv []string) *helperProcess {
	var matches []*helperProcess
	for i := range helpers {
		if runsPlan(helpers[i].argv, planArgv) {
			matches = append(matches, &helpers[i])
		}
	}
	var root *helperProcess
	for _, h := range matches {
		forked := slices.ContainsFunc(matches, func(o *helperProcess) bool { return o.pid == h.ppid })
		if forked {
			continue
		}
		if root != nil {
			return nil
		}
		root = h
	}
	return root
}

// runsPlan reports whether argv runs planArgv: the same arguments after the
// program, which may be run directly, by path, or through the interpreter of
// a #! script (whose argv starts with the interpreter).
func runsPlan(argv, planArgv []string) bool {
	n := len(planArgv)
	if n == 0 || len(argv) < n {
		return false
	}
	off := len(argv) - n
	return filepath.Base(argv[off]) == filepath.Base(planArgv[0]) && slices.Equal(argv[off+1:], planArgv[1:])
}

// mountProbe is what a mount path holds.
type mountProbe int

const (
	notMounted mountProbe = iota
	mountLive
	// mountBroken: the path cannot be read, as a FUSE mount whose tool is
	// gone answers ENOTCONN. It has to be unmounted before it can be
	// mounted again.
	mountBroken
)

// probeMount reports what hostPath holds: a mount is a path on another
// device than its parent. A var so tests need no real mount.
var probeMount = func(hostPath string) mountProbe {
	st, err := os.Stat(hostPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return notMounted
		}
		return mountBroken
	}
	parent := pathDevOf(filepath.Dir(hostPath))
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || parent == 0 || uint64(sys.Dev) == parent {
		return notMounted
	}
	return mountLive
}

// adoptOne takes over mount index of sandboxID when it is still served. It
// returns nil when it is not, and the caller mounts it afresh.
func (m *Manager) adoptOne(sandboxID string, index int, spec models.MountSpec, helpers []helperProcess) (*mountState, ContainerBind) {
	adapter, ok := m.adapters[spec.Type]
	if !ok {
		return nil, ContainerBind{}
	}
	hostPath := m.hostPath(sandboxID, index)
	if probeMount(hostPath) != mountLive {
		return nil, ContainerBind{}
	}
	// Build is pure: the plan names the command a live helper must be
	// running, and what the supervisor restarts if it exits.
	plan, err := adapter.Build(sandboxID, index, spec, hostPath, m.credDir)
	if err != nil {
		return nil, ContainerBind{}
	}
	state := &mountState{
		sandboxID: sandboxID,
		index:     index,
		spec:      spec,
		hostPath:  hostPath,
		plan:      plan,
		startedAt: time.Now().UTC(),
	}
	bind := ContainerBind{HostPath: hostPath, ContainerPath: spec.Target, ReadOnly: spec.ReadOnly}
	if plan.IsKernelMount {
		return state, bind // nothing runs; the kernel holds the mount
	}
	match := helperFor(helpers, plan.Argv)
	if match == nil {
		return nil, ContainerBind{}
	}
	proc, err := openHelperProcess(match.pid, match.argv)
	if err != nil {
		return nil, ContainerBind{}
	}
	state.proc = proc
	state.exit = watchLiveExit(proc)
	state.output = &helperOutput{path: m.helperLogPath(sandboxID, index)}
	state.supervised = true
	go m.superviseExit(state)
	m.logger.Info("mounts: adopted running mount helper", "sandbox_id", sandboxID, "index", index, "type", string(spec.Type), "pid", match.pid)
	return state, bind
}

// clearStaleMount readies mount index of sandboxID to be mounted afresh: it
// kills any helper still naming the path and unmounts whatever is left
// there. Without it, a dead FUSE mount fails the mkdir in mountOne (ENOTCONN
// reads as "file exists"), and a live one would sit under the new mount.
func (m *Manager) clearStaleMount(sandboxID string, index int, helpers []helperProcess) {
	hostPath := m.hostPath(sandboxID, index)
	for _, h := range helpers {
		if h.argv[len(h.argv)-1] != hostPath {
			continue
		}
		proc, err := openHelperProcess(h.pid, h.argv)
		if err != nil {
			continue
		}
		m.logger.Info("mounts: stopping stale mount helper", "sandbox_id", sandboxID, "index", index, "pid", h.pid)
		killLiveProcess(proc)
	}
	if probeMount(hostPath) != notMounted {
		if err := unmountPath(hostPath); err != nil {
			m.logger.Warn("mounts: unmount stale mount failed", "path", hostPath, "error", err)
		}
	}
}

// watchLiveExit reports an adopted helper's exit the way watchExit reports a
// child's.
func watchLiveExit(p liveProcess) *procExit {
	e := &procExit{done: make(chan struct{})}
	go func() {
		<-p.Done()
		e.err = errAdoptedToolExited
		close(e.done)
	}()
	return e
}

// killGroup signals a helper's process group (its FUSE children, such as
// sshfs's ssh). A var so tests never signal a real group.
var killGroup = func(pgid int, sig syscall.Signal) { _ = syscall.Kill(-pgid, sig) }

// adoptedKillGrace is how long an adopted helper gets to exit on SIGTERM.
var adoptedKillGrace = 3 * time.Second

// killLiveProcess stops an adopted helper as killMount stops a child: SIGTERM
// to it and its group, then SIGKILL after a grace period. The group is
// signalled only while the leader lives, so its id cannot name another
// group yet.
func killLiveProcess(p liveProcess) {
	pid := p.Pid()
	_ = p.Signal(syscall.SIGTERM)
	killGroup(pid, syscall.SIGTERM)
	select {
	case <-p.Done():
	case <-time.After(adoptedKillGrace):
		_ = p.Signal(syscall.SIGKILL)
		killGroup(pid, syscall.SIGKILL)
		<-p.Done()
	}
	_ = p.Close()
}

// hostPath is where mount index of sandboxID is mounted on the host.
func (m *Manager) hostPath(sandboxID string, index int) string {
	return filepath.Join(m.rootDir, sandboxID, strconv.Itoa(index))
}

// helperLogPath is the log file of mount index's helper, beside the mount
// path (never inside it: the mount path is what the container sees).
func (m *Manager) helperLogPath(sandboxID string, index int) string {
	return filepath.Join(m.rootDir, sandboxID, fmt.Sprintf("%d.log", index))
}
