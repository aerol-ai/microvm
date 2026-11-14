package mounts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// maxCapturedMountBytes caps how much mount-tool output an error carries.
// Mount tools (mount-s3, rclone, sshfs) print the actionable failure line just
// before they exit, so we keep the TAIL: a 4 KiB window is plenty for a stack
// of credential/region/endpoint errors.
const maxCapturedMountBytes = 4 << 10

// maxHelperLogBytes caps a mount tool's log file on disk. The tool appends
// (O_APPEND), so cutting the file back to empty from here is safe while it
// writes, and only the tail is ever read: a chatty --debug run costs at most
// this much disk per mount.
const maxHelperLogBytes = 1 << 20

// helperLogTrimInterval is how often the supervisor checks a tool's log size.
var helperLogTrimInterval = 30 * time.Second

// helperOutput is a mount tool's stdout and stderr: a file the tool writes
// directly (rootDir/<id>/<index>.log, mode 0600). It is a file and not a
// pipe to sandboxd so the tool outlives sandboxd: once the read end of a
// pipe is gone, the tool's next write raises SIGPIPE, which kills sshfs and
// rclone (a Go program exits on SIGPIPE on fds 1 and 2). It backs the error
// of a mount that never becomes ready, so a bad credential, region or
// endpoint is diagnosable instead of a bare "timed out waiting for mount"
// (cluster-hetero UC-81..84).
type helperOutput struct {
	path string
}

// openHelperOutput truncates path and opens it for a new run of the tool.
// The caller hands the file to the tool and closes its own copy.
func openHelperOutput(path string) (*os.File, *helperOutput, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open mount tool log: %w", err)
	}
	return f, &helperOutput{path: path}, nil
}

// String returns the last maxCapturedMountBytes of the tool's output with
// surrounding whitespace trimmed. Safe on a nil receiver so callers don't
// have to nil-check before logging.
func (o *helperOutput) String() string {
	if o == nil {
		return ""
	}
	f, err := os.Open(o.path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := max(st.Size()-maxCapturedMountBytes, 0)
	buf := make([]byte, st.Size()-off)
	n, _ := f.ReadAt(buf, off)
	return strings.TrimSpace(string(buf[:n]))
}

// trim empties the log once it grows past maxHelperLogBytes.
func (o *helperOutput) trim() {
	if o == nil {
		return
	}
	if st, err := os.Stat(o.path); err == nil && st.Size() > maxHelperLogBytes {
		_ = os.Truncate(o.path, 0)
	}
}

// ErrMountToolUnavailable is a mount whose tool (mount-s3, sshfs, rclone,
// mount) is not installed on this node, as on a local install, which skips
// them. It is the node's configuration, never the request: the adapters fix
// argv[0], so no mount spec can name a missing program. The API answers it
// with 501 mount_tool_unavailable instead of the catch-all 400.
var ErrMountToolUnavailable = errors.New("mount tool is not installed on this node")

// toolStartError marks a failure to start a mount tool as
// ErrMountToolUnavailable when the program is missing: exec.ErrNotFound from
// the $PATH lookup, or ENOENT starting an absolute path (or the interpreter
// its #! line names). The exec error, which names the tool, stays wrapped.
// Any other start failure is returned unchanged.
func toolStartError(tool string, err error) error {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s: %w", ErrMountToolUnavailable, tool, err)
	}
	return err
}

// procExit reports a mount tool's exit. One goroutine reaps the process
// (cmd.Wait); everyone else watches done. Two parties need the exit: the
// readiness wait, which must stop as soon as the tool is gone, and the
// supervisor, which restarts it once the mount is up. cmd.Wait may only be
// called once, so neither may call it themselves.
type procExit struct {
	done chan struct{} // closed once cmd.Wait has returned
	err  error         // cmd.Wait's result; read only after done is closed
}

func watchExit(cmd *exec.Cmd) *procExit {
	e := &procExit{done: make(chan struct{})}
	go func() {
		e.err = cmd.Wait()
		close(e.done)
	}()
	return e
}

// status reports how the tool exited, or false while it is still running.
// It never blocks.
func (e *procExit) status() (string, bool) {
	select {
	case <-e.done:
	default:
		return "", false
	}
	if e.err == nil {
		return "exit status 0", true
	}
	return e.err.Error(), true
}

// spawnHelper starts a supervised FUSE mount tool with its stdout and stderr
// in a log file (helperOutput), and starts the one goroutine that reaps it.
// Shared by the initial mount (mountOne) and the supervisor's restart path so
// both surface the tool's output identically. SysProcAttr.Setpgid keeps the
// process in its own group; killMount signals the whole group so FUSE helper
// children die with it.
//
// The tool starts inside the helpers' cgroup (helperCgroup) when the host
// has one, so stopping sandboxd's unit does not stop it. The clone puts it
// there (CLONE_INTO_CGROUP) rather than a move after it starts: a tool that
// forks before such a move (sshfs starts ssh) would leave the child in
// sandboxd's cgroup, to die with the next restart. If that clone fails and a
// plain start works, the cgroup is turned off for good and helpers run as
// they did before.
func (m *Manager) spawnHelper(plan adapters.Plan, logPath string) (*exec.Cmd, *helperOutput, *procExit, error) {
	logFile, out, err := openHelperOutput(logPath)
	if err != nil {
		return nil, nil, nil, err
	}
	// The tool holds its own copy of the descriptor.
	defer logFile.Close()
	newCmd := func() *exec.Cmd {
		cmd := exec.Command(plan.Argv[0], plan.Argv[1:]...)
		if len(plan.Env) > 0 {
			cmd.Env = append(os.Environ(), plan.Env...)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd
	}
	cmd := newCmd()
	if fd, ok := m.cgroup.fd(); ok {
		setCgroupFD(cmd.SysProcAttr, fd)
		cgErr := startCmd(cmd)
		if cgErr == nil {
			return cmd, out, watchExit(cmd), nil
		}
		// Either the cgroup or the tool is the problem. A plain start tells
		// which: when it works, the cgroup was.
		cmd = newCmd()
		if err := startCmd(cmd); err != nil {
			return nil, nil, nil, err
		}
		m.cgroup.disable(fmt.Errorf("start %s in the cgroup: %w", plan.Argv[0], cgErr))
		return cmd, out, watchExit(cmd), nil
	}
	if err := startCmd(cmd); err != nil {
		return nil, nil, nil, err
	}
	return cmd, out, watchExit(cmd), nil
}

// startCmd starts a mount tool. Tests replace it to see which cgroup a tool
// would start in.
var startCmd = func(cmd *exec.Cmd) error { return cmd.Start() }

// mountWaitError wraps the readiness-wait error with how the tool exited, when
// it has, and its captured output, so a mount that never became ready is
// actionable instead of a bare timeout. The wait error is wrapped with %w so
// callers matching on "timed out waiting for mount" still match a timeout.
//
// The exit status is reliable because procExit reaps the tool: an exited tool
// is reported as exited, never mistaken for a live one. Call it before killing
// the tool, so the status is the tool's own and not our SIGTERM.
func mountWaitError(waitErr error, exit *procExit, out *helperOutput) error {
	if status, exited := exit.status(); exited {
		if errors.Is(waitErr, errMountToolExited) {
			waitErr = fmt.Errorf("%w: %s", waitErr, status)
		} else {
			waitErr = fmt.Errorf("%w (mount tool exited: %s)", waitErr, status)
		}
	}
	if tail := out.String(); tail != "" {
		return fmt.Errorf("%w (mount tool output: %s)", waitErr, tail)
	}
	return fmt.Errorf("%w (mount tool produced no output)", waitErr)
}
