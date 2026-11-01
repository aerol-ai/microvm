package mounts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// maxCapturedMountBytes caps how much mount-tool output we retain per process.
// Mount tools (mount-s3, rclone, sshfs) print the actionable failure line just
// before they exit, so we keep the TAIL: a 4 KiB window is plenty for a stack
// of credential/region/endpoint errors without letting a chatty --debug run
// balloon memory across many sandboxes.
const maxCapturedMountBytes = 4 << 10

// capturedOutput is a threadsafe io.Writer that retains the last
// maxCapturedMountBytes bytes written to it. It backs cmd.Stdout/cmd.Stderr for
// supervised FUSE mount processes so a mount that never becomes ready (bad
// creds, wrong region, unreachable endpoint) is diagnosable. Before this, the
// FUSE process's stderr was discarded entirely and the only signal was a bare
// "timed out waiting for mount" (cluster-hetero UC-81..84).
type capturedOutput struct {
	mu  sync.Mutex
	buf []byte
}

func (c *capturedOutput) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	if len(c.buf) > maxCapturedMountBytes {
		// Keep the tail; drop the oldest bytes.
		c.buf = c.buf[len(c.buf)-maxCapturedMountBytes:]
	}
	return len(p), nil
}

// String returns the captured output with surrounding whitespace trimmed. Safe
// on a nil receiver so callers don't have to nil-check before logging.
func (c *capturedOutput) String() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimSpace(string(c.buf))
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

// spawnMountProcess starts a supervised FUSE mount tool with its stdout and
// stderr teed into a capped buffer, and starts the one goroutine that reaps it.
// Shared by the initial mount (mountOne) and the supervisor's restart path so
// both surface the tool's output identically. SysProcAttr.Setpgid keeps the
// process in its own group; killMount signals the whole group so FUSE helper
// children die with it.
func spawnMountProcess(plan adapters.Plan) (*exec.Cmd, *capturedOutput, *procExit, error) {
	cmd := exec.Command(plan.Argv[0], plan.Argv[1:]...)
	if len(plan.Env) > 0 {
		cmd.Env = append(os.Environ(), plan.Env...)
	}
	out := &capturedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	return cmd, out, watchExit(cmd), nil
}

// mountWaitError wraps the readiness-wait error with how the tool exited, when
// it has, and its captured output, so a mount that never became ready is
// actionable instead of a bare timeout. The wait error is wrapped with %w so
// callers matching on "timed out waiting for mount" still match a timeout.
//
// The exit status is reliable because procExit reaps the tool: an exited tool
// is reported as exited, never mistaken for a live one. Call it before killing
// the tool, so the status is the tool's own and not our SIGTERM.
func mountWaitError(waitErr error, exit *procExit, out *capturedOutput) error {
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
