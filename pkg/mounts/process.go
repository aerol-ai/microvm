package mounts

import (
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

// spawnMountProcess starts a supervised FUSE mount tool with its stdout and
// stderr teed into a capped buffer. Shared by the initial mount (mountOne) and
// the supervisor's restart path so both surface the tool's output identically.
// SysProcAttr.Setpgid keeps the process in its own group; killMount signals the
// whole group so FUSE helper children die with it.
func spawnMountProcess(plan adapters.Plan) (*exec.Cmd, *capturedOutput, error) {
	cmd := exec.Command(plan.Argv[0], plan.Argv[1:]...)
	if len(plan.Env) > 0 {
		cmd.Env = append(os.Environ(), plan.Env...)
	}
	out := &capturedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, out, nil
}

// mountWaitError wraps the readiness-probe error with the captured mount-tool
// output so a mount that never became ready is actionable instead of a bare
// timeout. The original probe error is wrapped with %w so callers/tests
// matching on "timed out waiting for mount" still match.
//
// We deliberately do NOT report whether the process is still alive: on the
// failure path nobody has reaped it, so an exited tool lingers as a zombie that
// a signal-0 probe still reports as "running". The captured stderr is the
// reliable signal — a tool that failed fast prints its reason here; a genuinely
// hung tool leaves this empty.
func mountWaitError(probeErr error, out *capturedOutput) error {
	if tail := out.String(); tail != "" {
		return fmt.Errorf("%w (mount tool output: %s)", probeErr, tail)
	}
	return fmt.Errorf("%w (mount tool produced no output before timeout)", probeErr)
}
