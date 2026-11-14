package main

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

// Buffered exec (POST /process/execute) used to read stdout and stderr to EOF
// before it waited for the command. A command that started a background job
// (`server &`) left that job holding the pipes, so the call hung until the job
// ended, and on a timeout only the shell was killed, so it hung forever
// (plans/agent-sandbox-feature-parity.md, B2). Every caller shares this path:
// AerolVM exec, Daytona executeCommand and Runloop one-shot commands (ER2).
//
//	start ─► shell exits ─► output still held? ─no──────────────────────► reply
//	                              │yes
//	                              ▼
//	                        grace (execOutputGrace) ─► reply ─► drainers < max? ─yes─► detach drainer ─► EOF
//	                                                                    │no
//	                                                                    └─► close the output (the job may stop on its next write)
//	timeout ─► kill the whole process group ─► reply(timed_out) ─► same path
//
// toolboxd creates the pipes itself and hands the child the write ends as
// *os.File, so cmd.Wait (inside trackedChild.wait) never closes toolboxd's
// read ends; the background job keeps a working stdout after the reply.

var (
	// execOutputGrace is how long exec waits, after the command itself has
	// exited, for output a background job still writes. Output already in
	// the pipes is read at once; the grace only applies while a job holds
	// them open. A variable for tests.
	execOutputGrace = time.Second
	// maxExecDrainers bounds the readers left soaking up background jobs'
	// output. Each holds a goroutine and two file descriptors; past the
	// limit a new job's output is closed instead, so toolboxd can never run
	// out of descriptors because of background jobs (ER3). A variable for
	// tests.
	maxExecDrainers int64 = 256
	// execDrainers counts detached readers in this process.
	execDrainers atomic.Int64
	// execOutputCeiling is the most toolboxd keeps of one stream of one
	// buffered exec, whatever the request asks: the last line under the
	// caller's cap and the operator's, which sandboxd writes into the
	// request (E1, ER5) and an older sandboxd does not. Before it, toolboxd
	// held all output in memory and then encoded it again as JSON, so one
	// command printing a few GB could OOM-kill the agent, and with it every
	// exec, file call and terminal of the sandbox. 64 MiB equals the JSON
	// reply the Daytona and Runloop facades already refuse to decode past
	// (maxToolboxJSONBytes, maxToolboxResponse), so no facade loses output
	// it could read today. A variable for tests.
	execOutputCeiling int64 = 64 << 20
)

// execOutputLimits are the per-stream byte caps of one buffered exec. Zero
// means the ceiling alone.
type execOutputLimits struct {
	stdout, stderr int64
}

// effectiveLimit clamps a requested cap to the ceiling.
func effectiveLimit(requested int64) int64 {
	if requested > 0 && requested < execOutputCeiling {
		return requested
	}
	return execOutputCeiling
}

// execDrainersAtCap reports whether new background jobs lose their output.
func execDrainersAtCap() bool { return execDrainers.Load() >= maxExecDrainers }

// bufferedExecOutput is what one buffered exec produced.
type bufferedExecOutput struct {
	stdout          string
	stderr          string
	stdoutTruncated bool
	stderrTruncated bool
	waitErr         error
}

// capturedStream keeps the first limit bytes of one output stream.
type capturedStream struct {
	data      []byte
	limit     int64
	truncated bool
}

// add keeps what fits under the limit. The reader goes on reading past it
// and drops the rest, so the command never blocks on a full pipe.
func (s *capturedStream) add(p []byte) {
	room := s.limit - int64(len(s.data))
	if int64(len(p)) <= room {
		s.data = append(s.data, p...)
		return
	}
	if room > 0 {
		s.data = append(s.data, p[:room]...)
	}
	s.truncated = true
}

// text is the kept output. A cut can split a multi-byte UTF-8 character,
// which JSON would turn into U+FFFD and so grow past the cap; the partial
// character is dropped instead. Untruncated output is returned as the
// command wrote it.
func (s *capturedStream) text() string {
	if !s.truncated {
		return string(s.data)
	}
	return string(trimPartialRune(s.data))
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of b. Bytes
// that are not UTF-8 at all are left alone: the output was binary, not cut
// text.
func trimPartialRune(b []byte) []byte {
	for back := 1; back <= utf8.UTFMax && back <= len(b); back++ {
		c := b[len(b)-back]
		if c < utf8.RuneSelf {
			return b // ASCII: whatever follows is a whole or invalid sequence
		}
		if utf8.RuneStart(c) {
			if !utf8.FullRune(b[len(b)-back:]) {
				return b[:len(b)-back]
			}
			return b
		}
	}
	return b
}

// execCollector gathers output until the reply is sent, then discards it.
type execCollector struct {
	mu        sync.Mutex
	stdout    capturedStream
	stderr    capturedStream
	responded bool
}

func (c *execCollector) read(f *os.File, dst *capturedStream, wg *sync.WaitGroup) {
	defer wg.Done()
	defer f.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			c.mu.Lock()
			if !c.responded {
				dst.add(buf[:n])
			}
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// finish freezes the reply: later output is read and dropped, and never
// marks a stream truncated.
func (c *execCollector) finish() bufferedExecOutput {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responded = true
	return bufferedExecOutput{
		stdout:          c.stdout.text(),
		stderr:          c.stderr.text(),
		stdoutTruncated: c.stdout.truncated,
		stderrTruncated: c.stderr.truncated,
	}
}

// prepareProcessGroup puts cmd in its own process group and makes a context
// cancel kill the whole group, not just the shell. exec.CommandContext alone
// kills only the direct child.
func prepareProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

// runBufferedExec starts cmd, which must have no Stdout or Stderr set, and
// returns once the command itself has exited (plus the grace when a
// background job still holds its output).
func runBufferedExec(logger *slog.Logger, cmd *exec.Cmd) (bufferedExecOutput, error) {
	return runBufferedExecLimited(logger, cmd, execOutputLimits{})
}

// runBufferedExecLimited is runBufferedExec keeping at most limits of each
// stream (E1). The caps only bound what is kept; reading, the grace and the
// drainers work exactly as without them.
func runBufferedExecLimited(logger *slog.Logger, cmd *exec.Cmd, limits execOutputLimits) (bufferedExecOutput, error) {
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return bufferedExecOutput{}, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return bufferedExecOutput{}, err
	}
	cmd.Stdout, cmd.Stderr = stdoutW, stderrW

	child, startErr := startTracked(cmd)
	// toolboxd's own copies of the write ends close now, started or not:
	// while toolboxd holds one, the readers never see EOF.
	_ = stdoutW.Close()
	_ = stderrW.Close()
	if startErr != nil {
		_ = stdoutR.Close()
		_ = stderrR.Close()
		return bufferedExecOutput{}, startErr
	}

	collector := &execCollector{
		stdout: capturedStream{limit: effectiveLimit(limits.stdout)},
		stderr: capturedStream{limit: effectiveLimit(limits.stderr)},
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go collector.read(stdoutR, &collector.stdout, &readers)
	go collector.read(stderrR, &collector.stderr, &readers)
	allClosed := make(chan struct{})
	go func() {
		readers.Wait()
		close(allClosed)
	}()

	waitErr := child.wait()

	timer := time.NewTimer(execOutputGrace)
	select {
	case <-allClosed:
	case <-timer.C:
	}
	timer.Stop()
	out := collector.finish()
	out.waitErr = waitErr

	select {
	case <-allClosed:
	default:
		detachExecDrainers(logger, allClosed, stdoutR, stderrR)
	}
	return out, nil
}

// detachExecDrainers leaves the readers running for a background job that
// still holds the output, within the drainer budget. Past it, the read ends
// are closed, which ends the readers; the job gets EPIPE or SIGPIPE on its
// next write, as it would under Go's WaitDelay.
func detachExecDrainers(logger *slog.Logger, allClosed <-chan struct{}, readEnds ...*os.File) {
	if execDrainers.Add(1) > maxExecDrainers {
		execDrainers.Add(-1)
		for _, f := range readEnds {
			_ = f.Close()
		}
		if logger != nil {
			logger.Warn("exec: background job output closed; drainer limit reached", "limit", maxExecDrainers)
		}
		return
	}
	go func() {
		<-allClosed
		execDrainers.Add(-1)
	}()
}
