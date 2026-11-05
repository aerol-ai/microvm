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
)

// execDrainersAtCap reports whether new background jobs lose their output.
func execDrainersAtCap() bool { return execDrainers.Load() >= maxExecDrainers }

// bufferedExecOutput is what one buffered exec produced.
type bufferedExecOutput struct {
	stdout  string
	stderr  string
	waitErr error
}

// execCollector gathers output until the reply is sent, then discards it.
type execCollector struct {
	mu        sync.Mutex
	stdout    []byte
	stderr    []byte
	responded bool
}

func (c *execCollector) read(f *os.File, dst *[]byte, wg *sync.WaitGroup) {
	defer wg.Done()
	defer f.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			c.mu.Lock()
			if !c.responded {
				*dst = append(*dst, buf[:n]...)
			}
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// finish freezes the reply: later output is read and dropped.
func (c *execCollector) finish() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responded = true
	return string(c.stdout), string(c.stderr)
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

	collector := &execCollector{}
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
	stdout, stderr := collector.finish()

	select {
	case <-allClosed:
	default:
		detachExecDrainers(logger, allClosed, stdoutR, stderrR)
	}
	return bufferedExecOutput{stdout: stdout, stderr: stderr, waitErr: waitErr}, nil
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
