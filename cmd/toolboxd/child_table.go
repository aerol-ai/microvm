package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
)

// toolboxd is PID 1 in the container, so its SIGCHLD reaper must call
// wait4(-1) to collect reparented orphans. wait4(-1) cannot exclude pids,
// so it also reaps toolboxd's OWN exec children whenever it wins the race
// against exec.Cmd.Wait. cmd.Wait then sees ECHILD and the child's exit
// status is gone. A fast-failing command (`sh -c 'echo x > /ro/file'`) was
// reported as exit 0, and UC-84 saw a write to a read-only volume
// "succeed".
//
// childTable closes that race without making the reaper skip anything.
// Every exec child is started under mu and registered by pid before mu is
// released. The reaper holds mu across its wait4, so it can never reap a
// child that is running but not yet registered. When it does reap a
// registered pid, it hands the status to that child's waiter instead of
// dropping it.
type childTable struct {
	mu    sync.Mutex
	byPID map[int]chan syscall.WaitStatus
}

var execChildren = &childTable{byPID: map[int]chan syscall.WaitStatus{}}

// trackedChild is one registered exec child. wait must be called exactly
// once, in place of cmd.Wait.
type trackedChild struct {
	table  *childTable
	cmd    *exec.Cmd
	pid    int
	status chan syscall.WaitStatus
}

// start runs startFn (cmd.Start, or a pty start that calls it) under mu and
// registers the resulting child.
func (t *childTable) start(cmd *exec.Cmd, startFn func() error) (*trackedChild, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := startFn(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	ch := make(chan syscall.WaitStatus, 1)
	t.byPID[pid] = ch
	return &trackedChild{table: t, cmd: cmd, pid: pid, status: ch}, nil
}

// reap collects one exited child (pid -1 = any) without blocking. If the
// child is registered, its status goes to that child's waiter.
// tracked reports whether that happened. ok is false when nothing had
// exited.
func (t *childTable) reap(pid int) (reaped int, status syscall.WaitStatus, tracked, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	reaped, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
	if reaped <= 0 || err != nil {
		return 0, 0, false, false
	}
	if ch, found := t.byPID[reaped]; found {
		ch <- status // cap 1, and one send per registration: never blocks
		delete(t.byPID, reaped)
		return reaped, status, true, true
	}
	return reaped, status, false, true
}

// wait replaces cmd.Wait. It still calls cmd.Wait, which closes the pipes and
// stops the copy goroutines. If the reaper took the status first, wait
// returns that status instead of ECHILD.
func (c *trackedChild) wait() error {
	err := c.cmd.Wait()
	c.table.mu.Lock()
	// Only drop our own entry: once cmd.Wait reaped the pid, the kernel may
	// hand it to a new child that start has already registered.
	if c.table.byPID[c.pid] == c.status {
		delete(c.table.byPID, c.pid)
	}
	c.table.mu.Unlock()
	if !errors.Is(err, syscall.ECHILD) {
		return err
	}
	// ECHILD means the reaper's wait4 got the child. The reaper sends the
	// status while it still holds mu, and we locked mu after that, so the
	// status is already in the buffered channel.
	select {
	case st := <-c.status:
		return reapedStatusError(st)
	default:
		return err
	}
}

// reapedExit carries a status the reaper collected. exec.ExitError cannot be
// built from a WaitStatus, so interpretWaitResult understands this type too.
type reapedExit struct {
	status syscall.WaitStatus
}

func (e *reapedExit) Error() string {
	if e.status.Signaled() {
		return "signal: " + e.status.Signal().String()
	}
	return fmt.Sprintf("exit status %d", e.status.ExitStatus())
}

func reapedStatusError(st syscall.WaitStatus) error {
	if st.Exited() && st.ExitStatus() == 0 {
		return nil
	}
	return &reapedExit{status: st}
}

// startTracked is cmd.Start for an exec child.
func startTracked(cmd *exec.Cmd) (*trackedChild, error) {
	return execChildren.start(cmd, cmd.Start)
}

// startSessionProcess starts a session's command as a tracked child, so the
// reaper hands a background command's or a shell's exit status to its
// session. Before sessions went through here, every pipe session lost the
// race (it waits for its output pumps before cmd.Wait) and `aerolvm logs
// --follow` reported exit 0 for a command that exited 4.
func startSessionProcess(cmd *exec.Cmd, start func() error) (func() (int, string), error) {
	child, err := execChildren.start(cmd, start)
	if err != nil {
		return nil, err
	}
	return func() (int, string) { return interpretWaitResult(child.wait()) }, nil
}

// trackedCombinedOutput is cmd.CombinedOutput for an exec child.
func trackedCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	if cmd.Stdout != nil || cmd.Stderr != nil {
		return nil, errors.New("exec: Stdout or Stderr already set")
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	child, err := startTracked(cmd)
	if err != nil {
		return nil, err
	}
	err = child.wait()
	return buf.Bytes(), err
}
