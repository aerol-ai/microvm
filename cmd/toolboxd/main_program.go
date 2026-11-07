package main

import (
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The sandbox's main program is the container command toolboxd starts (the
// image's entrypoint and cmd, or the create request's container_command).
// toolboxd is PID 1 and keeps serving after it ends, so the sandbox does not
// stop and nothing outside the sandbox would know. /health shows its state
// so sandboxd's lifecycle sweep can act on the end
// (lifecycle.destroyAfterExitFor; plans/agent-sandbox-feature-parity.md L5,
// owner row P2) and record status_reason program_exited with the exit code.
const (
	mainProgramNone    = "none"    // no container command
	mainProgramRunning = "running" // started, not reaped yet
	mainProgramExited  = "exited"  // ended with an exit code
	mainProgramKilled  = "killed"  // ended by a signal
)

// mainProgramState is the main program's lifecycle. Its lock is also what
// makes a fast exit safe: startUserCommand holds it from fork until the pid
// is recorded, and the reaper takes it before deciding a reaped pid is the
// main program, so a program that exits before its pid is published is still
// seen as the main program instead of an orphan.
type mainProgramState struct {
	mu        sync.Mutex
	state     string
	pid       int
	exitCode  int
	signal    string
	startedAt time.Time
	endedAt   time.Time
}

var mainProgram = &mainProgramState{state: mainProgramNone}

// mainProgramClock is a test seam.
var mainProgramClock = func() time.Time { return time.Now().UTC() }

// lockForStart is held by startUserCommand across cmd.Start; started or
// failedToStart releases it.
func (m *mainProgramState) lockForStart() { m.mu.Lock() }

func (m *mainProgramState) started(pid int) {
	defer m.mu.Unlock()
	m.state, m.pid, m.exitCode, m.signal = mainProgramRunning, pid, 0, ""
	m.startedAt, m.endedAt = mainProgramClock(), time.Time{}
}

// failedToStart records a command that never ran as ended with 127, the
// shell's "command not found": for destroyAfterExitFor a program that could
// not start has finished as surely as one that crashed.
func (m *mainProgramState) failedToStart() {
	defer m.mu.Unlock()
	now := mainProgramClock()
	m.state, m.pid, m.exitCode, m.signal = mainProgramExited, 0, 127, ""
	m.startedAt, m.endedAt = now, now
}

// noteExit records the end of pid if it is the running main program, and
// reports whether it was.
func (m *mainProgramState) noteExit(pid int, status syscall.WaitStatus) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != mainProgramRunning || pid != m.pid || pid <= 0 {
		return false
	}
	m.endedAt = mainProgramClock()
	switch {
	case status.Signaled():
		// 128+n, as a shell reports a command killed by signal n.
		m.state, m.signal = mainProgramKilled, unix.SignalName(status.Signal())
		m.exitCode = 128 + int(status.Signal())
	default:
		m.state, m.exitCode = mainProgramExited, status.ExitStatus()
	}
	return true
}

// snapshot is the main_program object on /health. exit_code, signal and
// ended_at appear only once the program has ended.
func (m *mainProgramState) snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{"state": m.state}
	if !m.startedAt.IsZero() {
		out["started_at"] = m.startedAt.Format(time.RFC3339Nano)
	}
	if m.state == mainProgramExited || m.state == mainProgramKilled {
		out["exit_code"] = m.exitCode
		out["ended_at"] = m.endedAt.Format(time.RFC3339Nano)
		if m.signal != "" {
			out["signal"] = m.signal
		}
	}
	return out
}
