package worker

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

// A worker tells sandboxd it serves, so a create waits for the worker
// rather than for the next readiness poll (the poll steps are 2, 4, 8 and
// 16 ms, and a start that misses one waits out the next). At each start
// the Supervisor makes a pipe and gives the worker its write end, named by
// ReadyFDEnv; the worker writes one byte right before it accepts its first
// connection, and closes the pipe. sandboxd treats the byte as a hint and
// nothing more:
//
//   - it reads the pipe in Go's poller (a parked goroutine, never a
//     blocked thread), one byte at most, and drops its end once the byte
//     came, the worker exited, or the slot stopped;
//   - the byte only wakes the driver's readiness wait early: the worker is
//     used once a ping answers, as before, and a byte from a worker that
//     does not serve only moves that ping (waitWorker);
//   - a worker that never writes (one started by an older sandboxd and
//     adopted, or a hostile one) is found by the same poll as before;
//   - the pipe is close-on-exec in sandboxd and, once the worker has taken
//     it, in the worker too: only that one child ever holds it across exec.

// ReadyFDEnv names the descriptor a worker writes its ready byte to.
const ReadyFDEnv = "AEROL_WASM_WORKER_READY_FD"

// readyWatchers counts the goroutines waiting on a ready pipe (tests check
// that a slot's end takes its watcher with it).
var readyWatchers atomic.Int64

// attachReadyPipe gives cmd the write end of a new pipe as its last extra
// descriptor, named by ReadyFDEnv, and returns both ends: the caller keeps
// r and closes w once cmd has started (or failed to).
func attachReadyPipe(cmd *exec.Cmd) (r, w *os.File, err error) {
	r, w, err = os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	// The last value of a repeated variable wins (os/exec).
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", ReadyFDEnv, 2+len(cmd.ExtraFiles)))
	return r, w, nil
}

// watchReady closes ready once the worker writes its byte. It returns when
// the byte came, the worker's end closed (it exited) or r was closed (the
// slot ended); r is closed on the way out, so the worker's later writes
// fail rather than fill a pipe nobody reads.
func watchReady(r *os.File, ready chan struct{}) {
	readyWatchers.Add(1)
	defer readyWatchers.Add(-1)
	var b [1]byte
	if n, _ := r.Read(b[:]); n == 1 {
		close(ready)
	}
	_ = r.Close()
}

// takeReadyFD takes the ready pipe sandboxd passed (ReadyFDEnv), before the
// worker drops: nil when none was passed, or when the descriptor is not a
// pipe (a write to anything else would be a write to whatever holds that
// number). It is made close-on-exec, and the variable is dropped, so
// nothing the worker might start holds it.
func takeReadyFD() *os.File {
	raw := strings.TrimSpace(os.Getenv(ReadyFDEnv))
	if raw == "" {
		return nil
	}
	_ = os.Unsetenv(ReadyFDEnv)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 {
		return nil
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFIFO {
		return nil
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "ready pipe")
}

// signalReady writes the ready byte and closes the pipe. A failed write (the
// slot already ended) changes nothing: sandboxd's poll still finds the
// worker.
func signalReady(f *os.File) {
	if f == nil {
		return
	}
	_, _ = f.Write([]byte{1})
	_ = f.Close()
}
