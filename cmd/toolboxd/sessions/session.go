// Package sessions implements long-running command sessions inside a sandbox
// container: PTY or pipes, in-memory replay buffer, fan-out to multiple
// attached clients, and asciinema recording. Designed to live in toolboxd
// (PID 1 of the container) and be reachable via the toolbox HTTP/WS API.
package sessions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/creack/pty"
)

// Stream identifies which output stream a chunk of bytes belongs to. Pipe
// mode uses both; PTY mode only uses Stdout.
type Stream uint8

const (
	StreamStdout Stream = 1
	StreamStderr Stream = 2
)

// Frame is a unit of session output observed by an attached client.
type Frame struct {
	Stream Stream
	Data   []byte
}

// Session is one long-running process plus the fan-out hub that distributes
// its output to attached clients. Methods are safe for concurrent use.
type Session struct {
	id        string
	name      string
	argv      []string
	workdir   string
	pty       bool
	createdAt time.Time
	startedAt time.Time

	cmd   *exec.Cmd
	ptmx  *os.File       // nil for pipe mode
	stdin io.WriteCloser // nil for PTY mode
	cols  int
	rows  int

	buf      *ring
	recorder *recorder
	pumpWG   sync.WaitGroup

	mu          sync.Mutex
	subscribers map[uint64]chan Frame
	nextSubID   uint64
	bytes       atomic.Int64
	attached    atomic.Int32

	exited     atomic.Bool
	exitedAt   time.Time
	exitCode   int
	exitSignal string
	failed     bool
	doneCh     chan struct{}
}

// Snapshot returns the metadata view of the session.
func (s *Session) Snapshot() models.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := models.SessionStatusRunning
	if s.exited.Load() {
		switch {
		case s.failed:
			status = models.SessionStatusFailed
		case s.exitSignal != "":
			status = models.SessionStatusKilled
		default:
			status = models.SessionStatusExited
		}
	}
	return models.Session{
		ID:         s.id,
		Name:       s.name,
		Argv:       append([]string{}, s.argv...),
		WorkDir:    s.workdir,
		PTY:        s.pty,
		Status:     status,
		ExitCode:   s.exitCode,
		ExitSignal: s.exitSignal,
		CreatedAt:  s.createdAt,
		StartedAt:  s.startedAt,
		ExitedAt:   s.exitedAt,
		Recording:  s.recorder != nil,
		Bytes:      s.bytes.Load(),
		Attached:   int(s.attached.Load()),
	}
}

// ID returns the session's stable identifier.
func (s *Session) ID() string { return s.id }

// Name returns the human-friendly session name.
func (s *Session) Name() string { return s.name }

// PID returns the OS process identifier for the session, or 0 when the
// session has not started successfully.
func (s *Session) PID() int {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// IsPTY reports whether the session was started in PTY mode.
func (s *Session) IsPTY() bool { return s.pty }

// Done returns a channel that closes when the underlying process exits.
func (s *Session) Done() <-chan struct{} { return s.doneCh }

// RecordingPath returns the absolute path to the session's asciinema cast
// file, or "" if recording is disabled.
func (s *Session) RecordingPath() string { return s.recorder.Path() }

// ExitInfo returns the exit code and signal name (empty if not signaled). If
// the session is still running, returns -1, "".
func (s *Session) ExitInfo() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.exited.Load() {
		return -1, ""
	}
	return s.exitCode, s.exitSignal
}

// Replay returns the current contents of the replay buffer (oldest→newest).
func (s *Session) Replay() []byte {
	s.mu.Lock()
	replay := s.buf.Snapshot()
	s.mu.Unlock()
	return replay
}

// Subscribe registers a new attacher. The returned channel first receives a
// replay frame containing the current buffer contents (merged as stdout), then
// live output frames in order until the session ends or the caller calls the
// cancel function. Channel buffer size is 64; slow consumers drop older
// frames.
func (s *Session) Subscribe() (<-chan Frame, func()) {
	s.mu.Lock()
	replay := s.buf.Snapshot()
	id := s.nextSubID
	ch := make(chan Frame, 64)
	if len(replay) > 0 {
		ch <- Frame{Stream: StreamStdout, Data: replay}
	}
	subscribed := false
	if !s.exited.Load() {
		s.nextSubID++
		if s.subscribers == nil {
			s.subscribers = map[uint64]chan Frame{}
		}
		s.subscribers[id] = ch
		subscribed = true
	} else {
		close(ch)
	}
	s.mu.Unlock()
	if subscribed {
		s.attached.Add(1)
	}

	var once sync.Once
	cancel := func() {
		if !subscribed {
			return
		}
		once.Do(func() {
			s.mu.Lock()
			if existing, ok := s.subscribers[id]; ok {
				delete(s.subscribers, id)
				close(existing)
			}
			s.mu.Unlock()
			s.attached.Add(-1)
		})
	}
	return ch, cancel
}

// Write forwards bytes to the session's stdin (PTY in PTY mode, pipe stdin
// otherwise). Returns an error if the session has exited or stdin is closed.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.exited.Load() {
		s.mu.Unlock()
		return 0, errors.New("session has exited")
	}
	ptmx := s.ptmx
	stdin := s.stdin
	rec := s.recorder
	s.mu.Unlock()
	if ptmx != nil {
		if rec != nil {
			rec.WriteInput(p)
		}
		return ptmx.Write(p)
	}
	if stdin != nil {
		return stdin.Write(p)
	}
	return 0, errors.New("session has no writable stdin")
}

// CloseStdin half-closes stdin so the process sees EOF.
func (s *Session) CloseStdin() error {
	if s.stdin != nil {
		return s.stdin.Close()
	}
	if s.ptmx != nil {
		// PTY half-close isn't well-defined; nothing to do.
		return nil
	}
	return nil
}

// Resize updates the PTY window size. No-op in pipe mode or after exit.
func (s *Session) Resize(cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited.Load() || s.ptmx == nil {
		return nil
	}
	if cols <= 0 || rows <= 0 {
		return errors.New("invalid window size")
	}
	s.cols = cols
	s.rows = rows
	return pty.Setsize(s.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Signal sends a signal to the session's process group. Accepts INT, TERM,
// KILL, HUP, QUIT (with or without SIG prefix).
func (s *Session) Signal(name string) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("session not running")
	}
	sig := mapSignal(name)
	if sig == nil {
		return fmt.Errorf("unsupported signal %q", name)
	}
	// Negative PID targets the whole process group so children also receive.
	return syscall.Kill(-s.cmd.Process.Pid, sig.(syscall.Signal))
}

// fanout publishes a frame to the replay buffer and every attached client.
// Slow subscribers drop frames rather than blocking the producer.
func (s *Session) fanout(stream Stream, data []byte) {
	if len(data) == 0 {
		return
	}
	chunk := append([]byte(nil), data...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytes.Add(int64(len(chunk)))
	_, _ = s.buf.Write(chunk)
	if s.recorder != nil {
		s.recorder.WriteOutput(chunk)
	}

	for _, ch := range s.subscribers {
		select {
		case ch <- Frame{Stream: stream, Data: chunk}:
		default:
			// Drop on backpressure. The replay buffer still has the bytes.
		}
	}
}

// runPump reads from r and fans out frames until r returns EOF or error.
func (s *Session) runPump(r io.Reader, stream Stream) {
	defer s.pumpWG.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.fanout(stream, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// finish records the exit code/signal, closes subscribers, and finalizes
// the recorder.
func (s *Session) finish(code int, signal string, failed bool) {
	s.mu.Lock()
	if s.exited.Load() {
		s.mu.Unlock()
		return
	}
	s.exitCode = code
	s.exitSignal = signal
	s.failed = failed
	s.exitedAt = time.Now().UTC()
	// Publish the terminal state only after all metadata is initialized. Readers
	// that need the metadata take mu, while the atomic remains a cheap guard for
	// write/shutdown paths that only need to know whether the process exited.
	s.exited.Store(true)
	for id, ch := range s.subscribers {
		close(ch)
		delete(s.subscribers, id)
	}
	s.mu.Unlock()

	if s.recorder != nil {
		_ = s.recorder.Close()
	}
	s.mu.Lock()
	ptmx := s.ptmx
	s.ptmx = nil
	s.mu.Unlock()
	if ptmx != nil {
		_ = ptmx.Close()
	}
	close(s.doneCh)
}

// waitAndFinish waits for the process to exit and finalizes the session.
// Manager wires output pumps before calling this.
func (s *Session) waitAndFinish() {
	s.pumpWG.Wait()
	code, sig := waitProcess(s.cmd)
	s.finish(code, sig, false)
}

// shutdown forcefully terminates the session if it's still running. Used
// when the container is going away.
func (s *Session) shutdown() {
	if s.exited.Load() {
		return
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	}
}

// waitProcess returns (exit_code, signal_name). signal_name is empty if the
// process exited normally.
func waitProcess(cmd *exec.Cmd) (int, string) {
	return interpretWaitProcessResult(cmd.Wait())
}

func interpretWaitProcessResult(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return -1, status.Signal().String()
			}
			return status.ExitStatus(), ""
		}
		return ee.ExitCode(), ""
	}
	if errors.Is(err, syscall.ECHILD) {
		return 0, ""
	}
	return -1, err.Error()
}

func mapSignal(name string) any {
	upper := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(name), "SIG"))
	switch upper {
	case "INT":
		return syscall.SIGINT
	case "TERM":
		return syscall.SIGTERM
	case "KILL":
		return syscall.SIGKILL
	case "HUP":
		return syscall.SIGHUP
	case "QUIT":
		return syscall.SIGQUIT
	}
	return nil
}

// recordingPathForID returns the path on the recordings directory for a
// given session ID. Sessions overwrite the same file each session restart;
// ID is unique per session so collisions don't happen in practice.
func recordingPathForID(dir, sandboxID, sessionID string) string {
	return filepath.Join(dir, sandboxID, sessionID+".cast")
}
