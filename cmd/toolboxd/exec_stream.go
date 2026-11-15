package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/gorilla/websocket"
)

// The exec stream's wire format lives in internal/toolboxwire, shared with
// the WASM toolhost so both servers speak the same protocol.
const (
	streamFramePrefixStdout = toolboxwire.FramePrefixStdout
	streamFramePrefixStderr = toolboxwire.FramePrefixStderr
)

type (
	execStreamStartMsg   = toolboxwire.ExecStreamStart
	execStreamControlIn  = toolboxwire.ExecStreamControlIn
	execStreamControlOut = toolboxwire.ExecStreamControlOut
)

// execStreamLiveness is toolboxwire.Liveness with toolboxd's test override
// (server.execLiveness); see toolboxwire.Liveness for why streams ping.
type execStreamLiveness struct {
	pingInterval  time.Duration
	pongWait      time.Duration
	pingWriteWait time.Duration
}

var defaultExecStreamLiveness = execStreamLiveness{
	pingInterval:  toolboxwire.DefaultLiveness.PingInterval,
	pongWait:      toolboxwire.DefaultLiveness.PongWait,
	pingWriteWait: toolboxwire.DefaultLiveness.PingWriteWait,
}

func (s *server) execStreamLiveness() execStreamLiveness {
	if s.execLiveness.pingInterval <= 0 || s.execLiveness.pongWait <= 0 {
		return defaultExecStreamLiveness
	}
	cfg := s.execLiveness
	if cfg.pingWriteWait <= 0 {
		cfg.pingWriteWait = defaultExecStreamLiveness.pingWriteWait
	}
	return cfg
}

// execStreamUpgrader echoes sandbox.bearer and skips origin checks; see
// toolboxwire.NewExecStreamUpgrader. Argv (E2) is handled in exec_argv.go.
var execStreamUpgrader = toolboxwire.NewExecStreamUpgrader()

func (s *server) handleExecStream(w http.ResponseWriter, r *http.Request) {
	conn, err := execStreamUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade itself writes the HTTP error response; log and return.
		s.logger.Warn("exec stream upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// First message defines the process to run. Bound the wait so a stalled
	// client can't hold a goroutine open indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(toolboxwire.StartTimeout)); err != nil {
		return
	}
	var start execStreamStartMsg
	if err := conn.ReadJSON(&start); err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "invalid start message"})
		return
	}
	if msg := validateArgvRequest(start.Command != "", start.Argv); msg != "" {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: msg})
		return
	}

	env := mergeEnvForExec(start.Env)
	// Without this an image with no shell fails at start with "fork/exec
	// /bin/sh: no such file or directory", which reads as a toolboxd fault.
	shell, err := detectShell()
	var cmd *exec.Cmd
	switch {
	case len(start.Argv) == 0:
		if err != nil {
			writeStreamControl(conn, execStreamControlOut{Type: "error", Message: err.Error()})
			return
		}
		cmd = exec.Command(shell, "-c", start.Command)
	case err == nil:
		args := shellArgv(shell, false, start.Argv)
		cmd = exec.Command(args[0], args[1:]...)
	default:
		path, code, stderr := resolveArgvProgram(start.Argv[0], argvSearchPath(env, start.Env), start.Workdir)
		if code != 0 {
			// What a shell would do: a line of error output, then the exit.
			// A terminal has one output stream, so it goes there.
			prefix := streamFramePrefixStderr
			if start.TTY {
				prefix = streamFramePrefixStdout
			}
			_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{prefix}, stderr...))
			writeStreamControl(conn, execStreamControlOut{Type: "exit", Code: code})
			return
		}
		cmd = exec.Command(path, start.Argv[1:]...)
		cmd.Args[0] = start.Argv[0]
	}
	if start.Workdir != "" {
		cmd.Dir = start.Workdir
	}
	cmd.Env = env

	// New process group so client-initiated signals can target the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: start.TTY, Setpgid: !start.TTY}

	if start.TTY {
		s.runWithPTY(conn, cmd, &start)
	} else {
		s.runWithPipes(conn, cmd)
	}
}

// armExecStreamLiveness starts the keepalive pinger and the pong-extended read
// deadline. extend must be called after every client message (it runs on the
// reader goroutine, as does the pong handler). stop ends the pinger.
func armExecStreamLiveness(conn *websocket.Conn, cfg execStreamLiveness) (extend func(), stop func()) {
	return toolboxwire.ArmLiveness(conn, toolboxwire.Liveness{
		PingInterval:  cfg.pingInterval,
		PongWait:      cfg.pongWait,
		PingWriteWait: cfg.pingWriteWait,
	})
}

// execStreamKiller kills the command's process group when the client side of
// the stream ends before the exit message is sent (CEO review CF3): a client
// that dies, a proxy that drops the socket, or a missed keepalive. Before
// this, the command kept running with nobody to read its output or stop it,
// and only killing the sandbox ended it. Sessions (/process/session) are the
// way to run work that outlives a connection; they are unaffected.
type execStreamKiller struct {
	pgid   int
	exited atomic.Bool
}

func newExecStreamKiller(cmd *exec.Cmd) *execStreamKiller {
	k := &execStreamKiller{}
	if cmd != nil && cmd.Process != nil {
		// Setpgid (pipes) and Setsid (PTY) both make the child its own
		// process-group leader, so the group ID is its PID.
		k.pgid = cmd.Process.Pid
	}
	return k
}

// markExited records that the command was reaped and its exit is about to be
// reported, so the reader's error on the normal close is not a drop.
func (k *execStreamKiller) markExited() { k.exited.Store(true) }

// streamDropped kills the whole process group unless the command already
// exited. Negative PID targets the group so children die too.
func (k *execStreamKiller) streamDropped() {
	if k.exited.Load() || k.pgid <= 0 {
		return
	}
	_ = syscall.Kill(-k.pgid, syscall.SIGKILL)
}

func (s *server) runWithPTY(conn *websocket.Conn, cmd *exec.Cmd, start *execStreamStartMsg) {
	cols, rows := uint16(start.Cols), uint16(start.Rows)
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	var ptmx *os.File
	child, err := execChildren.start(cmd, func() error {
		var startErr error
		ptmx, startErr = sessions.StartPTY(cmd, cols, rows)
		return startErr
	})
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "start pty: " + err.Error()})
		return
	}
	defer ptmx.Close()

	done := make(chan struct{})
	killer := newExecStreamKiller(cmd)
	extend, stopLiveness := armExecStreamLiveness(conn, s.execStreamLiveness())
	defer stopLiveness()

	// Goroutine: client → PTY (stdin and control messages).
	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				killer.streamDropped()
				_ = ptmx.Close() // unblock the read pump
				return
			}
			extend()
			switch msgType {
			case websocket.BinaryMessage:
				if _, err := ptmx.Write(data); err != nil {
					return
				}
			case websocket.TextMessage:
				var ctrl execStreamControlIn
				if err := json.Unmarshal(data, &ctrl); err != nil {
					continue
				}
				handlePTYControl(s.logger, ctrl, ptmx, cmd)
			}
		}
	}()

	// Main: PTY → client.
	if err := pumpReader(conn, ptmx, streamFramePrefixStdout); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Debug("pty read ended", "error", err)
	}

	waitErr := child.wait()
	killer.markExited()
	exitCode, exitSignal := interpretWaitResult(waitErr)
	close(done)
	writeStreamControl(conn, execStreamControlOut{Type: "exit", Code: exitCode, Signal: exitSignal})
}

func (s *server) runWithPipes(conn *websocket.Conn, cmd *exec.Cmd) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "stdin pipe: " + err.Error()})
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "stdout pipe: " + err.Error()})
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "stderr pipe: " + err.Error()})
		return
	}

	child, err := startTracked(cmd)
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "start: " + err.Error()})
		return
	}

	var writeMu sync.Mutex
	killer := newExecStreamKiller(cmd)
	extend, stopLiveness := armExecStreamLiveness(conn, s.execStreamLiveness())
	defer stopLiveness()

	// Client → stdin (and control messages).
	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				killer.streamDropped()
				_ = stdinPipe.Close()
				return
			}
			extend()
			switch msgType {
			case websocket.BinaryMessage:
				if _, err := stdinPipe.Write(data); err != nil {
					return
				}
			case websocket.TextMessage:
				var ctrl execStreamControlIn
				if err := json.Unmarshal(data, &ctrl); err != nil {
					continue
				}
				switch ctrl.Type {
				case "signal":
					sendSignalToCmd(cmd, ctrl.Signal)
				case "close":
					_ = stdinPipe.Close()
				}
			}
		}
	}()

	// stdout → client.
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		_ = pumpReaderLocked(conn, stdoutPipe, streamFramePrefixStdout, &writeMu)
	}()

	// stderr → client.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_ = pumpReaderLocked(conn, stderrPipe, streamFramePrefixStderr, &writeMu)
	}()

	<-stdoutDone
	<-stderrDone

	waitErr := child.wait()
	killer.markExited()
	exitCode, exitSignal := interpretWaitResult(waitErr)
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = conn.WriteJSON(execStreamControlOut{Type: "exit", Code: exitCode, Signal: exitSignal})
}

func handlePTYControl(logger *slog.Logger, ctrl execStreamControlIn, ptmx *os.File, cmd *exec.Cmd) {
	switch ctrl.Type {
	case "resize":
		if ctrl.Cols <= 0 || ctrl.Rows <= 0 {
			return
		}
		if err := sessions.SetWinsize(ptmx, uint16(ctrl.Cols), uint16(ctrl.Rows)); err != nil {
			logger.Debug("pty resize failed", "error", err)
		}
	case "signal":
		sendSignalToCmd(cmd, ctrl.Signal)
	case "close":
		// no-op; the client will close the WS shortly after.
	}
}

func sendSignalToCmd(cmd *exec.Cmd, name string) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	sig := mapStreamSignal(name)
	if sig == nil {
		return
	}
	// Negative PID targets the process group so children also receive.
	_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))
}

// pumpReader copies from r into the websocket as binary frames, prefixed
// with `prefix`. Locks shared with stderr writes via the mutex variant.
func pumpReader(conn *websocket.Conn, r io.Reader, prefix byte) error {
	buf := make([]byte, 32*1024)
	out := make([]byte, 1+len(buf))
	out[0] = prefix
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out[:1], buf[:n]...)
			if werr := conn.WriteMessage(websocket.BinaryMessage, out); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func pumpReaderLocked(conn *websocket.Conn, r io.Reader, prefix byte, mu *sync.Mutex) error {
	buf := make([]byte, 32*1024)
	frame := make([]byte, 0, 1+cap(buf))
	for {
		n, err := r.Read(buf)
		if n > 0 {
			frame = append(frame[:0], prefix)
			frame = append(frame, buf[:n]...)
			mu.Lock()
			werr := conn.WriteMessage(websocket.BinaryMessage, frame)
			mu.Unlock()
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func writeStreamControl(conn *websocket.Conn, msg execStreamControlOut) {
	_ = conn.WriteJSON(msg)
}

func interpretWaitResult(err error) (int, string) {
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
	var re *reapedExit
	if errors.As(err, &re) {
		if re.status.Signaled() {
			return -1, re.status.Signal().String()
		}
		return re.status.ExitStatus(), ""
	}
	// An exec child started through execChildren never loses its status to
	// the reaper. So ECHILD here means the status is really gone. This path
	// used to report it as exit 0, which made a failed command look like a
	// success (UC-84). Report it as unknown instead.
	return -1, err.Error()
}

func mergeEnvForExec(extra map[string]string) []string {
	// Inherit the container env (PATH, HOME, ...) and the sandbox env; the
	// request's env goes last so it wins.
	base := childEnviron()
	for k, v := range extra {
		base = append(base, fmt.Sprintf("%s=%s", k, v))
	}
	return base
}

func mapStreamSignal(name string) any {
	switch name {
	case "INT", "SIGINT":
		return syscall.SIGINT
	case "TERM", "SIGTERM":
		return syscall.SIGTERM
	case "KILL", "SIGKILL":
		return syscall.SIGKILL
	case "HUP", "SIGHUP":
		return syscall.SIGHUP
	case "QUIT", "SIGQUIT":
		return syscall.SIGQUIT
	}
	return nil
}
