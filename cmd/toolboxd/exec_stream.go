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
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// streamFramePrefixStdout / streamFramePrefixStderr are the first byte of
// every server→client binary frame. Single-byte prefix avoids a JSON envelope
// on the hot path (large stdout dumps, video streams, etc.).
const (
	streamFramePrefixStdout byte = 0x01
	streamFramePrefixStderr byte = 0x02
)

var execStreamUpgrader = websocket.Upgrader{
	// Auth happens in the HTTP handler before upgrade. Once upgraded the
	// connection is private to the authenticated caller, so we don't need
	// origin checks (also avoids breaking SDK / CLI clients that don't set
	// Origin).
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	// Echo `sandbox.bearer` if the client offered it. The pattern lets
	// browsers smuggle the bearer token through Sec-WebSocket-Protocol since
	// they can't set Authorization on a WebSocket constructor.
	Subprotocols: []string{"sandbox.bearer"},
}

type execStreamStartMsg struct {
	Command string            `json:"command"`
	Workdir string            `json:"workdir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	TTY     bool              `json:"tty,omitempty"`
	Cols    int               `json:"cols,omitempty"`
	Rows    int               `json:"rows,omitempty"`
}

type execStreamControlIn struct {
	Type   string `json:"type"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Signal string `json:"signal,omitempty"`
}

type execStreamControlOut struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Message string `json:"message,omitempty"`
}

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
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	var start execStreamStartMsg
	if err := conn.ReadJSON(&start); err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "invalid start message"})
		return
	}
	if start.Command == "" {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "command is required"})
		return
	}
	// Future reads: no deadline; the read pump uses pong handling for liveness.
	_ = conn.SetReadDeadline(time.Time{})

	cmd := exec.Command("/bin/sh", "-c", start.Command)
	if start.Workdir != "" {
		cmd.Dir = start.Workdir
	}
	cmd.Env = mergeEnvForExec(start.Env)

	// New process group so client-initiated signals can target the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: start.TTY, Setpgid: !start.TTY}

	if start.TTY {
		s.runWithPTY(conn, cmd, &start)
	} else {
		s.runWithPipes(conn, cmd)
	}
}

func (s *server) runWithPTY(conn *websocket.Conn, cmd *exec.Cmd, start *execStreamStartMsg) {
	cols, rows := uint16(start.Cols), uint16(start.Rows)
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "start pty: " + err.Error()})
		return
	}
	defer ptmx.Close()

	done := make(chan struct{})

	// Goroutine: client → PTY (stdin and control messages).
	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				_ = ptmx.Close() // unblock the read pump
				return
			}
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

	exitCode, exitSignal := waitForCommand(cmd)
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

	if err := cmd.Start(); err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: "start: " + err.Error()})
		return
	}

	var writeMu sync.Mutex

	// Client → stdin (and control messages).
	go func() {
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				_ = stdinPipe.Close()
				return
			}
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

	exitCode, exitSignal := waitForCommand(cmd)
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
		if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(ctrl.Cols), Rows: uint16(ctrl.Rows)}); err != nil {
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

func waitForCommand(cmd *exec.Cmd) (int, string) {
	return interpretWaitResult(cmd.Wait())
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
	// toolboxd runs as PID 1 in the container. Orphaned grandchildren (e.g.
	// npm lifecycle scripts) are reparented to it and exit with SIGCHLD. In
	// rare races this can cause the kernel to return ECHILD for our direct
	// child before cmd.Wait() gets there. Since we only call this after all
	// pipe I/O has completed (process definitely exited), treat ECHILD as 0.
	if errors.Is(err, syscall.ECHILD) {
		return 0, ""
	}
	return -1, err.Error()
}

func mergeEnvForExec(extra map[string]string) []string {
	// Inherit container env so PATH, HOME, etc. are present.
	base := append([]string(nil), os.Environ()...)
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
