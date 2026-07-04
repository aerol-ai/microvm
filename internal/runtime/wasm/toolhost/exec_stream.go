package toolhost

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	streamFramePrefixStdout byte = 0x01
	streamFramePrefixStderr byte = 0x02
)

var execStreamUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	Subprotocols:    []string{"sandbox.bearer"},
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

func (h *Host) handleExecStream(w http.ResponseWriter, r *http.Request) {
	conn, err := execStreamUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Default().Warn("wasm exec stream upgrade failed", "error", err)
		return
	}
	defer conn.Close()

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
	_ = conn.SetReadDeadline(time.Time{})

	workdir := strings.TrimSpace(start.Workdir)
	if workdir == "" {
		workdir = h.workDir
	}

	cmd := exec.Command("/bin/sh", "-c", start.Command)
	cmd.Dir = workdir
	cmd.Env = mergeExecEnv(start.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: start.TTY, Setpgid: !start.TTY}

	if start.TTY {
		h.runExecStreamPTY(conn, cmd, &start)
		return
	}
	h.runExecStreamPipes(conn, cmd)
}

func mergeExecEnv(extra map[string]string) []string {
	if len(extra) == 0 {
		return os.Environ()
	}
	out := append([]string(nil), os.Environ()...)
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

func writeStreamControl(conn *websocket.Conn, msg execStreamControlOut) {
	_ = conn.WriteJSON(msg)
}

func (h *Host) runExecStreamPTY(conn *websocket.Conn, cmd *exec.Cmd, start *execStreamStartMsg) {
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
	defer func() { _ = ptmx.Close() }()

	// Client → PTY in the background; PTY → client on the main goroutine so
	// only one writer touches the websocket (gorilla/websocket is not
	// concurrent-write safe).
	go h.execStreamControlPump(conn, cmd, ptmx)

	_ = pumpExecStreamReader(conn, ptmx, streamFramePrefixStdout)

	exitCode, sig := waitExec(cmd)
	writeStreamControl(conn, execStreamControlOut{Type: "exit", Code: exitCode, Signal: sig})
}

func (h *Host) runExecStreamPipes(conn *websocket.Conn, cmd *exec.Cmd) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: err.Error()})
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: err.Error()})
		return
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		writeStreamControl(conn, execStreamControlOut{Type: "error", Message: err.Error()})
		return
	}

	var writeMu sync.Mutex

	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		_ = pumpExecStreamReaderLocked(conn, stdout, streamFramePrefixStdout, &writeMu)
	}()
	go func() {
		defer close(stderrDone)
		_ = pumpExecStreamReaderLocked(conn, stderr, streamFramePrefixStderr, &writeMu)
	}()
	go h.execStreamStdinPump(conn, stdin)

	<-stdoutDone
	<-stderrDone

	exitCode, sig := waitExec(cmd)
	writeMu.Lock()
	_ = conn.WriteJSON(execStreamControlOut{Type: "exit", Code: exitCode, Signal: sig})
	writeMu.Unlock()
}

func pumpExecStreamReader(conn *websocket.Conn, r io.Reader, prefix byte) error {
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

func pumpExecStreamReaderLocked(conn *websocket.Conn, r io.Reader, prefix byte, mu *sync.Mutex) error {
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

func (h *Host) execStreamControlPump(conn *websocket.Conn, cmd *exec.Cmd, ptmx *os.File) {
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			_ = ptmx.Close() // unblock the PTY read pump
			return
		}
		switch msgType {
		case websocket.BinaryMessage:
			_, _ = ptmx.Write(data)
		case websocket.TextMessage:
			var ctrl execStreamControlIn
			if err := json.Unmarshal(data, &ctrl); err != nil {
				continue
			}
			switch ctrl.Type {
			case "resize":
				_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(ctrl.Cols), Rows: uint16(ctrl.Rows)})
			case "signal":
				signalExec(cmd, ctrl.Signal)
			}
		}
	}
}

func (h *Host) execStreamStdinPump(conn *websocket.Conn, stdin io.WriteCloser) {
	defer func() { _ = stdin.Close() }()
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		switch msgType {
		case websocket.BinaryMessage:
			if _, err := stdin.Write(data); err != nil {
				return
			}
		case websocket.TextMessage:
			var ctrl execStreamControlIn
			if err := json.Unmarshal(data, &ctrl); err != nil {
				continue
			}
			if ctrl.Type == "signal" {
				return
			}
		}
	}
}

func waitExec(cmd *exec.Cmd) (int, string) {
	err := cmd.Wait()
	if err == nil {
		return 0, ""
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), ""
	}
	return 1, err.Error()
}

func signalExec(cmd *exec.Cmd, sig string) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	sig = strings.ToUpper(strings.TrimSpace(sig))
	var s syscall.Signal
	switch sig {
	case "TERM", "SIGTERM":
		s = syscall.SIGTERM
	case "KILL", "SIGKILL":
		s = syscall.SIGKILL
	case "INT", "SIGINT":
		s = syscall.SIGINT
	default:
		return
	}
	_ = cmd.Process.Signal(s)
}
