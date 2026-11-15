package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/gorilla/websocket"
)

// Streaming exec on WASM (issue #535), wire-identical to toolboxd's
// /process/exec/stream (internal/toolboxwire). The command runs as a guest
// instance inside the wasm engine in the sandbox's worker (Processes); this
// handler, which runs in sandboxd on the host, only moves bytes. What
// differs from toolboxd follows from WASM having no OS process:
//
//   - no terminal: tty:true is refused with an error frame;
//   - no signals: any signal the protocol knows ends the run (it is killed,
//     and the exit reports signal "killed");
//   - no shell: argv runs as given, a command string is split into words
//     with shell quoting but no expansion (splitShellWords);
//   - no working directory: workdir must be /work or under it, and reaches
//     the module as PWD (guests built with Go's wasip1 port honour it).

var execStreamUpgrader = toolboxwire.NewExecStreamUpgrader()

// streamSignals are the signal names toolboxd delivers; on WASM each ends
// the run. Unknown names are ignored, as toolboxd ignores them.
var streamSignals = map[string]bool{
	"INT": true, "SIGINT": true, "TERM": true, "SIGTERM": true, "KILL": true, "SIGKILL": true,
	"HUP": true, "SIGHUP": true, "QUIT": true, "SIGQUIT": true,
}

func (h *Host) handleExecStream(w http.ResponseWriter, r *http.Request) {
	if h.procs == nil {
		writeError(w, http.StatusNotImplemented, "streaming exec is not available for this wasm sandbox")
		return
	}
	// Refuse before the upgrade where we can, so the caller gets a status
	// code; a run that fails to start after it gets an error frame instead.
	if err := h.procs.CanStart(); err != nil {
		writeError(w, processErrorStatus(err), err.Error())
		return
	}
	conn, err := execStreamUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has written the HTTP error.
		return
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(toolboxwire.StartTimeout)); err != nil {
		return
	}
	var start toolboxwire.ExecStreamStart
	if err := conn.ReadJSON(&start); err != nil {
		writeStreamControl(conn, toolboxwire.ExecStreamControlOut{Type: "error", Message: "invalid start message"})
		return
	}
	spec, msg := wasmStreamSpec(start)
	if msg != "" {
		writeStreamControl(conn, toolboxwire.ExecStreamControlOut{Type: "error", Message: msg})
		return
	}
	st, err := h.procs.StartStream(r.Context(), spec)
	if err != nil {
		writeStreamControl(conn, toolboxwire.ExecStreamControlOut{Type: "error", Message: err.Error()})
		if errors.Is(err, ErrTooManyProcesses) {
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "too many processes"), time.Now().Add(time.Second))
		}
		return
	}
	defer st.Close()
	h.pumpExecStream(r.Context(), conn, st)
}

// wasmStreamSpec turns a start message into a run, or an error message for
// the client. The messages match toolboxd's where the rule is the same.
func wasmStreamSpec(start toolboxwire.ExecStreamStart) (StreamSpec, string) {
	if start.TTY {
		return StreamSpec{}, "terminals are not supported on wasm sandboxes; run without tty"
	}
	hasCommand := start.Command != ""
	switch {
	case hasCommand && len(start.Argv) > 0:
		return StreamSpec{}, "set command or argv, not both"
	case !hasCommand && len(start.Argv) == 0:
		return StreamSpec{}, "command is required"
	case len(start.Argv) > 0 && strings.TrimSpace(start.Argv[0]) == "":
		return StreamSpec{}, "argv[0] must name the program to run"
	case len(start.Argv) > 0 && strings.HasPrefix(start.Argv[0], "-"):
		return StreamSpec{}, "argv[0] must name the program to run, not an option"
	}
	args := start.Argv
	if hasCommand {
		words, err := splitShellWords(start.Command)
		if err != nil {
			return StreamSpec{}, err.Error()
		}
		if len(words) == 0 {
			return StreamSpec{}, "command is required"
		}
		args = words
	}
	env := start.Env
	if start.Workdir != "" {
		dir := path.Clean(start.Workdir)
		if dir != "/work" && !strings.HasPrefix(dir, "/work/") {
			return StreamSpec{}, "workdir must be /work or a folder inside it on wasm sandboxes"
		}
		if _, set := env["PWD"]; !set {
			env = make(map[string]string, len(start.Env)+1)
			for k, v := range start.Env {
				env[k] = v
			}
			env["PWD"] = dir
		}
	}
	// An exec stream lasts as long as the client keeps it open, as on
	// toolboxd: a dropped connection is what ends it, not a timer.
	return StreamSpec{Args: args, Env: env, Stdin: true, NoDeadline: true}, ""
}

func (h *Host) streamLiveness() toolboxwire.Liveness {
	if h.liveness.PingInterval > 0 && h.liveness.PongWait > 0 {
		cfg := h.liveness
		if cfg.PingWriteWait <= 0 {
			cfg.PingWriteWait = toolboxwire.DefaultLiveness.PingWriteWait
		}
		return cfg
	}
	return toolboxwire.DefaultLiveness
}

// pumpExecStream moves stdin and control frames to the run and its output
// to the client until the run exits, the client drops, or ctx ends (the
// sandbox is stopping).
func (h *Host) pumpExecStream(ctx context.Context, conn *websocket.Conn, st ProcessStream) {
	var exited atomic.Bool
	// A dropped client and a stopping sandbox both end the run: nobody can
	// see its output any more. Kill first: Close alone cannot reach a run
	// whose stdin is backed up.
	var endOnce sync.Once
	end := func() {
		endOnce.Do(func() {
			if !exited.Load() {
				_ = st.Kill()
			}
			_ = st.Close()
		})
	}
	stopWatch := context.AfterFunc(ctx, end)
	defer stopWatch()
	extend, stopLiveness := toolboxwire.ArmLiveness(conn, h.streamLiveness())
	defer stopLiveness()

	readerDone := make(chan struct{})
	// The reader ends on the connection's close, or on the run's: a reader
	// stuck writing stdin the guest never read is freed by st.Close.
	defer func() {
		_ = conn.Close()
		_ = st.Close()
		<-readerDone
	}()
	go func() {
		defer close(readerDone)
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				end()
				return
			}
			extend()
			switch msgType {
			case websocket.BinaryMessage:
				_ = st.WriteStdin(data)
			case websocket.TextMessage:
				var ctrl toolboxwire.ExecStreamControlIn
				if json.Unmarshal(data, &ctrl) != nil {
					continue
				}
				switch ctrl.Type {
				case "signal":
					if streamSignals[strings.ToUpper(ctrl.Signal)] {
						_ = st.Kill()
					}
				case "close":
					_ = st.CloseStdin()
				}
			}
		}
	}()

	// Only this goroutine writes frames; the pinger's WriteControl is safe
	// alongside it.
	write := func(prefix byte, data []byte) error {
		return conn.WriteMessage(websocket.BinaryMessage, append([]byte{prefix}, data...))
	}
	for {
		ev, err := st.Recv()
		if err != nil {
			msg := "stream ended: " + err.Error()
			if ctx.Err() != nil {
				msg = "the sandbox stopped"
			}
			writeStreamControl(conn, toolboxwire.ExecStreamControlOut{Type: "error", Message: msg})
			return
		}
		if ev.Exit != nil {
			exited.Store(true)
			out := toolboxwire.ExecStreamControlOut{Type: "exit", Code: ev.Exit.ExitCode}
			if ev.Exit.Killed || ev.Exit.TimedOut {
				out.Code, out.Signal = -1, "killed"
			}
			if ev.Exit.Error != "" {
				// A trap (out of memory, unreachable) has no stderr of its
				// own; say what happened before the exit.
				_ = write(toolboxwire.FramePrefixStderr, []byte(ev.Exit.Error+"\n"))
			}
			writeStreamControl(conn, out)
			return
		}
		if len(ev.Stdout) > 0 {
			if write(toolboxwire.FramePrefixStdout, ev.Stdout) != nil {
				end()
				return
			}
		}
		if len(ev.Stderr) > 0 {
			if write(toolboxwire.FramePrefixStderr, ev.Stderr) != nil {
				end()
				return
			}
		}
	}
}

func writeStreamControl(conn *websocket.Conn, msg toolboxwire.ExecStreamControlOut) {
	_ = conn.WriteJSON(msg)
}
