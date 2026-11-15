package toolhost

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/gorilla/websocket"
)

// The Daytona-compatible /process/session routes on WASM (issue #178),
// wire-identical to toolboxd's (cmd/toolboxd/daytona_process.go, shapes in
// internal/toolboxwire): the same paths, bodies, status codes and the order
// in which they are checked. Each command runs inside the wasm engine
// (Sessions); this handler, which runs in sandboxd on the host, only moves
// bytes. What differs from toolboxd follows from WASM having no shell:
//
//   - a command line is split into argv with shell quoting but no
//     expansion (splitShellWords, as the exec stream does) and runs the
//     sandbox's own module; there are no pipes, &&, cd or exports, and no
//     working directory or environment carries from one command to the next;
//   - output kept per command is capped (newest bytes kept), so a sync
//     exec's output and the logs of a long command can lose their head;
//   - a follow WebSocket ends with a normal close frame when the command
//     ends, where toolboxd drops the connection;
//   - the entrypoint session is the sandbox's serving guest, which toolboxd
//     does not serve at all (501), and "entrypoint" cannot be created as an
//     ordinary session.

var logsUpgrader = toolboxwire.NewLogsUpgrader()

// followCloseWait bounds the close frame sent after a follow ends.
const followCloseWait = time.Second

func (h *Host) handleProcessSession(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeError(w, http.StatusNotImplemented, "sessions are not available for this wasm sandbox")
		return
	}
	if r.URL.Path == "/process/session" {
		switch r.Method {
		case http.MethodPost:
			h.handleSessionCreate(w, r)
		case http.MethodGet:
			writeJSON(w, http.StatusOK, sessionResponses(h.sessions.List()))
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/process/session/")
	switch rest {
	case toolboxwire.EntrypointSessionID:
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleEntrypointSession(w, r)
		return
	case toolboxwire.EntrypointSessionID + "/logs":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleEntrypointLogs(w, r)
		return
	}
	sessionID, action, _ := strings.Cut(rest, "/")
	if strings.TrimSpace(sessionID) == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	switch {
	case action == "":
		switch r.Method {
		case http.MethodGet:
			info, err := h.sessions.Get(sessionID)
			if err != nil {
				writeSessionError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, sessionResponse(info))
		case http.MethodDelete:
			if err := h.sessions.Delete(sessionID); err != nil {
				writeSessionError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case action == "exec":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleSessionExec(w, r, sessionID)
	case strings.HasPrefix(action, "command/"):
		h.handleSessionCommandRoute(w, r, sessionID, strings.TrimPrefix(action, "command/"))
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *Host) handleSessionCommandRoute(w http.ResponseWriter, r *http.Request, sessionID, rest string) {
	commandID, action, _ := strings.Cut(rest, "/")
	if strings.TrimSpace(commandID) == "" {
		writeError(w, http.StatusBadRequest, "command id is required")
		return
	}
	want := map[string]string{"": http.MethodGet, "logs": http.MethodGet, "input": http.MethodPost}
	method, ok := want[action]
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != method {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// As toolboxd: a missing session is 404 before anything else is read.
	if _, err := h.sessions.Get(sessionID); err != nil {
		writeSessionError(w, err)
		return
	}
	switch action {
	case "":
		info, err := h.sessions.Command(sessionID, commandID)
		if err != nil {
			writeSessionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, commandResponse(info))
	case "logs":
		h.handleSessionCommandLogs(w, r, sessionID, commandID)
	case "input":
		h.handleSessionCommandInput(w, r, sessionID, commandID)
	}
}

func (h *Host) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	var req toolboxwire.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}
	if sessionID == toolboxwire.EntrypointSessionID {
		// Its routes are the entrypoint's; a session by that name could
		// be made but never reached.
		writeError(w, http.StatusConflict, `session id "entrypoint" is the sandbox's entrypoint session`)
		return
	}
	created, err := h.sessions.Create(sessionID)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
}

func (h *Host) handleSessionExec(w http.ResponseWriter, r *http.Request, sessionID string) {
	if _, err := h.sessions.Get(sessionID); err != nil {
		writeSessionError(w, err)
		return
	}
	var req toolboxwire.SessionExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	text := strings.TrimSpace(req.Command)
	if text == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	argv, err := splitShellWords(text)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(argv) == 0 {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	async := req.RunsAsync()
	res, err := h.sessions.Exec(r.Context(), sessionID, SessionCommand{Text: text, Argv: argv}, async)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if async {
		writeJSON(w, http.StatusOK, toolboxwire.SessionExecuteResponse{CmdID: res.ID})
		return
	}
	writeJSON(w, http.StatusOK, toolboxwire.NewSessionExecuteResponse(res.ID, res.ExitCode, res.Stdout, res.Stderr))
}

func (h *Host) handleSessionCommandLogs(w http.ResponseWriter, r *http.Request, sessionID, commandID string) {
	if strings.EqualFold(r.URL.Query().Get("follow"), "true") {
		follow, err := h.sessions.Follow(sessionID, commandID)
		if err != nil {
			writeSessionError(w, err)
			return
		}
		serveFollow(w, r, follow)
		return
	}
	if _, err := h.sessions.Command(sessionID, commandID); err != nil {
		writeSessionError(w, err)
		return
	}
	q, err := toolboxwire.ParseLogQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	stdout, stderr, err := h.sessions.Logs(sessionID, commandID, q)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toolboxwire.NewSessionLogsResponse(stdout, stderr))
}

// handleSessionCommandInput writes a line to the running command's stdin.
// The checks run in toolboxd's order: command, then running, then body.
func (h *Host) handleSessionCommandInput(w http.ResponseWriter, r *http.Request, sessionID, commandID string) {
	info, err := h.sessions.Command(sessionID, commandID)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if !info.Running {
		writeSessionError(w, ErrCommandNotRunning)
		return
	}
	var req toolboxwire.SessionInputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := h.sessions.Input(sessionID, commandID, []byte(req.Line())); err != nil {
		writeSessionError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleEntrypointSession is GET /process/session/entrypoint: a session
// whose one command is the sandbox's serving guest.
func (h *Host) handleEntrypointSession(w http.ResponseWriter, r *http.Request) {
	info, err := h.sessions.Entrypoint(r.Context(), false)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toolboxwire.SessionResponse{
		SessionID: toolboxwire.EntrypointSessionID,
		Commands: []toolboxwire.CommandResponse{{
			Command:  info.Command,
			ExitCode: info.ExitCode,
			ID:       toolboxwire.EntrypointCommandID,
		}},
	})
}

// entrypointLogsResponse is Daytona's entrypoint logs body.
type entrypointLogsResponse struct {
	Output string `json:"output"`
	Stderr string `json:"stderr"`
	Stdout string `json:"stdout"`
}

func (h *Host) handleEntrypointLogs(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.URL.Query().Get("follow"), "true") {
		follow, err := h.sessions.FollowEntrypoint(r.Context())
		if err != nil {
			writeSessionError(w, err)
			return
		}
		serveFollow(w, r, follow)
		return
	}
	info, err := h.sessions.Entrypoint(r.Context(), true)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entrypointLogsResponse{Output: info.Stdout + info.Stderr, Stdout: info.Stdout, Stderr: info.Stderr})
}

// serveFollow upgrades to the follow WebSocket and streams follow until it
// ends or the client leaves. A command that ended gets a normal close
// frame, so a client (the Daytona Go SDK among them) reads a clean end
// rather than a dropped connection.
func serveFollow(w http.ResponseWriter, r *http.Request, follow *LogFollow) {
	defer follow.Close()
	conn, err := logsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has written the HTTP error.
		return
	}
	defer conn.Close()
	// A stopping sandbox ends the request's context; the follow ends with
	// it rather than waiting on output that will not come.
	stop := context.AfterFunc(r.Context(), func() { _ = conn.Close() })
	defer stop()
	if toolboxwire.FollowLogs(conn, follow.Replay, follow.Frames) {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(followCloseWait))
	}
}

func sessionResponses(infos []SessionInfo) []toolboxwire.SessionResponse {
	out := make([]toolboxwire.SessionResponse, 0, len(infos))
	for _, info := range infos {
		out = append(out, sessionResponse(info))
	}
	return out
}

func sessionResponse(info SessionInfo) toolboxwire.SessionResponse {
	cmds := make([]toolboxwire.CommandResponse, 0, len(info.Commands))
	for _, c := range info.Commands {
		cmds = append(cmds, commandResponse(c))
	}
	return toolboxwire.SessionResponse{Commands: cmds, SessionID: info.ID}
}

func commandResponse(c CommandInfo) toolboxwire.CommandResponse {
	return toolboxwire.CommandResponse{Command: c.Command, ExitCode: c.ExitCode, ID: c.ID}
}

func writeSessionError(w http.ResponseWriter, err error) {
	writeError(w, sessionErrorStatus(err), err.Error())
}
