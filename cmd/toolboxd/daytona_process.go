package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// Daytona SDK ≥0.175 streams session command logs over WebSocket on
// /process/session/{sid}/command/{cid}/logs?follow=true. Frames are binary;
// the client (stdDemuxStream in @daytona/sdk's utils/Stream.js) demultiplexes
// stdout and stderr by these three-byte markers preceding each chunk.
var (
	daytonaStdoutPrefix = []byte{0x01, 0x01, 0x01}
	daytonaStderrPrefix = []byte{0x02, 0x02, 0x02}
)

var daytonaLogsUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

type daytonaCompat struct {
	mu       sync.Mutex
	sessions map[string]*daytonaSessionState
}

type daytonaSessionState struct {
	execMu sync.Mutex
	mu     sync.RWMutex

	commands        map[string]*daytonaCommandState
	activeCommandID string
}

type daytonaCommandState struct {
	id        string
	command   string
	stdout    string
	stderr    string
	output    string
	exitCode  *int32
	running   bool
	createdAt time.Time

	// stream is pointer-indirect on purpose: the outer struct is copied
	// for snapshot reads (commandsSnapshot, command()), so embedding a
	// mutex directly would trip `go vet` copylocks. All copies share the
	// same live stream, which is exactly what subscribers need.
	stream *daytonaCommandStream
}

// daytonaCommandStream owns the live streaming state for /logs?follow=true
// subscribers: a replay buffer of bytes already broadcast, the list of
// active subscriber channels, and a once-closed `finished` channel. mu
// covers all three fields.
type daytonaCommandStream struct {
	mu       sync.Mutex
	stdout   []byte
	stderr   []byte
	subs     []chan []byte
	finished chan struct{}
}

func newDaytonaCommandStream() *daytonaCommandStream {
	return &daytonaCommandStream{finished: make(chan struct{})}
}

// broadcast appends a chunk to the streaming buffer and pushes a framed copy
// to every active subscriber. Sends are non-blocking — a slow subscriber
// drops the frame rather than stalling the command runner.
func (c *daytonaCommandStream) broadcast(stream sessions.Stream, chunk []byte) {
	if c == nil || len(chunk) == 0 {
		return
	}
	prefix := daytonaStdoutPrefix
	if stream == sessions.StreamStderr {
		prefix = daytonaStderrPrefix
	}
	frame := make([]byte, 0, len(prefix)+len(chunk))
	frame = append(frame, prefix...)
	frame = append(frame, chunk...)

	c.mu.Lock()
	if stream == sessions.StreamStderr {
		c.stderr = append(c.stderr, chunk...)
	} else {
		c.stdout = append(c.stdout, chunk...)
	}
	subs := make([]chan []byte, len(c.subs))
	copy(subs, c.subs)
	c.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub <- frame:
		default:
		}
	}
}

// finish signals all subscribers the command has ended and clears the
// subscriber list. Safe to call multiple times — finished is closed at
// most once.
func (c *daytonaCommandStream) finish() {
	if c == nil {
		return
	}
	c.mu.Lock()
	select {
	case <-c.finished:
		c.mu.Unlock()
		return
	default:
		close(c.finished)
	}
	subs := c.subs
	c.subs = nil
	c.mu.Unlock()
	for _, sub := range subs {
		close(sub)
	}
}

// subscribe registers a new live subscriber. Returns the framed replay of
// bytes already broadcast (so the subscriber doesn't miss earlier output)
// and a channel for future frames. If the command has already finished the
// returned channel is closed. Registration is atomic with the replay
// snapshot: no broadcast can slip in between the two without showing up
// either in the replay or on the channel.
func (c *daytonaCommandStream) subscribe() (initial []byte, ch <-chan []byte, finished bool) {
	if c == nil {
		closed := make(chan []byte)
		close(closed)
		return nil, closed, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stdout) > 0 {
		initial = append(initial, daytonaStdoutPrefix...)
		initial = append(initial, c.stdout...)
	}
	if len(c.stderr) > 0 {
		initial = append(initial, daytonaStderrPrefix...)
		initial = append(initial, c.stderr...)
	}
	select {
	case <-c.finished:
		closed := make(chan []byte)
		close(closed)
		return initial, closed, true
	default:
	}
	sub := make(chan []byte, 256)
	c.subs = append(c.subs, sub)
	return initial, sub, false
}

type daytonaCreateSessionRequest struct {
	SessionID string `json:"sessionId"`
}

type daytonaSessionResponse struct {
	Commands  []daytonaCommandResponse `json:"commands"`
	SessionID string                   `json:"sessionId"`
}

type daytonaCommandResponse struct {
	Command  string `json:"command"`
	ExitCode *int32 `json:"exitCode,omitempty"`
	ID       string `json:"id"`
}

type daytonaSessionExecuteRequest struct {
	Async             *bool  `json:"async,omitempty"`
	Command           string `json:"command"`
	RunAsync          *bool  `json:"runAsync,omitempty"`
	SuppressInputEcho *bool  `json:"suppressInputEcho,omitempty"`
}

type daytonaSessionExecuteResponse struct {
	CmdID    string  `json:"cmdId"`
	ExitCode *int32  `json:"exitCode,omitempty"`
	Output   *string `json:"output,omitempty"`
	Stderr   *string `json:"stderr,omitempty"`
	Stdout   *string `json:"stdout,omitempty"`
}

type daytonaSessionLogsResponse struct {
	Output string `json:"output"`
	Stderr string `json:"stderr"`
	Stdout string `json:"stdout"`
}

type daytonaSessionInputRequest struct {
	Data string `json:"data"`
}

func newDaytonaCompat() *daytonaCompat {
	return &daytonaCompat{sessions: map[string]*daytonaSessionState{}}
}

func (c *daytonaCompat) ensureSession(sessionID string) *daytonaSessionState {
	trimmed := strings.TrimSpace(sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.sessions[trimmed]
	if state == nil {
		state = &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
		c.sessions[trimmed] = state
	}
	return state
}

func (c *daytonaCompat) session(sessionID string) (*daytonaSessionState, bool) {
	trimmed := strings.TrimSpace(sessionID)
	c.mu.Lock()
	state, ok := c.sessions[trimmed]
	c.mu.Unlock()
	return state, ok
}

func (c *daytonaCompat) deleteSession(sessionID string) {
	c.mu.Lock()
	delete(c.sessions, strings.TrimSpace(sessionID))
	c.mu.Unlock()
}

func (c *daytonaCompat) listSessionIDs() []string {
	c.mu.Lock()
	ids := make([]string, 0, len(c.sessions))
	for sessionID := range c.sessions {
		ids = append(ids, sessionID)
	}
	c.mu.Unlock()
	sort.Strings(ids)
	return ids
}

func (s *daytonaSessionState) addCommand(command *daytonaCommandState) {
	s.mu.Lock()
	if s.commands == nil {
		s.commands = map[string]*daytonaCommandState{}
	}
	s.commands[command.id] = command
	s.mu.Unlock()
}

func (s *daytonaSessionState) setActive(commandID string) {
	s.mu.Lock()
	if command, ok := s.commands[commandID]; ok {
		command.running = true
	}
	s.activeCommandID = commandID
	s.mu.Unlock()
}

func (s *daytonaSessionState) finishCommand(commandID, stdout, stderr string, exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	command, ok := s.commands[commandID]
	if !ok {
		return
	}
	command.stdout = stdout
	command.stderr = stderr
	command.output = stdout + stderr
	command.exitCode = int32Ptr(exitCode)
	command.running = false
	if s.activeCommandID == commandID {
		s.activeCommandID = ""
	}
}

func (s *daytonaSessionState) command(commandID string) (*daytonaCommandState, bool) {
	s.mu.RLock()
	command, ok := s.commands[commandID]
	if !ok {
		s.mu.RUnlock()
		return nil, false
	}
	copy := *command
	s.mu.RUnlock()
	return &copy, true
}

// commandPtr returns the live pointer (NOT a copy) so the streaming
// /logs?follow=true handler can register subscribers on the shared state.
// Callers must restrict themselves to the dedicated streamMu-protected
// surface (broadcast / finishStream / subscribeStream).
func (s *daytonaSessionState) commandPtr(commandID string) (*daytonaCommandState, bool) {
	s.mu.RLock()
	command, ok := s.commands[commandID]
	s.mu.RUnlock()
	return command, ok
}

func (s *daytonaSessionState) commandsSnapshot() []daytonaCommandState {
	s.mu.RLock()
	items := make([]daytonaCommandState, 0, len(s.commands))
	for _, command := range s.commands {
		items = append(items, *command)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].createdAt.Before(items[j].createdAt) })
	return items
}

func (s *daytonaSessionState) acceptsInput(commandID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	command, ok := s.commands[commandID]
	if !ok {
		return false
	}
	return command.running && s.activeCommandID == commandID
}

func (s *server) handleDaytonaProcessRoute(w http.ResponseWriter, r *http.Request) bool {
	if s.sessions == nil {
		writeError(w, http.StatusNotImplemented, "sessions are disabled")
		return true
	}
	if r.URL.Path == "/process/session" {
		switch r.Method {
		case http.MethodPost:
			s.handleDaytonaSessionCreate(w, r)
		case http.MethodGet:
			s.handleDaytonaSessionList(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return true
	}
	const prefix = "/process/session/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "entrypoint" || rest == "entrypoint/logs" {
		writeError(w, http.StatusNotImplemented, "entrypoint session compatibility is not implemented")
		return true
	}
	sessionID, action, _ := strings.Cut(rest, "/")
	if strings.TrimSpace(sessionID) == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return true
	}
	switch {
	case action == "":
		switch r.Method {
		case http.MethodGet:
			s.handleDaytonaSessionGet(w, r, sessionID)
		case http.MethodDelete:
			s.handleDaytonaSessionDelete(w, r, sessionID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case action == "exec":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		s.handleDaytonaSessionExec(w, r, sessionID)
	case strings.HasPrefix(action, "command/"):
		s.handleDaytonaSessionCommandRoute(w, r, sessionID, strings.TrimPrefix(action, "command/"))
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
	return true
}

func (s *server) handleDaytonaSessionCommandRoute(w http.ResponseWriter, r *http.Request, sessionID, rest string) {
	commandID, action, _ := strings.Cut(rest, "/")
	if strings.TrimSpace(commandID) == "" {
		writeError(w, http.StatusBadRequest, "command id is required")
		return
	}
	switch action {
	case "":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDaytonaSessionCommandGet(w, r, sessionID, commandID)
	case "logs":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDaytonaSessionCommandLogs(w, r, sessionID, commandID)
	case "input":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDaytonaSessionCommandInput(w, r, sessionID, commandID)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// handleDaytonaSessionCommandInput forwards bytes from a Daytona-style
// {"data": "..."} payload to the session's stdin. The shell that backs the
// session reads stdin one byte at a time when stdin is a pipe (a documented
// bash behavior for non-interactive scripts), so a `read` builtin inside the
// running command picks up the input directly — no shared-buffer races with
// the wrapper's end marker. Data is written verbatim; callers that need a
// trailing newline must include it.
func (s *server) handleDaytonaSessionCommandInput(w http.ResponseWriter, r *http.Request, sessionID, commandID string) {
	sess, state, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if _, ok := state.command(commandID); !ok {
		writeError(w, http.StatusNotFound, "command not found")
		return
	}
	if !state.acceptsInput(commandID) {
		writeError(w, http.StatusConflict, "command is not currently accepting input")
		return
	}
	var req daytonaSessionInputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := sess.Write([]byte(req.Data)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleDaytonaSessionCreate(w http.ResponseWriter, r *http.Request) {
	var req daytonaCreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}
	_, created, err := s.sessions.GetOrCreate(r.Context(), models.CreateSessionRequest{Name: sessionID, PTY: false})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.daytona.ensureSession(sessionID)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
}

func (s *server) handleDaytonaSessionList(w http.ResponseWriter, r *http.Request) {
	items := make([]daytonaSessionResponse, 0)
	for _, sessionID := range s.daytona.listSessionIDs() {
		sess, state, ok := s.lookupDaytonaSession(sessionID)
		if !ok {
			continue
		}
		items = append(items, buildDaytonaSessionResponse(sess.Name(), state))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *server) handleDaytonaSessionGet(w http.ResponseWriter, r *http.Request, sessionID string) {
	sess, state, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, buildDaytonaSessionResponse(sess.Name(), state))
}

func (s *server) handleDaytonaSessionDelete(w http.ResponseWriter, r *http.Request, sessionID string) {
	sess, _, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err := s.sessions.Delete(sess.ID()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sessions.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	s.daytona.deleteSession(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaSessionExec(w http.ResponseWriter, r *http.Request, sessionID string) {
	sess, state, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	var req daytonaSessionExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	commandText := strings.TrimSpace(req.Command)
	if commandText == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	commandID, err := newDaytonaCommandID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	command := &daytonaCommandState{
		id:        commandID,
		command:   commandText,
		createdAt: time.Now().UTC(),
		running:   true,
		stream:    newDaytonaCommandStream(),
	}
	state.addCommand(command)
	async := (req.RunAsync != nil && *req.RunAsync) || (req.Async != nil && *req.Async)
	if async {
		go s.runDaytonaSessionCommand(sess, state, command)
		writeJSON(w, http.StatusOK, daytonaSessionExecuteResponse{CmdID: commandID})
		return
	}
	response, err := s.runDaytonaSessionCommand(sess, state, command)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) handleDaytonaSessionCommandGet(w http.ResponseWriter, r *http.Request, sessionID, commandID string) {
	_, state, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	command, ok := state.command(commandID)
	if !ok {
		writeError(w, http.StatusNotFound, "command not found")
		return
	}
	writeJSON(w, http.StatusOK, daytonaCommandResponse{Command: command.command, ExitCode: cloneInt32Ptr(command.exitCode), ID: command.id})
}

func (s *server) handleDaytonaSessionCommandLogs(w http.ResponseWriter, r *http.Request, sessionID, commandID string) {
	_, state, ok := s.lookupDaytonaSession(sessionID)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if strings.EqualFold(r.URL.Query().Get("follow"), "true") {
		cmd, ok := state.commandPtr(commandID)
		if !ok {
			writeError(w, http.StatusNotFound, "command not found")
			return
		}
		s.streamDaytonaSessionCommandLogs(w, r, cmd)
		return
	}
	command, ok := state.command(commandID)
	if !ok {
		writeError(w, http.StatusNotFound, "command not found")
		return
	}
	writeJSON(w, http.StatusOK, daytonaSessionLogsResponse{Output: command.output, Stderr: command.stderr, Stdout: command.stdout})
}

// streamDaytonaSessionCommandLogs upgrades the request to a WebSocket and
// streams stdout/stderr to the client until the command ends. Frame format
// is the Daytona convention: each binary message begins with a 3-byte
// marker (0x01x3 = stdout, 0x02x3 = stderr) followed by the chunk bytes.
// On subscribe we first send the replay of bytes already broadcast, then
// stream new frames. Closing the channel (when the runner finishes) ends
// the loop and the WebSocket is closed.
func (s *server) streamDaytonaSessionCommandLogs(w http.ResponseWriter, r *http.Request, cmd *daytonaCommandState) {
	conn, err := daytonaLogsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrader has already written an HTTP error response on failure.
		s.logger.Warn("daytona session logs upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	initial, ch, _ := cmd.stream.subscribe()
	if len(initial) > 0 {
		if err := conn.WriteMessage(websocket.BinaryMessage, initial); err != nil {
			return
		}
	}

	// Detect client disconnects so we don't block forever waiting on a
	// command that may run indefinitely. Reads here drain any frames the
	// client sends (none, per protocol) but unblock when the peer closes.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

func (s *server) lookupDaytonaSession(sessionID string) (*sessions.Session, *daytonaSessionState, bool) {
	state, ok := s.daytona.session(sessionID)
	if !ok {
		return nil, nil, false
	}
	sess, err := s.sessions.GetByName(sessionID)
	if err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			s.daytona.deleteSession(sessionID)
			return nil, nil, false
		}
		return nil, nil, false
	}
	return sess, state, true
}

func buildDaytonaSessionResponse(sessionID string, state *daytonaSessionState) daytonaSessionResponse {
	commands := state.commandsSnapshot()
	response := make([]daytonaCommandResponse, 0, len(commands))
	for _, command := range commands {
		response = append(response, daytonaCommandResponse{Command: command.command, ExitCode: cloneInt32Ptr(command.exitCode), ID: command.id})
	}
	return daytonaSessionResponse{Commands: response, SessionID: sessionID}
}

func (s *server) runDaytonaSessionCommand(sess *sessions.Session, state *daytonaSessionState, command *daytonaCommandState) (*daytonaSessionExecuteResponse, error) {
	state.execMu.Lock()
	defer state.execMu.Unlock()
	// finishStream always fires once the runner exits so any live
	// /logs?follow=true subscribers see EOF promptly, regardless of which
	// branch below returns (write error, end-marker, or session close).
	defer command.stream.finish()

	startMarker := "__SB_DAYTONA_START_" + command.id + "__"
	endMarker := "__SB_DAYTONA_END_" + command.id + "__"
	pattern := endMarker + ":"
	frames, cancel := sess.Subscribe()
	defer cancel()
	state.setActive(command.id)

	// Wrap the user command in a `{ ... }` brace group joined by semicolons so
	// the wrapper is a single compound statement. Bash buffers its stdin and
	// parses the entire compound before executing — without the group, a
	// `read` inside the user command would consume the wrapper's own follow-up
	// lines (status capture, end marker) from bash's parse buffer instead of
	// waiting for input. The trailing newline before `}` lets the user's last
	// command terminate normally.
	payload := "printf '%s\\n' " + shellSingleQuote(startMarker) + "; { " + command.command + "\n}; __sb_daytona_status=$?; printf '%s:%s\\n' " + shellSingleQuote(endMarker) + " \"$__sb_daytona_status\"\n"
	if _, err := sess.Write([]byte(payload)); err != nil {
		state.finishCommand(command.id, "", err.Error(), 1)
		return nil, err
	}

	var stdout strings.Builder
	var stderr strings.Builder
	started := false
	// stdoutBroadcasted tracks how many bytes of the post-start stdout
	// buffer have already been pushed to live subscribers, so each new
	// frame broadcasts only the genuinely new prefix-safe slice.
	stdoutBroadcasted := 0
	for frame := range frames {
		chunk := string(frame.Data)
		if frame.Stream == sessions.StreamStderr {
			if started {
				stderr.WriteString(chunk)
				command.stream.broadcast(sessions.StreamStderr, []byte(chunk))
			}
			continue
		}

		stdout.WriteString(chunk)
		captured := stdout.String()
		if !started {
			index := strings.Index(captured, startMarker)
			if index < 0 {
				if stdout.Len() > len(startMarker)*2 {
					tail := captured[len(captured)-len(startMarker):]
					stdout.Reset()
					stdout.WriteString(tail)
				}
				continue
			}
			started = true
			captured = captured[index+len(startMarker):]
			captured = strings.TrimPrefix(captured, "\n")
			stdout.Reset()
			stdout.WriteString(captured)
			stdoutBroadcasted = 0
		}

		captured = stdout.String()
		if index := strings.Index(captured, pattern); index >= 0 {
			// End marker located: flush any unbroadcast pre-end bytes
			// once, then finalize. stdoutBroadcasted is bumped to index
			// so any later iteration is a no-op (e.g. when we continue
			// below waiting for the exit-code newline).
			if index > stdoutBroadcasted {
				command.stream.broadcast(sessions.StreamStdout, []byte(captured[stdoutBroadcasted:index]))
				stdoutBroadcasted = index
			}
			rest := captured[index+len(pattern):]
			lineEnd := strings.IndexByte(rest, '\n')
			if lineEnd < 0 {
				continue
			}
			exitCode, err := strconv.Atoi(strings.TrimSpace(rest[:lineEnd]))
			if err != nil {
				exitCode = 1
			}
			stdoutText := captured[:index]
			stderrText := stderr.String()
			state.finishCommand(command.id, stdoutText, stderrText, int32(exitCode))
			output := stdoutText + stderrText
			return &daytonaSessionExecuteResponse{
				CmdID:    command.id,
				ExitCode: int32Ptr(int32(exitCode)),
				Output:   stringOrNil(output),
				Stderr:   stringOrNil(stderrText),
				Stdout:   stringOrNil(stdoutText),
			}, nil
		}
		// No end marker yet: broadcast everything except a trailing
		// window that could still resolve into the marker. Holding back
		// len(pattern)-1 bytes is the minimum safe — a full marker is
		// only possible once we have len(pattern) bytes of buffer.
		hold := len(pattern) - 1
		if safeLen := len(captured) - hold; safeLen > stdoutBroadcasted {
			command.stream.broadcast(sessions.StreamStdout, []byte(captured[stdoutBroadcasted:safeLen]))
			stdoutBroadcasted = safeLen
		}
	}

	stdoutText := stdout.String()
	stderrText := stderr.String()
	exitCode, _ := sess.ExitInfo()
	if exitCode < 0 {
		exitCode = 1
	}
	// Session ended without the end marker — there is no partial marker
	// to worry about. Flush whatever tail wasn't broadcast yet.
	if started && len(stdoutText) > stdoutBroadcasted {
		command.stream.broadcast(sessions.StreamStdout, []byte(stdoutText[stdoutBroadcasted:]))
	}
	state.finishCommand(command.id, stdoutText, stderrText, int32(exitCode))
	output := stdoutText + stderrText
	return &daytonaSessionExecuteResponse{
		CmdID:    command.id,
		ExitCode: int32Ptr(int32(exitCode)),
		Output:   stringOrNil(output),
		Stderr:   stringOrNil(stderrText),
		Stdout:   stringOrNil(stdoutText),
	}, nil
}

func newDaytonaCommandID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func int32Ptr(value int32) *int32 {
	return &value
}

func cloneInt32Ptr(value *int32) *int32 {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func stringOrNil(value string) *string {
	if value == "" {
		return nil
	}
	v := value
	return &v
}
