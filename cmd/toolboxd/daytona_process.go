package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The wire shapes (bodies, log windows, follow framing) live in
// internal/toolboxwire, shared with the WASM toolhost, which serves the same
// routes from runs inside the wasm engine.

var daytonaLogsUpgrader = toolboxwire.NewLogsUpgrader()

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
	frame := toolboxwire.FrameLog(stream == sessions.StreamStderr, chunk)

	c.mu.Lock()
	defer c.mu.Unlock()
	if stream == sessions.StreamStderr {
		c.stderr = append(c.stderr, chunk...)
	} else {
		c.stdout = append(c.stdout, chunk...)
	}
	// Keep the lock through these non-blocking sends so finish cannot close a
	// subscriber after it has been selected here but before the send occurs.
	for _, sub := range c.subs {
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

// window returns each stream's bytes from its offset — at most limit bytes
// of each, 0 meaning no limit — read in one critical section so the two
// agree. Only the window is copied, so a poller reading a long-running
// command's new output pays for the new bytes, not for everything the
// command has written.
func (c *daytonaCommandStream) window(q toolboxwire.LogQuery) (stdout, stderr toolboxwire.LogWindow) {
	if c == nil {
		return toolboxwire.LogWindow{}, toolboxwire.LogWindow{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return toolboxwire.CutLogWindow(c.stdout, q.StdoutOffset, q.Limit, false), toolboxwire.CutLogWindow(c.stderr, q.StderrOffset, q.Limit, false)
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
	initial = toolboxwire.LogReplay(c.stdout, c.stderr)
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
		writeRouteNotFound(w)
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
		writeRouteNotFound(w)
	}
}

// handleDaytonaSessionCommandInput forwards bytes from a Daytona-style
// {"data": "..."} payload to the session's stdin. The shell that backs the
// session reads stdin one byte at a time when stdin is a pipe (a documented
// bash behavior for non-interactive scripts), so a `read` builtin inside the
// running command picks up the input directly — no shared-buffer races with
// the wrapper's end marker.
//
// A trailing newline is added when the payload has none
// (toolboxwire.SessionInputRequest.Line): bash's `read` builtin blocks
// forever without it.
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
	var req toolboxwire.SessionInputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := sess.Write([]byte(req.Line())); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleDaytonaSessionCreate(w http.ResponseWriter, r *http.Request) {
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
	items := make([]toolboxwire.SessionResponse, 0)
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
	var req toolboxwire.SessionExecuteRequest
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
	if req.RunsAsync() {
		go s.runDaytonaSessionCommand(sess, state, command)
		writeJSON(w, http.StatusOK, toolboxwire.SessionExecuteResponse{CmdID: commandID})
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
	writeJSON(w, http.StatusOK, toolboxwire.CommandResponse{Command: command.command, ExitCode: cloneInt32Ptr(command.exitCode), ID: command.id})
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
	q, err := toolboxwire.ParseLogQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var stdout, stderr toolboxwire.LogWindow
	if command.exitCode == nil {
		// Still running: the final text is set only when the command ends,
		// so answer with what it has written so far — what a follower
		// would have been sent.
		stdout, stderr = command.stream.window(q)
	} else {
		stdout, stderr = toolboxwire.CutLogWindow(command.stdout, q.StdoutOffset, q.Limit, true), toolboxwire.CutLogWindow(command.stderr, q.StderrOffset, q.Limit, true)
	}
	writeJSON(w, http.StatusOK, toolboxwire.NewSessionLogsResponse(stdout, stderr))
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
	toolboxwire.FollowLogs(conn, initial, ch)
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

func buildDaytonaSessionResponse(sessionID string, state *daytonaSessionState) toolboxwire.SessionResponse {
	commands := state.commandsSnapshot()
	response := make([]toolboxwire.CommandResponse, 0, len(commands))
	for _, command := range commands {
		response = append(response, toolboxwire.CommandResponse{Command: command.command, ExitCode: cloneInt32Ptr(command.exitCode), ID: command.id})
	}
	return toolboxwire.SessionResponse{Commands: response, SessionID: sessionID}
}

func (s *server) runDaytonaSessionCommand(sess *sessions.Session, state *daytonaSessionState, command *daytonaCommandState) (*toolboxwire.SessionExecuteResponse, error) {
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
	//
	// The stderr sentinel is printed after the user command and before the
	// stdout end marker. Those two streams are separate pipes, so the end
	// marker is often read first and the command's stderr is still sitting
	// in the other pipe. Returning on the end marker alone drops that
	// stderr (the race behind TestRunDaytonaSessionCommandMarkerParsing
	// on Ubuntu dash). The runner keeps reading until the sentinel arrives.
	errSentinel := "__SB_DAYTONA_ERR_" + command.id + "__\n"
	payload := "printf '%s\\n' " + shellSingleQuote(startMarker) + "; { " + command.command + "\n}; __sb_daytona_status=$?; printf '%s' " + shellSingleQuote(errSentinel) + " >&2; printf '%s:%s\\n' " + shellSingleQuote(endMarker) + " \"$__sb_daytona_status\"\n"
	if _, err := sess.Write([]byte(payload)); err != nil {
		state.finishCommand(command.id, "", err.Error(), 1)
		return nil, err
	}

	var stdout strings.Builder
	var stderr strings.Builder
	started := false
	stderrDone := false
	// stdoutBroadcasted / stderrBroadcasted track how many bytes of the
	// post-start buffers have already been pushed to live subscribers, so
	// each new frame broadcasts only the genuinely new prefix-safe slice.
	stdoutBroadcasted := 0
	stderrBroadcasted := 0
	publishStderr := func() {
		// Hold pre-start stderr. It may be shell noise, and it may be the
		// command's stderr arriving before the start marker is observed;
		// either way it stays out of the live stream until the command
		// has been delimited. Once the sentinel lands the bytes are the
		// command's, even if the start marker frame has not been read yet.
		if !started && !stderrDone {
			return
		}
		captured := stderr.String()
		safeLen := len(captured)
		if !stderrDone {
			safeLen -= longestEndMarkerPrefixSuffix(captured, errSentinel)
		}
		if safeLen > stderrBroadcasted {
			command.stream.broadcast(sessions.StreamStderr, []byte(captured[stderrBroadcasted:safeLen]))
			stderrBroadcasted = safeLen
		}
	}
	var pendingStdout string
	var pendingExit int32
	havePending := false
	complete := func(stdoutText string, exitCode int32) (*toolboxwire.SessionExecuteResponse, error) {
		stderrText := stderr.String()
		state.finishCommand(command.id, stdoutText, stderrText, exitCode)
		return toolboxwire.NewSessionExecuteResponse(command.id, exitCode, stdoutText, stderrText), nil
	}
	for frame := range frames {
		chunk := string(frame.Data)
		if frame.Stream == sessions.StreamStderr {
			if !stderrDone {
				stderrDone = absorbDaytonaErrSentinel(&stderr, chunk, errSentinel)
				publishStderr()
			}
			if havePending && stderrDone {
				return complete(pendingStdout, pendingExit)
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
			publishStderr()
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
			var exitCode int32 = 1
			if parsed, perr := strconv.ParseInt(strings.TrimSpace(rest[:lineEnd]), 10, 32); perr == nil {
				exitCode = int32(parsed)
			}
			// Stdout is done, but stderr may still be unread on the other
			// pipe. Hold the result until the wrapper's sentinel arrives.
			pendingStdout = captured[:index]
			pendingExit = exitCode
			havePending = true
			if stderrDone {
				return complete(pendingStdout, pendingExit)
			}
			continue
		}
		// No end marker yet. Only hold back the trailing window that is
		// actually a partial prefix of the end marker — anything else
		// can be broadcast immediately. A naive `hold := len(pattern)-1`
		// would stall short outputs ("Enter name: \n" = 18 bytes,
		// pattern = ~34 bytes) until enough later text accumulates,
		// which never happens for interactive commands blocked on stdin.
		hold := longestEndMarkerPrefixSuffix(captured, pattern)
		if safeLen := len(captured) - hold; safeLen > stdoutBroadcasted {
			command.stream.broadcast(sessions.StreamStdout, []byte(captured[stdoutBroadcasted:safeLen]))
			stdoutBroadcasted = safeLen
		}
	}

	// The shell exited before the wrapper could print the stderr sentinel.
	// An end marker already parsed is the command's status; otherwise the
	// process exit code is all we have. Stderr buffered before the start
	// marker, with no sentinel, is shell noise and stays out of the result.
	// Nothing more will arrive, so a held-back sentinel prefix is user data
	// and has to be broadcast.
	flushStderr := func() {
		if !started && !stderrDone {
			return
		}
		captured := stderr.String()
		if len(captured) > stderrBroadcasted {
			command.stream.broadcast(sessions.StreamStderr, []byte(captured[stderrBroadcasted:]))
			stderrBroadcasted = len(captured)
		}
	}
	if havePending {
		flushStderr()
		return complete(pendingStdout, pendingExit)
	}
	stdoutText := stdout.String()
	if !started && !stderrDone {
		stderr.Reset()
	}
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
	flushStderr()
	state.finishCommand(command.id, stdoutText, stderrText, int32(exitCode))
	return toolboxwire.NewSessionExecuteResponse(command.id, int32(exitCode), stdoutText, stderrText), nil
}

// absorbDaytonaErrSentinel appends chunk and reports whether sentinel is
// now present. The sentinel and anything after it is removed so it never
// becomes part of the command's stderr. A partial sentinel stays in buf;
// callers hold that suffix back from live subscribers.
func absorbDaytonaErrSentinel(buf *strings.Builder, chunk, sentinel string) bool {
	buf.WriteString(chunk)
	captured := buf.String()
	i := strings.Index(captured, sentinel)
	if i < 0 {
		return false
	}
	buf.Reset()
	buf.WriteString(captured[:i])
	return true
}

func newDaytonaCommandID() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// longestEndMarkerPrefixSuffix returns the length of the longest trailing
// substring of `captured` that is also a prefix of `pattern`. Used by the
// streaming runner to decide how many bytes at the end of the stdout
// buffer MUST stay un-broadcast in case they turn out to be the start of
// the end marker. Any shorter suffix is safe to flush immediately, which
// is what makes short interactive output (e.g. "Enter name: \n") visible
// to /logs?follow=true subscribers without waiting for the command to
// finish.
func longestEndMarkerPrefixSuffix(captured, pattern string) int {
	maxLen := min(len(pattern)-1, len(captured))
	for k := maxLen; k > 0; k-- {
		if strings.HasPrefix(pattern, captured[len(captured)-k:]) {
			return k
		}
	}
	return 0
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
