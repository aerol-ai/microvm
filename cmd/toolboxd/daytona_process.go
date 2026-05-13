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
)

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
		writeError(w, http.StatusNotImplemented, "interactive command input is not implemented")
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
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
	command, ok := state.command(commandID)
	if !ok {
		writeError(w, http.StatusNotFound, "command not found")
		return
	}
	writeJSON(w, http.StatusOK, daytonaSessionLogsResponse{Output: command.output, Stderr: command.stderr, Stdout: command.stdout})
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

	startMarker := "__SB_DAYTONA_START_" + command.id + "__"
	endMarker := "__SB_DAYTONA_END_" + command.id + "__"
	frames, cancel := sess.Subscribe()
	defer cancel()
	state.setActive(command.id)

	payload := "printf '%s\\n' " + shellSingleQuote(startMarker) + "\n" + command.command + "\n__sb_daytona_status=$?\nprintf '%s:%s\\n' " + shellSingleQuote(endMarker) + " \"$__sb_daytona_status\"\n"
	if _, err := sess.Write([]byte(payload)); err != nil {
		state.finishCommand(command.id, "", err.Error(), 1)
		return nil, err
	}

	var stdout strings.Builder
	var stderr strings.Builder
	started := false
	for frame := range frames {
		chunk := string(frame.Data)
		if frame.Stream == sessions.StreamStderr {
			if started {
				stderr.WriteString(chunk)
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
		}

		captured = stdout.String()
		pattern := endMarker + ":"
		index := strings.Index(captured, pattern)
		if index < 0 {
			continue
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

	stdoutText := stdout.String()
	stderrText := stderr.String()
	exitCode, _ := sess.ExitInfo()
	if exitCode < 0 {
		exitCode = 1
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
