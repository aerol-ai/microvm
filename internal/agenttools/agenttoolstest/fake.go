// Package agenttoolstest is an in-memory fake of the parts of sandboxd the
// aerolvm CLI and MCP server use: v1 sandboxes (create, get, list by name,
// start, destroy, ports), the toolbox file and exec endpoints, the exec
// WebSocket, and sessions. Tests in agenttools, agentmcp and cmd/aerolvm
// share it so the three layers are checked against the same wire behaviour.
// It never imports server packages.
package agenttoolstest

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Token is the bearer token the fake accepts.
const Token = "test-token"

// DropStream, returned as the signal from an Exec, makes the fake close the
// exec stream without an exit message, like a connection lost mid-command.
const DropStream = "\x00drop"

// Exec is a scripted command. It writes output with out(stream, bytes)
// (stream 1 = stdout, 2 = stderr), reads stdin from in (closed at EOF), and
// returns the exit code and signal. killed is closed when the client sends
// KILL or the stream drops.
type Exec func(cmd string, in io.Reader, out func(stream byte, b []byte), killed <-chan struct{}) (code int, signal string)

// Sandbox is one fake sandbox with its files and sessions.
type Sandbox struct {
	models.Sandbox
	Files    map[string][]byte
	Sessions map[string]*Session
}

// Session is one fake background process.
type Session struct {
	models.Session
	Log []byte
}

// Server is the fake sandboxd. Fields after mu are guarded by it; read them
// through Snapshot-style helpers or after the client calls return.
type Server struct {
	*httptest.Server
	t testing.TB

	mu        sync.Mutex
	sandboxes map[string]*Sandbox
	nextID    int

	// Knobs.

	// IgnoreNameFilter makes GET /sandboxes ignore ?name=, like a server
	// that predates name lookup (CEO review CF5).
	IgnoreNameFilter bool
	// IgnoreLimit makes GET /sandboxes return every row even when the
	// caller sent ?limit=, like a daemon that predates single-node paging.
	IgnoreLimit bool
	// BadFileInfo makes GET /toolbox/files/info return a body that is
	// not the info JSON, so callers exercise their decode failure path.
	BadFileInfo bool
	// HangAttach accepts the session websocket and then waits for the
	// client to go away, so a follower can be detached instead of
	// observing an immediate exit.
	HangAttach bool
	// AttachReady is closed once a hanging attach has the websocket.
	// Tests wait on it before cancelling the client.
	AttachReady chan struct{}
	// AttachExitSignal is sent on the attach exit message. Empty means
	// the command exited by code alone.
	AttachExitSignal string
	// DropAfterCreate drops the connection this many times right after a
	// create succeeds, so the client never sees the reply (lost reply, D5).
	DropAfterCreate int
	// ExecFunc overrides the built-in command interpreter.
	ExecFunc Exec
	// BufferedPad adds this many bytes of padding to buffered exec stdout.
	BufferedPad int
	// FailStart makes POST /start fail with 500.
	FailStart bool
	// FailDestroy makes DELETE /sandboxes/{id} fail with 500 after the
	// sandbox was found, so callers can tell a destroy error from a miss.
	FailDestroy bool
	// FailToolbox makes every toolbox route fail with 500.
	FailToolbox bool
	// FailSessions makes session create/get/delete fail with 500.
	FailSessions bool
	// FailExpose makes POST /ports/{port} fail with 500.
	FailExpose bool
	// DropAttach upgrades the session websocket and closes it before an
	// exit message, so Wait returns an error instead of a code.
	DropAttach bool
	// ConflictAlways makes every create fail with 409 without creating
	// anything (a conflict on something other than the name).
	ConflictAlways bool
	// FailCreates makes the next N creates fail with 500.
	FailCreates int
	// CreateDelay holds each create this long, to widen races in tests.
	CreateDelay time.Duration

	// Observations.

	Requests       []string
	CreatePosts    int
	CreatedIDs     []string
	StreamDials    int
	Signals        []string
	ExecCommands   []string
	BufferedExecs  int
	LastCreate     models.CreateSandboxRequest
	StartCalls     int
	DestroyCalls   int
	ListQueries    []string
	UploadedBodies int
}

// New starts a fake sandboxd that the test closes on cleanup.
func New(t testing.TB) *Server {
	s := &Server{t: t, sandboxes: map[string]*Sandbox{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// AddSandbox registers a sandbox. A zero ID gets a generated one.
func (s *Server) AddSandbox(sb models.Sandbox) *Sandbox {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sb.ID == "" {
		sb.ID = s.newIDLocked()
	}
	if sb.Status == "" {
		sb.Status = models.SandboxStatusStarted
	}
	if sb.CreatedAt.IsZero() {
		sb.CreatedAt = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	}
	fake := &Sandbox{Sandbox: sb, Files: map[string][]byte{}, Sessions: map[string]*Session{}}
	s.sandboxes[sb.ID] = fake
	return fake
}

// Sandbox returns a copy of the fake sandbox's row.
func (s *Server) Sandbox(id string) (models.Sandbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.sandboxes[id]
	if !ok {
		return models.Sandbox{}, false
	}
	return sb.Sandbox, true
}

// File returns a file's content from a fake sandbox.
func (s *Server) File(id, path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb, ok := s.sandboxes[id]
	if !ok {
		return nil, false
	}
	b, ok := sb.Files[path]
	return append([]byte(nil), b...), ok
}

// PutFile stores a file in a fake sandbox.
func (s *Server) PutFile(id, path string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sandboxes[id].Files[path] = append([]byte(nil), data...)
}

// Remove deletes a sandbox, as an idle lifecycle destroy would.
func (s *Server) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sandboxes, id)
}

// SetStatus changes a sandbox's status (e.g. stopped by its idle timer).
func (s *Server) SetStatus(id string, status models.SandboxStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sandboxes[id].Status = status
}

// Count is the number of live sandboxes.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sandboxes)
}

// Observe runs fn with the server locked, for reading observation fields.
func (s *Server) Observe(fn func(*Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

func (s *Server) newIDLocked() string {
	s.nextID++
	return fmt.Sprintf("sb-%016x", s.nextID)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+Token {
		writeErr(w, http.StatusUnauthorized, "missing or invalid token")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	switch {
	case path == "/health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": "fake"})
	case path == "/sandboxes" && r.Method == http.MethodGet:
		s.list(w, r)
	case path == "/sandboxes" && r.Method == http.MethodPost:
		s.create(w, r)
	case strings.HasPrefix(path, "/sandboxes/"):
		rest := strings.TrimPrefix(path, "/sandboxes/")
		id, sub, _ := strings.Cut(rest, "/")
		s.sandboxRoute(w, r, id, sub)
	default:
		writeErr(w, http.StatusNotFound, "no route")
	}
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ListQueries = append(s.ListQueries, r.URL.RawQuery)
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	ids := make([]string, 0, len(s.sandboxes))
	for id := range s.sandboxes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []models.Sandbox{}
	for _, id := range ids {
		sb := s.sandboxes[id]
		if name != "" && !s.IgnoreNameFilter && sb.Name != name {
			continue
		}
		if !tagsMatch(sb.Tags, r) {
			continue
		}
		out = append(out, sb.Sandbox)
	}
	if !s.IgnoreLimit {
		if limit, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && limit > 0 && (name == "" || s.IgnoreNameFilter) {
			start := 0
			if tok := r.URL.Query().Get("page_token"); tok != "" {
				start, _ = strconv.Atoi(tok)
			}
			if start > len(out) {
				start = len(out)
			}
			end := min(start+limit, len(out))
			if end < len(out) {
				w.Header().Set("X-Cluster-List-Next-Page-Token", strconv.Itoa(end))
			}
			out = out[start:end]
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func tagsMatch(tags map[string]string, r *http.Request) bool {
	for key, values := range r.URL.Query() {
		k, ok := strings.CutPrefix(key, "tag.")
		if !ok || len(values) == 0 {
			continue
		}
		if tags[k] != values[0] {
			return false
		}
	}
	return true
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.mu.Lock()
	s.CreatePosts++
	s.LastCreate = req
	if err := models.ValidateSandboxName(req.Name); err != nil {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.ConflictAlways {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "cluster: reservation conflict on sandbox id")
		return
	}
	if s.FailCreates > 0 {
		s.FailCreates--
		s.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if d := s.CreateDelay; d > 0 {
		s.mu.Unlock()
		time.Sleep(d)
		s.mu.Lock()
	}
	if req.Name != "" {
		for _, sb := range s.sandboxes {
			if sb.Name == req.Name {
				s.mu.Unlock()
				writeErr(w, http.StatusConflict, "sandbox name already in use")
				return
			}
		}
	}
	id := s.newIDLocked()
	runtime := req.Runtime
	if runtime == "" {
		runtime = models.RuntimeDocker
	}
	sb := &Sandbox{
		Sandbox: models.Sandbox{
			ID: id, Name: req.Name, Image: req.Image, Status: models.SandboxStatusStarted,
			Runtime: runtime, Tags: req.Tags, CPU: req.CPU, MemoryMB: req.MemoryMB,
			CreatedAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
		},
		Files: map[string][]byte{}, Sessions: map[string]*Session{},
	}
	if req.Lifecycle != nil {
		sb.Lifecycle = *req.Lifecycle
	}
	s.sandboxes[id] = sb
	s.CreatedIDs = append(s.CreatedIDs, id)
	drop := s.DropAfterCreate > 0
	if drop {
		s.DropAfterCreate--
	}
	row := sb.Sandbox
	s.mu.Unlock()
	if drop {
		hijackAndClose(w)
		return
	}
	writeJSON(w, http.StatusCreated, models.CreateSandboxResponse{Sandbox: row})
}

func hijackAndClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("fake: response writer can't hijack")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func (s *Server) sandboxRoute(w http.ResponseWriter, r *http.Request, id, sub string) {
	s.mu.Lock()
	sb, ok := s.sandboxes[id]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "sandbox not found")
		return
	}
	switch {
	case sub == "" && r.Method == http.MethodGet:
		s.mu.Lock()
		row := sb.Sandbox
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, row)
	case sub == "" && r.Method == http.MethodDelete:
		s.mu.Lock()
		s.DestroyCalls++
		fail := s.FailDestroy
		if !fail {
			delete(s.sandboxes, id)
		}
		s.mu.Unlock()
		if fail {
			writeErr(w, http.StatusInternalServerError, "destroy failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case sub == "start" && r.Method == http.MethodPost:
		s.mu.Lock()
		s.StartCalls++
		fail := s.FailStart
		if !fail {
			sb.Status = models.SandboxStatusStarted
		}
		row := sb.Sandbox
		s.mu.Unlock()
		if fail {
			writeErr(w, http.StatusInternalServerError, "start failed")
			return
		}
		writeJSON(w, http.StatusOK, row)
	case sub == "stop" && r.Method == http.MethodPost:
		s.mu.Lock()
		sb.Status = models.SandboxStatusStopped
		row := sb.Sandbox
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, row)
	case strings.HasPrefix(sub, "ports/") && r.Method == http.MethodPost:
		s.mu.Lock()
		failExpose := s.FailExpose
		s.mu.Unlock()
		if failExpose {
			writeErr(w, http.StatusInternalServerError, "expose failed")
			return
		}
		port, _ := strconv.Atoi(strings.TrimPrefix(sub, "ports/"))
		var req struct {
			Protocol string `json:"protocol"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := models.ExposePortResponse{Protocol: "http", PublicURL: fmt.Sprintf("https://%d-%s.example.test", port, id)}
		if req.Protocol == "tcp" {
			resp.Protocol = "tcp"
			resp.Host = "127.0.0.1"
			resp.HostPort = 40000 + port
		}
		writeJSON(w, http.StatusOK, resp)
	case sub == "snapshot" && r.Method == http.MethodPost:
		var req models.CreateSandboxSnapshotRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusCreated, models.SandboxSnapshot{Name: req.Name, Image: "snapshots/" + req.Name, SourceSandboxID: id})
	case strings.HasPrefix(sub, "sessions/") && strings.HasSuffix(sub, "/attach") && r.Method == http.MethodGet:
		s.attachSession(w, r, sb, strings.TrimSuffix(strings.TrimPrefix(sub, "sessions/"), "/attach"))
	case strings.HasPrefix(sub, "sessions"):
		s.sessions(w, r, sb, strings.TrimPrefix(sub, "sessions"))
	case strings.HasPrefix(sub, "toolbox/"):
		s.toolbox(w, r, sb, "/"+strings.TrimPrefix(sub, "toolbox/"))
	default:
		writeErr(w, http.StatusNotFound, "no route")
	}
}

func (s *Server) toolbox(w http.ResponseWriter, r *http.Request, sb *Sandbox, path string) {
	s.mu.Lock()
	failToolbox := s.FailToolbox
	s.mu.Unlock()
	if failToolbox {
		writeErr(w, http.StatusInternalServerError, "toolbox failed")
		return
	}
	if sb.Runtime == models.RuntimeIsolate {
		writeErr(w, http.StatusNotImplemented, "isolate sandboxes have no toolbox")
		return
	}
	wasm := sb.Runtime == models.RuntimeWasm
	q := r.URL.Query()
	switch {
	case path == "/files/download" && r.Method == http.MethodGet:
		s.mu.Lock()
		data, ok := sb.Files[q.Get("path")]
		s.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, "open "+q.Get("path")+": no such file or directory")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	case path == "/files/upload" && r.Method == http.MethodPost:
		s.upload(w, r, sb)
	case path == "/files" && r.Method == http.MethodGet:
		s.listFiles(w, sb, q.Get("path"), wasm)
	case path == "/files/info" && r.Method == http.MethodGet && !wasm:
		s.mu.Lock()
		badInfo := s.BadFileInfo
		data, ok := sb.Files[q.Get("path")]
		s.mu.Unlock()
		if badInfo {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-json"))
			return
		}
		if !ok {
			writeErr(w, http.StatusNotFound, "no such file")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": q.Get("path"), "size": len(data), "isDir": false})
	case path == "/files/search" && r.Method == http.MethodGet && !wasm:
		s.mu.Lock()
		matches := []string{}
		for p := range sb.Files {
			if strings.HasSuffix(p, strings.TrimPrefix(q.Get("pattern"), "*")) {
				matches = append(matches, p)
			}
		}
		s.mu.Unlock()
		sort.Strings(matches)
		writeJSON(w, http.StatusOK, map[string]any{"files": matches})
	case path == "/files/find" && r.Method == http.MethodGet && !wasm:
		type match struct {
			Content string `json:"content"`
			File    string `json:"file"`
			Line    int32  `json:"line"`
		}
		s.mu.Lock()
		matches := []match{}
		paths := make([]string, 0, len(sb.Files))
		for p := range sb.Files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			for i, line := range strings.Split(string(sb.Files[p]), "\n") {
				if strings.Contains(line, q.Get("pattern")) {
					matches = append(matches, match{Content: line, File: p, Line: int32(i + 1)})
				}
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, matches)
	case path == "/process/execute" && r.Method == http.MethodPost:
		s.bufferedExec(w, r)
	case path == "/process/exec/stream" && r.Method == http.MethodGet:
		if wasm {
			writeErr(w, http.StatusNotImplemented, "streaming exec is not supported on wasm")
			return
		}
		s.execStream(w, r)
	default:
		writeErr(w, http.StatusNotFound, "no toolbox route "+path)
	}
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, sb *Sandbox) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	var target string
	var data []byte
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(part)
		switch part.FormName() {
		case "path":
			target = string(b)
		case "file":
			data = b
		}
	}
	if target == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	s.mu.Lock()
	sb.Files[target] = data
	s.UploadedBodies++
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"path": target})
}

func (s *Server) listFiles(w http.ResponseWriter, sb *Sandbox, dir string, wasm bool) {
	s.mu.Lock()
	type named struct {
		name  string
		isDir bool
	}
	names := []named{}
	for p := range sb.Files {
		if dir == "" || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/") {
			base := strings.TrimSuffix(p, "/")
			names = append(names, named{name: base[strings.LastIndex(base, "/")+1:], isDir: strings.HasSuffix(p, "/")})
		}
	}
	s.mu.Unlock()
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })
	if wasm {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = n.name
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	type entry struct {
		Name  string `json:"name"`
		IsDir bool   `json:"isDir"`
		Size  int32  `json:"size"`
		Mode  string `json:"mode"`
	}
	out := make([]entry, 0, len(names))
	for _, n := range names {
		out = append(out, entry{Name: n.name, IsDir: n.isDir, Size: 1, Mode: "-rw-r--r--"})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) bufferedExec(w http.ResponseWriter, r *http.Request) {
	var req models.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.mu.Lock()
	s.BufferedExecs++
	s.ExecCommands = append(s.ExecCommands, req.Command)
	pad := s.BufferedPad
	exec := s.execFunc()
	s.mu.Unlock()
	var stdout, stderr strings.Builder
	killed := make(chan struct{})
	code, signal := exec(req.Command, strings.NewReader(""), func(stream byte, b []byte) {
		if stream == 2 {
			stderr.Write(b)
		} else {
			stdout.Write(b)
		}
	}, killed)
	if signal != "" {
		code = -1
	}
	if pad > 0 {
		stdout.WriteString(strings.Repeat("p", pad))
	}
	writeJSON(w, http.StatusOK, models.ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code, DurationMS: 5})
}

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func (s *Server) execStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	var start struct {
		Command string `json:"command"`
	}
	if err := conn.ReadJSON(&start); err != nil {
		return
	}
	s.mu.Lock()
	s.StreamDials++
	s.ExecCommands = append(s.ExecCommands, start.Command)
	exec := s.execFunc()
	s.mu.Unlock()

	stdinR, stdinW := io.Pipe()
	killed := make(chan struct{})
	var killOnce sync.Once
	kill := func() { killOnce.Do(func() { close(killed) }) }
	go func() {
		defer stdinW.Close()
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				kill() // a dropped stream kills the command, like toolboxd
				return
			}
			if msgType == websocket.BinaryMessage {
				if _, err := stdinW.Write(data); err != nil {
					return
				}
				continue
			}
			var ctrl struct {
				Type   string `json:"type"`
				Signal string `json:"signal"`
			}
			if json.Unmarshal(data, &ctrl) != nil {
				continue
			}
			switch ctrl.Type {
			case "close":
				_ = stdinW.Close()
			case "signal":
				s.mu.Lock()
				s.Signals = append(s.Signals, ctrl.Signal)
				s.mu.Unlock()
				if ctrl.Signal == "KILL" {
					kill()
				}
			}
		}
	}()
	var writeMu sync.Mutex
	code, signal := exec(start.Command, stdinR, func(stream byte, b []byte) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{stream}, b...))
	}, killed)
	if signal == DropStream {
		_ = conn.UnderlyingConn().Close()
		return
	}
	writeMu.Lock()
	_ = conn.WriteJSON(map[string]any{"type": "exit", "code": code, "signal": signal})
	writeMu.Unlock()
}

func (s *Server) execFunc() Exec {
	if s.ExecFunc != nil {
		return s.ExecFunc
	}
	return Interpret
}

// Interpret is the built-in command language:
//
//	echo TEXT        stdout TEXT + newline, exit 0
//	stderr TEXT      stderr TEXT + newline, exit 0
//	exit N           exit N
//	cat              copy stdin to stdout until EOF
//	yes N            N bytes of "y\n" on stdout
//	sleep            run until killed, then report signal "killed"
//	signal NAME      exit by signal NAME
//	anything else    stdout "ran: CMD" + newline
func Interpret(cmd string, in io.Reader, out func(byte, []byte), killed <-chan struct{}) (int, string) {
	verb, arg, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	switch verb {
	case "echo":
		out(1, []byte(arg+"\n"))
	case "stderr":
		out(2, []byte(arg+"\n"))
	case "exit":
		n, _ := strconv.Atoi(arg)
		return n, ""
	case "cat":
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				out(1, append([]byte(nil), buf[:n]...))
			}
			if err != nil {
				return 0, ""
			}
		}
	case "yes":
		n, _ := strconv.Atoi(arg)
		chunk := []byte(strings.Repeat("y\n", 2048))
		for n > 0 {
			take := min(n, len(chunk))
			out(1, chunk[:take])
			n -= take
		}
	case "sleep":
		<-killed
		return -1, "killed"
	case "signal":
		return -1, arg
	default:
		out(1, []byte("ran: "+cmd+"\n"))
	}
	return 0, ""
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request, sb *Sandbox, rest string) {
	rest = strings.TrimPrefix(rest, "/")
	sid, sub, _ := strings.Cut(rest, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailSessions {
		writeErr(w, http.StatusInternalServerError, "sessions failed")
		return
	}
	switch {
	case sid == "" && r.Method == http.MethodPost:
		var req models.CreateSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		for _, existing := range sb.Sessions {
			if existing.Name == req.Name {
				writeJSON(w, http.StatusOK, existing.Session)
				return
			}
		}
		id := fmt.Sprintf("ses-%d", len(sb.Sessions)+1)
		status := models.SessionStatusRunning
		exitCode := 0
		// A command of "exit N" is already finished, so process-log callers
		// can render a non-running status without a second request.
		if n, ok := strings.CutPrefix(req.Command, "exit "); ok {
			status = models.SessionStatusExited
			exitCode, _ = strconv.Atoi(strings.TrimSpace(n))
		}
		session := &Session{Session: models.Session{ID: id, Name: req.Name, Argv: []string{"/bin/sh", "-c", req.Command}, Status: status, ExitCode: exitCode}}
		session.Log = []byte("started " + req.Command + "\n")
		sb.Sessions[id] = session
		writeJSON(w, http.StatusCreated, session.Session)
	case sid != "" && sub == "" && r.Method == http.MethodGet:
		session, ok := sb.Sessions[sid]
		if !ok {
			writeErr(w, http.StatusNotFound, "session not found")
			return
		}
		writeJSON(w, http.StatusOK, session.Session)
	case sid != "" && sub == "log" && r.Method == http.MethodGet:
		session, ok := sb.Sessions[sid]
		if !ok {
			writeErr(w, http.StatusNotFound, "session not found")
			return
		}
		_, _ = w.Write(session.Log)
	case sid != "" && sub == "" && r.Method == http.MethodDelete:
		if _, ok := sb.Sessions[sid]; !ok {
			writeErr(w, http.StatusNotFound, "session not found")
			return
		}
		delete(sb.Sessions, sid)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusNotFound, "no session route")
	}
}

// attachSession replays a session's log and reports exit code 0, like
// attaching to a command that has just finished.
func (s *Server) attachSession(w http.ResponseWriter, r *http.Request, sb *Sandbox, sessionID string) {
	s.mu.Lock()
	session, ok := sb.Sessions[sessionID]
	var logCopy []byte
	if ok {
		logCopy = append([]byte(nil), session.Log...)
	}
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	s.mu.Lock()
	hang := s.HangAttach
	ready := s.AttachReady
	exitSignal := s.AttachExitSignal
	drop := s.DropAttach
	s.mu.Unlock()
	if drop {
		return
	}
	if hang {
		if ready != nil {
			select {
			case <-ready:
			default:
				close(ready)
			}
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}
	_ = conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, logCopy...))
	_ = conn.WriteJSON(map[string]any{"type": "exit", "code": 0, "signal": exitSignal})
}

// AppendSessionLog adds output to a fake session's log.
func (s *Server) AppendSessionLog(sandboxID, sessionID string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sandboxes[sandboxID].Sessions[sessionID]
	session.Log = append(session.Log, b...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, models.ErrorResponse{Error: msg})
}
