package toolhost

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/gorilla/websocket"
)

// fakeSessions is a Sessions a test fills in by hand; it records what the
// routes asked of it.
type fakeSessions struct {
	mu        sync.Mutex
	createErr error
	sessions  map[string]SessionInfo
	commands  map[string]CommandInfo // "sid/cid"

	execErr    error
	execResult CommandResult
	execs      []SessionCommand
	execAsync  []bool

	logsQuery      toolboxwire.LogQuery
	stdout, stderr toolboxwire.LogWindow

	inputs   []string
	inputCtx context.Context
	inputErr error

	follow    *LogFollow
	followErr error

	entry    EntrypointInfo
	entryErr error
	entryLog []bool
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{sessions: map[string]SessionInfo{}, commands: map[string]CommandInfo{}}
}

func (f *fakeSessions) addCommand(sid string, c CommandInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info := f.sessions[sid]
	info.ID = sid
	info.Commands = append(info.Commands, c)
	f.sessions[sid] = info
	f.commands[sid+"/"+c.ID] = c
}

func (f *fakeSessions) Create(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return false, f.createErr
	}
	if _, ok := f.sessions[id]; ok {
		return false, nil
	}
	f.sessions[id] = SessionInfo{ID: id}
	return true, nil
}

func (f *fakeSessions) List() []SessionInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SessionInfo
	for _, s := range f.sessions {
		out = append(out, s)
	}
	return out
}

func (f *fakeSessions) Get(id string) (SessionInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return SessionInfo{}, ErrSessionNotFound
	}
	return s, nil
}

func (f *fakeSessions) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[id]; !ok {
		return ErrSessionNotFound
	}
	delete(f.sessions, id)
	return nil
}

func (f *fakeSessions) Exec(_ context.Context, _ string, cmd SessionCommand, async bool) (CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, cmd)
	f.execAsync = append(f.execAsync, async)
	return f.execResult, f.execErr
}

func (f *fakeSessions) Command(sid, cid string) (CommandInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.commands[sid+"/"+cid]
	if !ok {
		return CommandInfo{}, ErrCommandNotFound
	}
	return c, nil
}

func (f *fakeSessions) Logs(sid, cid string, q toolboxwire.LogQuery) (toolboxwire.LogWindow, toolboxwire.LogWindow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logsQuery = q
	return f.stdout, f.stderr, nil
}

func (f *fakeSessions) Follow(sid, cid string) (*LogFollow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.commands[sid+"/"+cid]; !ok {
		return nil, ErrCommandNotFound
	}
	return f.follow, f.followErr
}

func (f *fakeSessions) Input(ctx context.Context, _, _ string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputCtx = ctx
	f.inputs = append(f.inputs, string(data))
	return f.inputErr
}

func (f *fakeSessions) Entrypoint(_ context.Context, logs bool) (EntrypointInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entryLog = append(f.entryLog, logs)
	return f.entry, f.entryErr
}

func (f *fakeSessions) FollowEntrypoint(context.Context) (*LogFollow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.entryErr != nil {
		return nil, f.entryErr
	}
	return f.follow, f.followErr
}

// sessionCall sends one authenticated request to a host backed by f.
func sessionCall(t *testing.T, f *fakeSessions, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: f})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	h.serveHTTP(rec, req)
	return rec
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, status, rec.Body.String())
	}
	if body != "" && strings.TrimSpace(rec.Body.String()) != body {
		t.Fatalf("body = %s, want %s", rec.Body.String(), body)
	}
}

func int32p(v int32) *int32 { return &v }

// Statuses and bodies are toolboxd's, route by route, including the order
// in which a request's faults are found.
func TestProcessSessionRoutes(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "done", Command: "mod a", ExitCode: int32p(2)})
	f.addCommand("s", CommandInfo{ID: "run", Command: "mod b", Running: true})
	f.addCommand("s", CommandInfo{ID: "wait", Command: "mod c"})

	tests := []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"create", http.MethodPost, "/process/session", `{"sessionId":" new "}`, http.StatusCreated, ""},
		{"create existing", http.MethodPost, "/process/session", `{"sessionId":"s"}`, http.StatusOK, ""},
		{"create bad body", http.MethodPost, "/process/session", `{`, http.StatusBadRequest, `{"error":"invalid JSON body"}`},
		{"create no id", http.MethodPost, "/process/session", `{"sessionId":"  "}`, http.StatusBadRequest, `{"error":"sessionId is required"}`},
		{"create entrypoint", http.MethodPost, "/process/session", `{"sessionId":"entrypoint"}`, http.StatusConflict, ""},
		{"family method", http.MethodPut, "/process/session", ``, http.StatusMethodNotAllowed, `{"error":"method not allowed"}`},
		{"get", http.MethodGet, "/process/session/s", ``, http.StatusOK,
			`{"commands":[{"command":"mod a","exitCode":2,"id":"done"},{"command":"mod b","id":"run"},{"command":"mod c","id":"wait"}],"sessionId":"s"}`},
		{"get sandbox-prefixed", http.MethodGet, "/sb-test/process/session/s", ``, http.StatusOK, ""},
		{"get missing", http.MethodGet, "/process/session/nope", ``, http.StatusNotFound, `{"error":"session not found"}`},
		{"blank id", http.MethodGet, "/process/session/%20", ``, http.StatusBadRequest, `{"error":"session id is required"}`},
		{"session method", http.MethodPatch, "/process/session/s", ``, http.StatusMethodNotAllowed, ""},
		{"unknown action", http.MethodGet, "/process/session/s/bogus", ``, http.StatusNotFound, `{"error":"not found"}`},
		{"exec method", http.MethodGet, "/process/session/s/exec", ``, http.StatusMethodNotAllowed, ""},
		{"exec missing session first", http.MethodPost, "/process/session/nope/exec", `{`, http.StatusNotFound, `{"error":"session not found"}`},
		{"exec bad body", http.MethodPost, "/process/session/s/exec", `{`, http.StatusBadRequest, `{"error":"invalid JSON body"}`},
		{"exec no command", http.MethodPost, "/process/session/s/exec", `{"command":"  "}`, http.StatusBadRequest, `{"error":"command is required"}`},
		{"exec bad quoting", http.MethodPost, "/process/session/s/exec", `{"command":"echo 'open"}`, http.StatusBadRequest, ""},
		{"command", http.MethodGet, "/process/session/s/command/done", ``, http.StatusOK, `{"command":"mod a","exitCode":2,"id":"done"}`},
		{"command running", http.MethodGet, "/process/session/s/command/run", ``, http.StatusOK, `{"command":"mod b","id":"run"}`},
		{"command missing", http.MethodGet, "/process/session/s/command/nope", ``, http.StatusNotFound, `{"error":"command not found"}`},
		{"command missing session", http.MethodGet, "/process/session/nope/command/done", ``, http.StatusNotFound, `{"error":"session not found"}`},
		{"command no id", http.MethodGet, "/process/session/s/command/", ``, http.StatusBadRequest, `{"error":"command id is required"}`},
		{"command method", http.MethodPost, "/process/session/s/command/done", ``, http.StatusMethodNotAllowed, ""},
		{"command unknown action", http.MethodGet, "/process/session/s/command/done/bogus", ``, http.StatusNotFound, ""},
		{"logs method", http.MethodPost, "/process/session/s/command/done/logs", ``, http.StatusMethodNotAllowed, ""},
		{"logs bad query", http.MethodGet, "/process/session/s/command/done/logs?limit=x", ``, http.StatusBadRequest, `{"error":"limit must be a non-negative integer"}`},
		{"logs missing", http.MethodGet, "/process/session/s/command/nope/logs?limit=x", ``, http.StatusNotFound, `{"error":"command not found"}`},
		{"input method", http.MethodGet, "/process/session/s/command/run/input", ``, http.StatusMethodNotAllowed, ""},
		{"input finished before body", http.MethodPost, "/process/session/s/command/done/input", `{`, http.StatusConflict, `{"error":"command is not currently accepting input"}`},
		{"input waiting", http.MethodPost, "/process/session/s/command/wait/input", `{"data":"x"}`, http.StatusConflict, ""},
		{"input missing", http.MethodPost, "/process/session/s/command/nope/input", `{"data":"x"}`, http.StatusNotFound, ""},
		{"input bad body", http.MethodPost, "/process/session/s/command/run/input", `{`, http.StatusBadRequest, `{"error":"invalid JSON body"}`},
		{"input", http.MethodPost, "/process/session/s/command/run/input", `{"data":"Alice"}`, http.StatusOK, ""},
		{"entrypoint method", http.MethodDelete, "/process/session/entrypoint", ``, http.StatusMethodNotAllowed, ""},
		{"entrypoint logs method", http.MethodPost, "/process/session/entrypoint/logs", ``, http.StatusMethodNotAllowed, ""},
		{"delete missing", http.MethodDelete, "/process/session/nope", ``, http.StatusNotFound, `{"error":"session not found"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, sessionCall(t, f, tt.method, tt.path, tt.body), tt.status, tt.want)
		})
	}
	if _, ok := f.sessions["new"]; !ok {
		t.Fatal("session id was not trimmed")
	}
	if len(f.inputs) != 1 || f.inputs[0] != "Alice\n" {
		t.Fatalf("inputs = %q, want one line with its newline added", f.inputs)
	}
	if len(f.execs) != 0 {
		t.Fatalf("a refused exec reached Sessions: %+v", f.execs)
	}

	// Delete answers 204 with no body; list is a JSON array, never null.
	wantStatus(t, sessionCall(t, f, http.MethodDelete, "/process/session/new", ""), http.StatusNoContent, "")
	empty := newFakeSessions()
	wantStatus(t, sessionCall(t, empty, http.MethodGet, "/process/session", ""), http.StatusOK, `[]`)
	wantStatus(t, sessionCall(t, f, http.MethodGet, "/process/session", ""), http.StatusOK,
		`[{"commands":[{"command":"mod a","exitCode":2,"id":"done"},{"command":"mod b","id":"run"},{"command":"mod c","id":"wait"}],"sessionId":"s"}]`)
}

// A command line becomes argv with shell quoting and no expansion, as on
// the exec stream; the text is kept as the caller wrote it.
func TestProcessSessionExec(t *testing.T) {
	f := newFakeSessions()
	_, _ = f.Create("s")
	f.execResult = CommandResult{ID: "c1", ExitCode: 0, Stdout: "1\n"}
	wantStatus(t, sessionCall(t, f, http.MethodPost, "/process/session/s/exec", `{"command":" python -c \"print(1)\" $HOME "}`), http.StatusOK,
		`{"cmdId":"c1","exitCode":0,"output":"1\n","stdout":"1\n"}`)
	if got := f.execs[0]; got.Text != `python -c "print(1)" $HOME` || strings.Join(got.Argv, "|") != "python|-c|print(1)|$HOME" || f.execAsync[0] {
		t.Fatalf("exec = %+v async %v", got, f.execAsync[0])
	}
	// runAsync (or the older async) answers with the id alone.
	for _, body := range []string{`{"command":"mod","runAsync":true}`, `{"command":"mod","async":true}`} {
		wantStatus(t, sessionCall(t, f, http.MethodPost, "/process/session/s/exec", body), http.StatusOK, `{"cmdId":"c1"}`)
	}
	if !f.execAsync[1] || !f.execAsync[2] {
		t.Fatalf("async flags = %v", f.execAsync)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{ErrTooManyProcesses, http.StatusTooManyRequests},
		{ErrTooManyCommands, http.StatusTooManyRequests},
		{ErrStreamingUnsupported, http.StatusNotImplemented},
		{ErrSessionStopped, http.StatusConflict},
		{ErrSessionNotFound, http.StatusNotFound},
		{errors.New("boom"), http.StatusInternalServerError},
	} {
		f.execErr = tc.err
		rec := sessionCall(t, f, http.MethodPost, "/process/session/s/exec", `{"command":"mod"}`)
		wantStatus(t, rec, tc.status, "")
		if !strings.Contains(rec.Body.String(), tc.err.Error()) {
			t.Fatalf("%v: body %s", tc.err, rec.Body.String())
		}
	}
	f.createErr = ErrTooManySessions
	wantStatus(t, sessionCall(t, f, http.MethodPost, "/process/session", `{"sessionId":"x"}`), http.StatusTooManyRequests, "")
}

func TestProcessSessionLogs(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "c", Command: "mod", Running: true})
	f.stdout = toolboxwire.LogWindow{Text: "ady", End: 5, Length: 6}
	f.stderr = toolboxwire.LogWindow{Text: "", End: 4, Length: 4}
	wantStatus(t, sessionCall(t, f, http.MethodGet, "/process/session/s/command/c/logs?stdoutOffset=2&stderrOffset=9&limit=3", ""), http.StatusOK,
		`{"output":"ady","stderr":"","stdout":"ady","stdoutLength":6,"stderrLength":4,"stdoutEnd":5,"stderrEnd":4}`)
	if f.logsQuery != (toolboxwire.LogQuery{StdoutOffset: 2, StderrOffset: 9, Limit: 3}) {
		t.Fatalf("query = %+v", f.logsQuery)
	}
}

func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

// readFollow reads binary frames until the server closes, and returns them
// with how the connection ended.
func readFollow(t *testing.T, conn *websocket.Conn) ([]string, error) {
	t.Helper()
	var frames []string
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		typ, data, err := conn.ReadMessage()
		if err != nil {
			return frames, err
		}
		if typ != websocket.BinaryMessage {
			t.Fatalf("frame type %d", typ)
		}
		frames = append(frames, string(data))
	}
}

// Follow sends the replay, then live frames, then a normal close when the
// command ends; a refused follow is a plain HTTP error, never an upgrade.
func TestProcessSessionFollow(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "c", Command: "mod", Running: true})
	frames := make(chan []byte, 2)
	closed := make(chan struct{})
	f.follow = &LogFollow{
		Replay: toolboxwire.LogReplay([]byte("old"), []byte("warn")),
		Frames: frames,
		Close:  func() { close(closed) },
	}
	srv := httptest.NewServer(New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: f}).Handler())
	defer srv.Close()
	header := http.Header{"Authorization": {"Bearer tok"}}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/process/session/s/command/c/logs?follow=true"), header)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frames <- toolboxwire.FrameLog(false, []byte("new"))
	close(frames)
	got, err := readFollow(t, conn)
	if len(got) != 2 || got[0] != "\x01\x01\x01old\x02\x02\x02warn" || got[1] != "\x01\x01\x01new" {
		t.Fatalf("frames = %q", got)
	}
	if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("end = %v, want a normal close", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("follow not closed")
	}

	for _, tc := range []struct {
		path   string
		err    error
		status int
	}{
		{"/process/session/s/command/nope/logs?follow=true", nil, http.StatusNotFound},
		{"/process/session/nope/command/c/logs?follow=true", nil, http.StatusNotFound},
		{"/process/session/s/command/c/logs?follow=true", ErrTooManyFollowers, http.StatusTooManyRequests},
		{"/process/session/entrypoint/logs?follow=true", ErrNoEntrypoint, http.StatusNotFound},
		{"/process/session/entrypoint/logs?follow=true", ErrEntrypointUnsupported, http.StatusNotImplemented},
	} {
		f.mu.Lock()
		f.followErr, f.entryErr = nil, nil
		if strings.Contains(tc.path, "entrypoint") {
			f.entryErr = tc.err
		} else {
			f.followErr = tc.err
		}
		f.mu.Unlock()
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv, tc.path), header)
		if err == nil {
			conn.Close()
			t.Fatalf("%s: upgraded", tc.path)
		}
		if resp == nil || resp.StatusCode != tc.status {
			t.Fatalf("%s: resp %+v err %v, want %d", tc.path, resp, err, tc.status)
		}
		resp.Body.Close()
	}
}

// A follower that leaves ends its subscription; a stopping sandbox (the
// request's context) ends the follow too.
func TestProcessSessionFollowEnds(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "c", Command: "mod", Running: true})
	closed := make(chan struct{})
	f.follow = &LogFollow{Frames: make(chan []byte), Close: func() { close(closed) }}
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: f})

	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Handler().ServeHTTP(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/process/session/s/command/c/logs?follow=true"), http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if _, err := readFollow(t, conn); err == nil || websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("stopped follow ended with %v, want a dropped connection", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("follow not closed after the sandbox stopped")
	}
}

// The entrypoint session is the sandbox's serving guest: one command,
// entrypoint_command, and its logs.
func TestProcessSessionEntrypoint(t *testing.T) {
	f := newFakeSessions()
	f.entry = EntrypointInfo{Command: "server --port 8080", Stdout: "listening\n", Stderr: "warn\n"}
	wantStatus(t, sessionCall(t, f, http.MethodGet, "/process/session/entrypoint", ""), http.StatusOK,
		`{"commands":[{"command":"server --port 8080","id":"entrypoint_command"}],"sessionId":"entrypoint"}`)
	wantStatus(t, sessionCall(t, f, http.MethodGet, "/process/session/entrypoint/logs", ""), http.StatusOK,
		`{"output":"listening\nwarn\n","stderr":"warn\n","stdout":"listening\n"}`)
	if len(f.entryLog) != 2 || f.entryLog[0] || !f.entryLog[1] {
		t.Fatalf("logs asked for = %v, want only by the logs route", f.entryLog)
	}
	f.entry.ExitCode = int32p(1)
	wantStatus(t, sessionCall(t, f, http.MethodGet, "/process/session/entrypoint", ""), http.StatusOK,
		`{"commands":[{"command":"server --port 8080","exitCode":1,"id":"entrypoint_command"}],"sessionId":"entrypoint"}`)
	for _, tc := range []struct {
		err    error
		status int
	}{{ErrNoEntrypoint, http.StatusNotFound}, {ErrEntrypointUnsupported, http.StatusNotImplemented}} {
		f.entryErr = tc.err
		for _, path := range []string{"/process/session/entrypoint", "/process/session/entrypoint/logs"} {
			wantStatus(t, sessionCall(t, f, http.MethodGet, path, ""), tc.status, "")
		}
	}

	// Following the entrypoint streams like a command's logs.
	f.entryErr = nil
	frames := make(chan []byte, 1)
	frames <- toolboxwire.FrameLog(true, []byte("late"))
	close(frames)
	f.follow = &LogFollow{Replay: toolboxwire.LogReplay([]byte("early"), nil), Frames: frames, Close: func() {}}
	srv := httptest.NewServer(New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: f}).Handler())
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/process/session/entrypoint/logs?follow=true"), http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := readFollow(t, conn)
	if len(got) != 2 || got[0] != "\x01\x01\x01early" || got[1] != "\x02\x02\x02late" || !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("entrypoint follow = %q, %v", got, err)
	}
}

func TestSessionErrorStatus(t *testing.T) {
	for err, want := range map[error]int{
		ErrSessionNotFound:       http.StatusNotFound,
		ErrCommandNotFound:       http.StatusNotFound,
		ErrNoEntrypoint:          http.StatusNotFound,
		ErrCommandNotRunning:     http.StatusConflict,
		ErrSessionStopped:        http.StatusConflict,
		ErrInputPending:          http.StatusConflict,
		ErrInputTimeout:          http.StatusRequestTimeout,
		ErrTooManySessions:       http.StatusTooManyRequests,
		ErrTooManyCommands:       http.StatusTooManyRequests,
		ErrTooManyFollowers:      http.StatusTooManyRequests,
		ErrTooManyProcesses:      http.StatusTooManyRequests,
		ErrEntrypointUnsupported: http.StatusNotImplemented,
		ErrStreamingUnsupported:  http.StatusNotImplemented,
		errors.New("other"):      http.StatusInternalServerError,
	} {
		if got := sessionErrorStatus(err); got != want {
			t.Errorf("%v -> %d, want %d", err, got, want)
		}
	}
}

// TestProcessSessionRequestCaps: what a session request carries ends up
// in sandboxd's heap, so bodies (1 MiB), command lines (64 KiB) and
// session ids (128) are capped, each with a status that says why.
func TestProcessSessionRequestCaps(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "run", Command: "mod", Running: true})
	jsonOf := func(field, value string) string { return `{"` + field + `":"` + value + `"}` }
	big := strings.Repeat("a", int(sessionMaxBody))
	tests := []struct {
		name, path, body string
		status           int
		want             string
	}{
		{"create body over the cap", "/process/session", jsonOf("sessionId", big), http.StatusRequestEntityTooLarge, `{"error":"request body is larger than 1048576 bytes"}`},
		{"id over the cap", "/process/session", jsonOf("sessionId", strings.Repeat("i", 129)), http.StatusBadRequest, `{"error":"sessionId is longer than 128 bytes"}`},
		{"id at the cap", "/process/session", jsonOf("sessionId", strings.Repeat("i", 128)), http.StatusCreated, ""},
		{"exec body over the cap", "/process/session/s/exec", jsonOf("command", big), http.StatusRequestEntityTooLarge, ""},
		{"command over the cap", "/process/session/s/exec", jsonOf("command", "mod "+strings.Repeat("c", 64<<10)), http.StatusBadRequest, `{"error":"command is longer than 65536 bytes"}`},
		{"command at the cap", "/process/session/s/exec", jsonOf("command", "mod "+strings.Repeat("c", 64<<10-4)), http.StatusOK, ""},
		{"input body over the cap", "/process/session/s/command/run/input", jsonOf("data", big), http.StatusRequestEntityTooLarge, ""},
		{"input just under the cap", "/process/session/s/command/run/input", jsonOf("data", big[:len(big)-16]), http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, sessionCall(t, f, http.MethodPost, tt.path, tt.body), tt.status, tt.want)
		})
	}
	if len(f.execs) != 1 || len(f.execs[0].Text) != 64<<10 {
		t.Fatalf("execs that reached Sessions: %d", len(f.execs))
	}
	if len(f.inputs) != 1 || len(f.sessions) != 2 {
		t.Fatalf("inputs %d, sessions %d: a refused request reached Sessions", len(f.inputs), len(f.sessions))
	}
}

// TestProcessSessionInputGivesUp: input hands Sessions the request's
// context, and a write the command does not take answers 408 (it waited
// too long) or 409 (an earlier input still waits), not a hang.
func TestProcessSessionInputGivesUp(t *testing.T) {
	f := newFakeSessions()
	f.addCommand("s", CommandInfo{ID: "run", Command: "mod", Running: true})
	for _, tc := range []struct {
		err    error
		status int
	}{
		{ErrInputTimeout, http.StatusRequestTimeout},
		{ErrInputPending, http.StatusConflict},
	} {
		f.inputErr = tc.err
		rec := sessionCall(t, f, http.MethodPost, "/process/session/s/command/run/input", `{"data":"x"}`)
		wantStatus(t, rec, tc.status, "")
		if !strings.Contains(rec.Body.String(), tc.err.Error()) {
			t.Fatalf("%v: body %s", tc.err, rec.Body.String())
		}
	}
	if f.inputCtx == nil {
		t.Fatal("input got no request context")
	}
}
