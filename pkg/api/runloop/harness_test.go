package runloop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// fakeRuntime is a minimal runtime.Runtime. Every sandbox gets ContainerIP
// 127.0.0.1 so toolbox calls land on the fakeToolbox listener.
type fakeRuntime struct {
	mu          sync.Mutex
	states      map[string]*models.SandboxRuntimeState
	creates     int
	errCreate   error
	errSnapshot error
	blockCreate chan struct{}
	imageSeq    int
	lastReq     models.CreateSandboxRequest

	blockSnapshot chan struct{}
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{states: make(map[string]*models.SandboxRuntimeState)}
}

func (f *fakeRuntime) Create(_ context.Context, req models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if f.blockCreate != nil {
		<-f.blockCreate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = req
	if f.errCreate != nil {
		return nil, f.errCreate
	}
	f.creates++
	state := &models.SandboxRuntimeState{SandboxID: sandboxID, ContainerID: "ctr-" + sandboxID, ContainerIP: "127.0.0.1", Status: models.SandboxStatusStarted}
	f.states[sandboxID] = state
	cp := *state
	return &cp, nil
}

func (f *fakeRuntime) Start(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(ref)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", ref)
	}
	state.Status = models.SandboxStatusStarted
	cp := *state
	return &cp, nil
}

func (f *fakeRuntime) Stop(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(ref)
	if !ok {
		return fmt.Errorf("sandbox %q not found", ref)
	}
	state.Status = models.SandboxStatusStopped
	return nil
}

func (f *fakeRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sandbox != nil {
		delete(f.states, sandbox.ID)
	}
	return nil
}

func (f *fakeRuntime) CreateSnapshot(_ context.Context, _ string, imageRef string) (string, error) {
	if f.blockSnapshot != nil {
		<-f.blockSnapshot
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errSnapshot != nil {
		return "", f.errSnapshot
	}
	f.imageSeq++
	return fmt.Sprintf("sha256:img-%03d", f.imageSeq), nil
}

func (f *fakeRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error { return nil }

func (f *fakeRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(ref)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", ref)
	}
	cp := *state
	return &cp, nil
}

func (f *fakeRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(f.states))
	for id, state := range f.states {
		cp := *state
		out[id] = &cp
	}
	return out, nil
}

func (f *fakeRuntime) Ping(context.Context) error                                    { return nil }
func (f *fakeRuntime) RemoveImage(context.Context, string) error                     { return nil }
func (f *fakeRuntime) PushAllowedPorts(context.Context, string, string, []int) error { return nil }
func (f *fakeRuntime) ClearNetworkRules(string) error                                { return nil }
func (f *fakeRuntime) ApplyEgressPolicy(string, []string, []string) error            { return nil }
func (f *fakeRuntime) ClearEgressPolicy(string, []string, []string) error            { return nil }
func (f *fakeRuntime) ApplyNetworkBlockAll(string) error                             { return nil }
func (f *fakeRuntime) ApplyNetworkBlockIngress(string) error                         { return nil }
func (f *fakeRuntime) ClearNetworkBlockIngress(string) error                         { return nil }
func (f *fakeRuntime) ClearNetworkBlockEgress(string) error                          { return nil }

func (f *fakeRuntime) lookup(ref string) (*models.SandboxRuntimeState, bool) {
	if state, ok := f.states[ref]; ok {
		return state, true
	}
	for _, state := range f.states {
		if state.ContainerID == ref {
			return state, true
		}
	}
	return nil, false
}

// fakeToolbox is an in-memory toolboxd: the session API, /process/execute
// and the file endpoints. A command's outcome comes from script; a command
// starting with "block" stays running until release(command) is called.
type fakeToolbox struct {
	mu       sync.Mutex
	sessions map[string]*fakeSession
	files    map[string][]byte
	cmdSeq   int
	release  map[string]chan struct{}
	inputs   []string
	failNext map[string]int // path → status to fail the next request with
	execs    int
}

type fakeSession struct {
	commands []*fakeCommand
}

type fakeCommand struct {
	id       string
	command  string
	exitCode *int32
	stdout   string
	stderr   string
}

func newFakeToolbox() *fakeToolbox {
	return &fakeToolbox{
		sessions: make(map[string]*fakeSession),
		files:    make(map[string][]byte),
		release:  make(map[string]chan struct{}),
		failNext: make(map[string]int),
	}
}

// script decides a command's result.
func script(command string) (stdout, stderr string, exit int32) {
	switch {
	case strings.HasPrefix(command, "echo "):
		return strings.TrimPrefix(command, "echo ") + "\n", "", 0
	case strings.HasPrefix(command, "exit "):
		n, _ := strconv.Atoi(strings.TrimPrefix(command, "exit "))
		return "", "exiting\n", int32(n)
	case strings.HasPrefix(command, "lines "):
		n, _ := strconv.Atoi(strings.TrimPrefix(command, "lines "))
		var b strings.Builder
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&b, "line %d\n", i)
		}
		return b.String(), "", 0
	default:
		return "ran: " + command + "\n", "", 0
	}
}

func (f *fakeToolbox) setFailNext(path string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[path] = status
}

func (f *fakeToolbox) unblock(command string) {
	f.mu.Lock()
	ch, ok := f.release[command]
	if !ok {
		ch = make(chan struct{})
		f.release[command] = ch
	}
	f.mu.Unlock()
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (f *fakeToolbox) sessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

func (f *fakeToolbox) execCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.execs
}

func (f *fakeToolbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if status, ok := f.failNext[r.URL.Path]; ok {
		delete(f.failNext, r.URL.Path)
		f.mu.Unlock()
		http.Error(w, `{"error":"injected failure"}`, status)
		return
	}
	f.mu.Unlock()

	path := r.URL.Path
	switch {
	case path == "/health":
		w.WriteHeader(http.StatusOK)
	case path == "/process/execute":
		var req models.ExecRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusOK, models.ExecResult{Stdout: "/home/user", ExitCode: 0})
	case path == "/process/session" && r.Method == http.MethodPost:
		var req struct {
			SessionID string `json:"sessionId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		_, exists := f.sessions[req.SessionID]
		if !exists {
			f.sessions[req.SessionID] = &fakeSession{}
		}
		f.mu.Unlock()
		if exists {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	case strings.HasPrefix(path, "/process/session/"):
		f.serveSession(w, r, strings.TrimPrefix(path, "/process/session/"))
	case path == "/files/upload":
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, `{"error":"bad form"}`, http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, `{"error":"file is required"}`, http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(file)
		f.mu.Lock()
		f.files[r.URL.Query().Get("path")] = data
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]string{"path": r.URL.Query().Get("path")})
	case path == "/files/download":
		f.mu.Lock()
		data, ok := f.files[r.URL.Query().Get("path")]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"no such file"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (f *fakeToolbox) serveSession(w http.ResponseWriter, r *http.Request, rest string) {
	sid, action, _ := strings.Cut(rest, "/")
	f.mu.Lock()
	sess, ok := f.sessions[sid]
	f.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		f.mu.Lock()
		out := toolboxSession{SessionID: sid, Commands: []toolboxCommand{}}
		for _, cmd := range sess.commands {
			out.Commands = append(out.Commands, toolboxCommand{Command: cmd.command, ExitCode: cmd.exitCode, ID: cmd.id})
		}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, out)
	case action == "" && r.Method == http.MethodDelete:
		f.mu.Lock()
		delete(f.sessions, sid)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case action == "exec":
		var req struct {
			Command string `json:"command"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.cmdSeq++
		f.execs++
		cmd := &fakeCommand{id: fmt.Sprintf("%016x", f.cmdSeq), command: req.Command}
		sess.commands = append(sess.commands, cmd)
		var wait chan struct{}
		if strings.HasPrefix(req.Command, "block") {
			wait = f.release[req.Command]
			if wait == nil {
				wait = make(chan struct{})
				f.release[req.Command] = wait
			}
		}
		f.mu.Unlock()
		finish := func() {
			stdout, stderr, exit := script(req.Command)
			f.mu.Lock()
			cmd.stdout, cmd.stderr, cmd.exitCode = stdout, stderr, &exit
			f.mu.Unlock()
		}
		if wait != nil {
			go func() { <-wait; finish() }()
		} else {
			finish()
		}
		writeJSON(w, http.StatusOK, map[string]string{"cmdId": cmd.id})
	case strings.HasPrefix(action, "command/"):
		cid, sub, _ := strings.Cut(strings.TrimPrefix(action, "command/"), "/")
		f.mu.Lock()
		var cmd *fakeCommand
		for _, c := range sess.commands {
			if c.id == cid {
				cmd = c
			}
		}
		if cmd == nil {
			f.mu.Unlock()
			http.Error(w, `{"error":"command not found"}`, http.StatusNotFound)
			return
		}
		snapshot := *cmd
		f.mu.Unlock()
		switch sub {
		case "":
			writeJSON(w, http.StatusOK, toolboxCommand{Command: snapshot.command, ExitCode: snapshot.exitCode, ID: snapshot.id})
		case "logs":
			writeJSON(w, http.StatusOK, map[string]string{"stdout": snapshot.stdout, "stderr": snapshot.stderr, "output": snapshot.stdout + snapshot.stderr})
		case "input":
			var req struct {
				Data string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.mu.Lock()
			f.inputs = append(f.inputs, req.Data)
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

type testEnv struct {
	svc     *service.Service
	store   *store.Store
	runtime *fakeRuntime
	toolbox *fakeToolbox
	handler http.Handler
	h       *handlers
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	t.Setenv(blueprintMapEnv, `{"python":"python:3.12"}`)

	toolbox := newFakeToolbox()
	toolboxServer := httptest.NewServer(toolbox)
	t.Cleanup(toolboxServer.Close)
	u, _ := url.Parse(toolboxServer.URL)
	_, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{RootDir: filepath.Join(dir, "mounts"), CredDir: filepath.Join(dir, "creds"), WaitTimeout: time.Second})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mountManager.Close)
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}
	cfg := config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: port, HTTPClientTimeout: 5 * time.Second}
	rt := newFakeRuntime()
	svc := service.New(cfg, logger, st, rt, nil, caddy.New(cfg), cipher, mountManager, nil)

	deps := Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler { return next }}
	h := newHandlers(deps)
	mux := http.NewServeMux()
	mux.Handle(devboxesPath, http.HandlerFunc(h.route))
	mux.Handle(devboxesPath+"/", http.HandlerFunc(h.route))
	return &testEnv{svc: svc, store: st, runtime: rt, toolbox: toolbox, handler: mux, h: h}
}

// do sends a request and decodes a JSON response into out (when non-nil).
func (e *testEnv) do(t *testing.T, method, path string, body any, out any, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, devboxesPath+path, reader)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	if out != nil && rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", method, path, rr.Body.String(), err)
		}
	}
	return rr
}

func (e *testEnv) mustCreate(t *testing.T, body any, headers ...string) devboxView {
	t.Helper()
	var view devboxView
	rr := e.do(t, http.MethodPost, "/create_and_await_running", body, &view, headers...)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", rr.Code, rr.Body.String())
	}
	if view.Status != statusRunning {
		t.Fatalf("create status = %q, want running", view.Status)
	}
	return view
}

func expectStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, want, rr.Body.String())
	}
}
