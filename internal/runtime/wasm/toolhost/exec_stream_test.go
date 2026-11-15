package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/gorilla/websocket"
)

// fakeProcs is a Processes whose runs the test drives by hand.
type fakeProcs struct {
	mu       sync.Mutex
	canErr   error
	startErr error
	specs    []StreamSpec
	codeRuns []CodeRunSpec
	runs     []*fakeRun
}

func (f *fakeProcs) CanStart() error { return f.canErr }

func (f *fakeProcs) StartStream(_ context.Context, spec StreamSpec) (ProcessStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, spec)
	if f.startErr != nil {
		return nil, f.startErr
	}
	return f.newRun(), nil
}

func (f *fakeProcs) StartCodeRun(_ context.Context, spec CodeRunSpec) (ProcessStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codeRuns = append(f.codeRuns, spec)
	if f.startErr != nil {
		return nil, f.startErr
	}
	return f.newRun(), nil
}

func (f *fakeProcs) newRun() *fakeRun {
	r := &fakeRun{events: make(chan ProcessEvent, 16), errs: make(chan error, 1), closed: make(chan struct{})}
	f.runs = append(f.runs, r)
	return r
}

func (f *fakeProcs) run(t *testing.T, i int) *fakeRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.runs) > i {
			r := f.runs[i]
			f.mu.Unlock()
			return r
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("run never started")
	return nil
}

type fakeRun struct {
	events    chan ProcessEvent
	errs      chan error
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	stdin     []byte
	stdinEOF  bool
	kills     int
}

func (r *fakeRun) Recv() (ProcessEvent, error) {
	select {
	case ev := <-r.events:
		return ev, nil
	case err := <-r.errs:
		return ProcessEvent{}, err
	case <-r.closed:
		return ProcessEvent{}, io.ErrClosedPipe
	}
}

func (r *fakeRun) WriteStdin(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stdin = append(r.stdin, p...)
	return nil
}

func (r *fakeRun) CloseStdin() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stdinEOF = true
	return nil
}

func (r *fakeRun) Kill() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kills++
	return nil
}

func (r *fakeRun) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}

func (r *fakeRun) snapshot() (string, bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.stdin), r.stdinEOF, r.kills
}

func (r *fakeRun) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-r.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("run was not closed")
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// streamServer serves the toolhost; wrap may replace the request context.
func streamServer(t *testing.T, procs Processes, wrap func(*http.Request) *http.Request) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wrap != nil {
			r = wrap(r)
		}
		h := New(Config{
			SandboxID:      "sb",
			WorkDir:        t.TempDir(),
			AuthToken:      "tok",
			Procs:          procs,
			StreamLiveness: toolboxwire.Liveness{PingInterval: 50 * time.Millisecond, PongWait: 2 * time.Second},
		})
		h.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/process/exec/stream"
}

func dialStream(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{Subprotocols: []string{toolboxwire.BearerSubprotocol}}
	conn, resp, err := dialer.Dial(url, http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != toolboxwire.BearerSubprotocol {
		t.Fatalf("subprotocol = %q", got)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func readControl(t *testing.T, conn *websocket.Conn) toolboxwire.ExecStreamControlOut {
	t.Helper()
	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("got binary frame %q, want a control frame", data)
	}
	var out toolboxwire.ExecStreamControlOut
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func readBinary(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("got text frame %s, want output", data)
	}
	return data
}

func TestExecStreamWithoutProcessesIs501(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir(), AuthToken: "tok"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.serveHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestExecStreamAtTheCapIs429BeforeUpgrade(t *testing.T) {
	url := streamServer(t, &fakeProcs{canErr: ErrTooManyProcesses}, nil)
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer tok"}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("dial = %v, resp %+v, want 429", err, resp)
	}
}

func TestExecStreamRunsAndStreams(t *testing.T) {
	procs := &fakeProcs{}
	conn := dialStream(t, streamServer(t, procs, nil))
	if err := conn.WriteJSON(toolboxwire.ExecStreamStart{
		Command: `python -c 'print(1 + 2)' "a b"`,
		Env:     map[string]string{"A": "1"},
		Workdir: "/work/sub/",
	}); err != nil {
		t.Fatal(err)
	}
	run := procs.run(t, 0)
	spec := procs.specs[0]
	if strings.Join(spec.Args, "|") != "python|-c|print(1 + 2)|a b" || !spec.Stdin || !spec.NoDeadline {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.Env["A"] != "1" || spec.Env["PWD"] != "/work/sub" {
		t.Fatalf("env = %v", spec.Env)
	}

	// Client to run: stdin, control frames.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("in")); err != nil {
		t.Fatal(err)
	}
	for _, ctrl := range []string{`not json`, `{"type":"resize","cols":10,"rows":5}`, `{"type":"signal","signal":"USR1"}`, `{"type":"close"}`} {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(ctrl)); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "stdin and EOF", func() bool {
		in, eof, _ := run.snapshot()
		return in == "in" && eof
	})
	if _, _, kills := run.snapshot(); kills != 0 {
		t.Fatal("an unknown signal killed the run")
	}

	// Run to client: prefixed output, then the exit.
	run.events <- ProcessEvent{Stdout: []byte("out")}
	run.events <- ProcessEvent{Stderr: []byte("err")}
	run.events <- ProcessEvent{Exit: &ProcessExit{ExitCode: 3}}
	if got := readBinary(t, conn); string(got) != "\x01out" {
		t.Fatalf("stdout frame = %q", got)
	}
	if got := readBinary(t, conn); string(got) != "\x02err" {
		t.Fatalf("stderr frame = %q", got)
	}
	if out := readControl(t, conn); out.Type != "exit" || out.Code != 3 || out.Signal != "" {
		t.Fatalf("exit = %+v", out)
	}
	run.waitClosed(t)
}

func TestExecStreamArgvSignalsAndExits(t *testing.T) {
	cases := []struct {
		name   string
		exit   ProcessExit
		frames []string
	}{
		{"clean", ProcessExit{}, []string{`{"type":"exit"}`}},
		{"killed", ProcessExit{ExitCode: -1, Killed: true}, []string{`{"type":"exit","code":-1,"signal":"killed"}`}},
		{"timed out", ProcessExit{ExitCode: -1, TimedOut: true}, []string{`{"type":"exit","code":-1,"signal":"killed"}`}},
		{"trap", ProcessExit{ExitCode: 1, Error: "wasm error: out of memory"}, []string{"\x02wasm error: out of memory\n", `{"type":"exit","code":1}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procs := &fakeProcs{}
			conn := dialStream(t, streamServer(t, procs, nil))
			if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Argv: []string{"prog", "a b", "$X"}}); err != nil {
				t.Fatal(err)
			}
			run := procs.run(t, 0)
			if strings.Join(procs.specs[0].Args, "|") != "prog|a b|$X" {
				t.Fatalf("argv = %q", procs.specs[0].Args)
			}
			// Every signal toolboxd knows ends a WASM run.
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"signal","signal":"int"}`)); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, "kill", func() bool { _, _, k := run.snapshot(); return k == 1 })
			exit := tc.exit
			run.events <- ProcessEvent{Exit: &exit}
			for _, want := range tc.frames {
				_, data, err := conn.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != want && strings.TrimSpace(string(data)) != want {
					t.Fatalf("frame = %q, want %q", data, want)
				}
			}
		})
	}
}

func TestExecStreamRefusesBadStarts(t *testing.T) {
	cases := []struct {
		start string
		want  string
	}{
		{`not json`, "invalid start message"},
		{`{"command":"top","tty":true}`, "terminals are not supported"},
		{`{"command":"ls","argv":["ls"]}`, "set command or argv, not both"},
		{`{}`, "command is required"},
		{`{"command":"   "}`, "command is required"},
		{`{"argv":[" "]}`, "argv[0] must name the program"},
		{`{"argv":["-x"]}`, "not an option"},
		{`{"command":"echo 'open"}`, "unterminated quote"},
		{`{"command":"ls","workdir":"/etc"}`, "workdir must be /work"},
		{`{"command":"ls","workdir":"/work/../etc"}`, "workdir must be /work"},
		{`{"command":"ls","workdir":"work"}`, "workdir must be /work"},
	}
	for _, tc := range cases {
		procs := &fakeProcs{}
		conn := dialStream(t, streamServer(t, procs, nil))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(tc.start)); err != nil {
			t.Fatal(err)
		}
		if out := readControl(t, conn); out.Type != "error" || !strings.Contains(out.Message, tc.want) {
			t.Fatalf("%s: frame = %+v, want error containing %q", tc.start, out, tc.want)
		}
		if len(procs.specs) != 0 {
			t.Fatalf("%s: a refused start reached Processes", tc.start)
		}
	}
	// An explicit PWD is kept; /work itself is fine.
	procs := &fakeProcs{}
	conn := dialStream(t, streamServer(t, procs, nil))
	if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "ls", Workdir: "/work", Env: map[string]string{"PWD": "/work/x"}}); err != nil {
		t.Fatal(err)
	}
	procs.run(t, 0)
	if procs.specs[0].Env["PWD"] != "/work/x" {
		t.Fatalf("env = %v", procs.specs[0].Env)
	}
}

func TestExecStreamStartFailures(t *testing.T) {
	procs := &fakeProcs{startErr: ErrTooManyProcesses}
	conn := dialStream(t, streamServer(t, procs, nil))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "ls"})
	if out := readControl(t, conn); out.Type != "error" || !strings.Contains(out.Message, "maximum number of processes") {
		t.Fatalf("frame = %+v", out)
	}
	_, _, err := conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf("close = %v, want 1008", err)
	}

	procs = &fakeProcs{startErr: errors.New("compile module: boom")}
	conn = dialStream(t, streamServer(t, procs, nil))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "ls"})
	if out := readControl(t, conn); out.Type != "error" || out.Message != "compile module: boom" {
		t.Fatalf("frame = %+v", out)
	}
}

func TestExecStreamClientDropKillsTheRun(t *testing.T) {
	procs := &fakeProcs{}
	conn := dialStream(t, streamServer(t, procs, nil))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "spin"})
	run := procs.run(t, 0)
	_ = conn.Close()
	run.waitClosed(t)
	if _, _, kills := run.snapshot(); kills != 1 {
		t.Fatalf("kills = %d, want 1", kills)
	}
}

func TestExecStreamSandboxStopEndsTheRun(t *testing.T) {
	procs := &fakeProcs{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := dialStream(t, streamServer(t, procs, func(r *http.Request) *http.Request { return r.WithContext(ctx) }))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "spin"})
	run := procs.run(t, 0)
	cancel()
	if out := readControl(t, conn); out.Type != "error" || out.Message != "the sandbox stopped" {
		t.Fatalf("frame = %+v", out)
	}
	run.waitClosed(t)
	if _, _, kills := run.snapshot(); kills != 1 {
		t.Fatalf("kills = %d", kills)
	}
}

func TestExecStreamRecvErrorAndWriteFailure(t *testing.T) {
	procs := &fakeProcs{}
	conn := dialStream(t, streamServer(t, procs, nil))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "x"})
	run := procs.run(t, 0)
	run.errs <- errors.New("worker gone")
	if out := readControl(t, conn); out.Type != "error" || out.Message != "stream ended: worker gone" {
		t.Fatalf("frame = %+v", out)
	}

	// Output for a client that has gone: the run is ended.
	procs = &fakeProcs{}
	conn = dialStream(t, streamServer(t, procs, nil))
	_ = conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "x"})
	run = procs.run(t, 0)
	_ = conn.UnderlyingConn().Close()
	for i := 0; i < 50; i++ {
		select {
		case run.events <- ProcessEvent{Stdout: []byte(strings.Repeat("x", 4096)), Stderr: []byte("e")}:
		case <-run.closed:
		}
	}
	run.waitClosed(t)
}

func TestHandleExecStreamUpgradeRequiresWebSocket(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir(), Procs: &fakeProcs{}})
	rec := httptest.NewRecorder()
	h.handleExecStream(rec, httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil))
	if rec.Code == http.StatusOK || rec.Code == http.StatusSwitchingProtocols {
		t.Fatalf("plain GET upgraded: %d", rec.Code)
	}
}

func TestStreamLivenessDefaults(t *testing.T) {
	if got := (&Host{}).streamLiveness(); got != toolboxwire.DefaultLiveness {
		t.Fatalf("default = %+v", got)
	}
	got := (&Host{liveness: toolboxwire.Liveness{PingInterval: time.Second, PongWait: 2 * time.Second}}).streamLiveness()
	if got.PingWriteWait != toolboxwire.DefaultLiveness.PingWriteWait || got.PingInterval != time.Second {
		t.Fatalf("override = %+v", got)
	}
}

func TestRequireAuthComparesTokens(t *testing.T) {
	h := New(Config{SandboxID: "sb", AuthToken: "secret-token"})
	for _, tc := range []struct {
		header string
		ok     bool
	}{
		{"Bearer secret-token", true},
		{"Bearer secret-tokem", false}, // same length, last byte differs
		{"Bearer secret", false},
		{"Bearer secret-token-longer", false},
		{"secret-token", false},
		{"Basic secret-token", false},
		{"", false},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		if got := h.requireAuth(rec, req); got != tc.ok {
			t.Fatalf("%q: requireAuth = %v, want %v", tc.header, got, tc.ok)
		}
		if !tc.ok && rec.Code != http.StatusUnauthorized {
			t.Fatalf("%q: status %d", tc.header, rec.Code)
		}
	}
}

// tunedStreamServer is streamServer with the host's stream settings
// tuned, and a channel that receives once per handler that returned.
func tunedStreamServer(t *testing.T, procs Processes, ctx context.Context, tune func(*Config)) (string, <-chan struct{}) {
	t.Helper()
	handled := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { handled <- struct{}{} }()
		if ctx != nil {
			r = r.WithContext(ctx)
		}
		cfg := Config{SandboxID: "sb", WorkDir: t.TempDir(), AuthToken: "tok", Procs: procs,
			// Long enough that only the setting under test ends a stream.
			StreamLiveness: toolboxwire.Liveness{PingInterval: time.Minute, PongWait: time.Minute}}
		if tune != nil {
			tune(&cfg)
		}
		New(cfg).Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/process/exec/stream", handled
}

func waitHandled(t *testing.T, handled <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-handled:
	case <-time.After(within):
		t.Fatalf("the stream handler did not return within %s", within)
	}
}

// fillUntilStuck feeds a run's output to a client that never reads, until
// the handler's write blocks (the run's event queue stays full).
func fillUntilStuck(t *testing.T, run *fakeRun) {
	t.Helper()
	chunk := make([]byte, 1<<20)
	for i := 0; i < 512; i++ {
		select {
		case run.events <- ProcessEvent{Stdout: chunk}:
		case <-time.After(300 * time.Millisecond):
			return
		case <-run.closed:
			t.Fatal("the run ended before the handler's write blocked")
		}
	}
	t.Fatal("the handler never blocked writing to a client that does not read")
}

// TestExecStreamCapsClientMessages: one client message is read whole
// into sandboxd's heap, so its size is capped (1 MiB by default, close
// code 1009 past it) and the run ends with the stream.
func TestExecStreamCapsClientMessages(t *testing.T) {
	if got := (&Host{}).streamReadLimitBytes(); got != DefaultStreamReadLimit || DefaultStreamReadLimit != 1<<20 {
		t.Fatalf("default read limit = %d", got)
	}
	for _, tc := range []struct {
		name  string
		limit int64
		size  int
	}{
		{"default", 0, 1<<20 + 1},
		{"configured", 1024, 1025},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procs := &fakeProcs{}
			url, handled := tunedStreamServer(t, procs, nil, func(c *Config) { c.StreamReadLimit = tc.limit })
			conn := dialStream(t, url)
			if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "cat"}); err != nil {
				t.Fatal(err)
			}
			run := procs.run(t, 0)
			// At the limit is fine.
			if err := conn.WriteMessage(websocket.BinaryMessage, make([]byte, tc.size-1)); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, "stdin at the limit", func() bool { in, _, _ := run.snapshot(); return len(in) == tc.size-1 })
			_ = conn.WriteMessage(websocket.BinaryMessage, make([]byte, tc.size))
			_, _, err := conn.ReadMessage()
			var closeErr *websocket.CloseError
			if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
				t.Fatalf("read after an oversized message = %v, want close 1009", err)
			}
			run.waitClosed(t)
			waitHandled(t, handled, 5*time.Second)
			if in, _, kills := run.snapshot(); len(in) != tc.size-1 || kills != 1 {
				t.Fatalf("stdin %d bytes, kills %d: the oversized message reached the run", len(in), kills)
			}
		})
	}
}

// TestExecStreamCutsOffAClientThatStopsReading: each frame has a write
// deadline, so a client that stops reading (but keeps its connection up)
// ends the stream and the run instead of holding the handler forever.
func TestExecStreamCutsOffAClientThatStopsReading(t *testing.T) {
	if got := (&Host{}).streamWriteWaitTime(); got != defaultStreamWriteWait {
		t.Fatalf("default write wait = %s", got)
	}
	procs := &fakeProcs{}
	url, handled := tunedStreamServer(t, procs, nil, func(c *Config) { c.StreamWriteWait = 200 * time.Millisecond })
	conn := dialStream(t, url)
	if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "yes"}); err != nil {
		t.Fatal(err)
	}
	run := procs.run(t, 0)
	chunk := make([]byte, 1<<20)
	go func() {
		for {
			select {
			case run.events <- ProcessEvent{Stdout: chunk}:
			case <-run.closed:
				return
			}
		}
	}()
	run.waitClosed(t)
	waitHandled(t, handled, 5*time.Second)
	if _, _, kills := run.snapshot(); kills != 1 {
		t.Fatalf("kills = %d, want 1", kills)
	}
}

// TestExecStreamSandboxStopFreesAStuckWriter: a sandbox that stops while
// the handler is stuck writing to a client that stopped reading closes the
// client's connection (after a short grace), so the handler returns well
// before its write deadline.
func TestExecStreamSandboxStopFreesAStuckWriter(t *testing.T) {
	procs := &fakeProcs{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url, handled := tunedStreamServer(t, procs, ctx, func(c *Config) { c.StreamWriteWait = time.Hour })
	conn := dialStream(t, url)
	if err := conn.WriteJSON(toolboxwire.ExecStreamStart{Command: "yes"}); err != nil {
		t.Fatal(err)
	}
	run := procs.run(t, 0)
	fillUntilStuck(t, run)
	cancel()
	run.waitClosed(t)
	waitHandled(t, handled, streamStopGrace+5*time.Second)
	if _, _, kills := run.snapshot(); kills != 1 {
		t.Fatalf("kills = %d, want 1", kills)
	}
}
