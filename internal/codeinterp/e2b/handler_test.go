package e2b

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// splitLines checks the NDJSON framing (every line ends in a newline, no
// line is blank, the JavaScript SDK's JSON.parse throws on one) and returns
// the lines.
func splitLines(t *testing.T, body string) []string {
	t.Helper()
	if !strings.HasSuffix(body, "\n") {
		t.Fatalf("body does not end in a newline: %q", body)
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			t.Fatalf("line %d is blank in %q", i, body)
		}
		if !json.Valid([]byte(l)) {
			t.Fatalf("line %d is not JSON: %q", i, l)
		}
	}
	return lines
}

func TestExecuteStreamsEventsInOrder(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	rec := e.do(http.MethodPost, "/execute", `{"code":"all"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content type = %q", ct)
	}
	want := []string{
		`{"type":"number_of_executions","execution_count":1}`,
		`{"type":"stdout","text":"a\n","timestamp":"` + testStamp + `"}`,
		`{"type":"stderr","text":"b\n","timestamp":"` + testStamp + `"}`,
		`{"type":"result","png":"iVBO","extra":{},"is_main_result":false}`,
		`{"type":"result","text":"x","html":"<b>x</b>","extra":{},"is_main_result":true}`,
		`{"type":"error","name":"ValueError","value":"bad","traceback":"tb"}`,
		`{"type":"end_of_execution"}`,
	}
	got := splitLines(t, rec.Body.String())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestExecuteBodyValidation(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		status   int
		ctype    string
		wantBody string
	}{
		{name: "not JSON", body: `{"code":`, status: 422, ctype: "application/json", wantBody: `"json_invalid"`},
		{name: "empty body", body: ``, status: 422, ctype: "application/json", wantBody: `{"detail":[{"type":"missing","loc":["body"],"msg":"Field required"}]}`},
		{name: "no code", body: `{}`, status: 422, ctype: "application/json", wantBody: `{"detail":[{"type":"missing","loc":["body","code"],"msg":"Field required"}]}`},
		{name: "code not a string", body: `{"code":1}`, status: 422, ctype: "application/json", wantBody: `{"detail":[{"type":"type_error","loc":["body","code"],"msg":"Input should be a valid string"}]}`},
		{name: "env not an object", body: `{"code":"x","env_vars":"A=1"}`, status: 422, ctype: "application/json", wantBody: `"msg":"Input should be a valid object"`},
		{name: "body not an object", body: `[1]`, status: 422, ctype: "application/json", wantBody: `{"detail":[{"type":"type_error","loc":["body"],"msg":"Input should be a valid object"}]}`},
		{name: "env value not a string", body: `{"code":"x","env_vars":{"A":1}}`, status: 422, ctype: "application/json", wantBody: `"msg":"Input should be a valid string"`},
		{name: "both context and language", body: `{"code":"x","context_id":"c","language":"python"}`, status: 400, ctype: "text/plain; charset=utf-8", wantBody: "Only one of context_id or language can be provided"},
		{name: "unknown context", body: `{"code":"x","context_id":"nope"}`, status: 404, ctype: "text/plain; charset=utf-8", wantBody: "Context nope not found"},
		{name: "unsupported language", body: `{"code":"x","language":"cobol"}`, status: 400, ctype: "text/plain; charset=utf-8", wantBody: `unsupported language: "cobol"`},
		// The Python SDK sends every field, with nulls for the unset ones.
		{name: "explicit nulls", body: `{"code":"x","context_id":null,"language":null,"env_vars":null}`, status: 200, ctype: "application/x-ndjson", wantBody: `"text":"x"`},
		{name: "empty strings mean unset", body: `{"code":"x","context_id":"","language":""}`, status: 200, ctype: "application/x-ndjson", wantBody: `"text":"x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, time.Hour)
			rec := e.do(http.MethodPost, "/execute", tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.status)
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.ctype {
				t.Fatalf("content type = %q, want %q", ct, tc.ctype)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %q, want it to contain %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestExecuteBodyLimitsAndReadErrors(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	e.h.maxBody = 16
	rec := e.do(http.MethodPost, "/execute", `{"code":"`+strings.Repeat("x", 64)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "larger than 16 bytes") {
		t.Fatalf("oversized body: %d %q", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/execute", nil)
	req.Body = failingBody{}
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || rr.Body.String() != "failed to read the request body" {
		t.Fatalf("unreadable body: %d %q", rr.Code, rr.Body.String())
	}
}

func TestExecuteChoosesTheContext(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	created := e.do(http.MethodPost, "/contexts", `{"language":"bash","cwd":"/srv"}`)
	var ctx contextResponse
	if err := json.Unmarshal(created.Body.Bytes(), &ctx); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, body, want string
	}{
		{name: "no language or context is the python default", body: `{"code":"whoami"}`, want: "python /home/user"},
		{name: "language picks that language's default", body: `{"code":"whoami","language":" JS "}`, want: "javascript /home/user"},
		{name: "typescript alias", body: `{"code":"whoami","language":"ts"}`, want: "typescript /home/user"},
		{name: "context id", body: `{"code":"whoami","context_id":"` + ctx.ID + `"}`, want: "bash /srv"},
		{name: "per-run env", body: `{"code":"env","env_vars":{"K":"v1"}}`, want: `"text":"v1"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The query string is ignored, as on E2B.
			rec := e.do(http.MethodPost, "/execute?ignored=1", tc.body)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("%d %s, want %q", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
	// The python default ran twice (no language, then env) on one kernel.
	var py *fakeKernel
	for _, k := range e.l.kernels() {
		if k.spec.Language == codeinterp.LangPython && k.spec.Cwd == "/home/user" {
			py = k
		}
	}
	if runs, _, _ := py.state(); runs != 2 {
		t.Fatalf("python default ran %d times, want 2 on one kernel", runs)
	}
}

func TestDefaultsRegisteredOnFirstRequest(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	if rec := e.do(http.MethodGet, "/health", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if len(e.l.kernels()) != 0 {
		t.Fatal("registering the defaults must not start a kernel")
	}
	created := e.do(http.MethodPost, "/contexts", `{}`)
	var user contextResponse
	_ = json.Unmarshal(created.Body.Bytes(), &user)

	rec := e.do(http.MethodGet, "/contexts", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("list: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var list []contextResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Language != "python" || list[1].Language != "javascript" || list[2] != user {
		t.Fatalf("list = %+v, want python and javascript defaults first, then %+v", list, user)
	}
	for _, c := range list[:2] {
		if c.Cwd != "/home/user" || len(c.ID) != 36 {
			t.Fatalf("default %+v, want a UUID id and /home/user", c)
		}
	}
	// The JavaScript SDK reads the list with res.json(): never null.
	empty := newTestEnv(t, time.Hour)
	_ = empty.m.Delete(empty.mustDefault(t, "python"))
	_ = empty.m.Delete(empty.mustDefault(t, "javascript"))
	if got := empty.do(http.MethodGet, "/contexts", "").Body.String(); got != "[]" {
		t.Fatalf("empty list = %q, want []", got)
	}
}

func (e *testEnv) mustDefault(t *testing.T, lang string) string {
	t.Helper()
	// Any request registers the defaults first.
	e.do(http.MethodGet, "/health", "")
	info, err := e.m.Default(lang)
	if err != nil {
		t.Fatal(err)
	}
	return info.ID
}

func TestDefaultsRegistrationFailureIsNotFatal(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	// Take every slot so the first request cannot register the defaults.
	full := codeinterp.NewManager(codeinterp.Options{Launcher: e.l, Limit: e.lim})
	t.Cleanup(full.Close)
	for i := 0; i < 8; i++ {
		if _, err := full.Create(context.Background(), "python", ""); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.do(http.MethodGet, "/contexts", "").Body.String(); got != "[]" {
		t.Fatalf("list = %q", got)
	}
	rec := e.do(http.MethodPost, "/execute", `{"code":"x"}`)
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != "Failed to create context: too many interpreter contexts" {
		t.Fatalf("execute with a full sandbox: %d %q", rec.Code, rec.Body.String())
	}
}

func TestContextRoutes(t *testing.T) {
	e := newTestEnv(t, time.Hour)

	rec := e.do(http.MethodPost, "/contexts", `{"language":"js","cwd":"/tmp"}`)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var js contextResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &js); err != nil {
		t.Fatal(err)
	}
	if js.Language != "javascript" || js.Cwd != "/tmp" || js.ID == "" {
		t.Fatalf("create = %+v", js)
	}
	if !strings.HasPrefix(rec.Body.String(), `{"id":`) {
		t.Fatalf("create body %s must lead with id", rec.Body.String())
	}

	// An empty body is {}: python in the default cwd.
	rec = e.do(http.MethodPost, "/contexts", ``)
	var py contextResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &py)
	if rec.Code != http.StatusOK || py.Language != "python" || py.Cwd != "/home/user" {
		t.Fatalf("create with no body: %d %+v", rec.Code, py)
	}

	// Restart keeps the id and starts a fresh kernel in the same cwd.
	before := len(e.l.kernels())
	rec = e.do(http.MethodPost, "/contexts/"+js.ID+"/restart", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "null" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("restart: %d %q", rec.Code, rec.Body.String())
	}
	ks := e.l.kernels()
	if len(ks) != before+1 || ks[len(ks)-1].spec.Cwd != "/tmp" {
		t.Fatalf("restart launched %d kernels (cwd %q)", len(ks)-before, ks[len(ks)-1].spec.Cwd)
	}

	rec = e.do(http.MethodDelete, "/contexts/"+js.ID, "")
	if rec.Code != http.StatusOK || rec.Body.String() != "null" {
		t.Fatalf("delete: %d %q", rec.Code, rec.Body.String())
	}
	for _, id := range e.contextIDs() {
		if id == js.ID {
			t.Fatal("deleted context still listed")
		}
	}

	notFound := []struct{ method, path string }{
		{http.MethodDelete, "/contexts/" + js.ID},
		{http.MethodPost, "/contexts/" + js.ID + "/restart"},
	}
	for _, nf := range notFound {
		rec := e.do(nf.method, nf.path, "")
		if rec.Code != http.StatusNotFound || rec.Body.String() != "Context "+js.ID+" not found" ||
			rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("%s %s: %d %q", nf.method, nf.path, rec.Code, rec.Body.String())
		}
	}

	// A deleted default is replaced on next use, not resurrected.
	defaultPy := e.mustDefault(t, "python")
	if rec := e.do(http.MethodDelete, "/contexts/"+defaultPy, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete default: %d", rec.Code)
	}
	if again := e.mustDefault(t, "python"); again == defaultPy {
		t.Fatal("a deleted default came back with the same id")
	}
}

func TestContextCreateErrors(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		fail   error
		fill   bool
		status int
		want   string
	}{
		{name: "bad JSON", body: `{"language":`, status: 422, want: `"json_invalid"`},
		{name: "language not a string", body: `{"language":3}`, status: 422, want: `"loc":["body","language"]`},
		{name: "unsupported language", body: `{"language":"cobol"}`, status: 400, want: `Failed to create context: unsupported language: "cobol"`},
		{name: "missing interpreter", body: `{"language":"r"}`, fail: &codeinterp.MissingInterpreterError{Language: "r", Programs: []string{"Rscript"}}, status: 500,
			want: "Failed to create context: r interpreter not found in the sandbox (looked for [Rscript])"},
		{name: "sandbox full", body: `{}`, fill: true, status: 429, want: "Failed to create context: too many interpreter contexts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, time.Hour)
			e.do(http.MethodGet, "/health", "") // registers the two defaults
			if tc.fill {
				for i := 0; i < 6; i++ {
					if rec := e.do(http.MethodPost, "/contexts", `{}`); rec.Code != http.StatusOK {
						t.Fatalf("fill %d: %d", i, rec.Code)
					}
				}
			}
			e.l.setFail(tc.fail)
			rec := e.do(http.MethodPost, "/contexts", tc.body)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("%d %q, want %d %q", rec.Code, rec.Body.String(), tc.status, tc.want)
			}
		})
	}
}

func TestRestartLaunchFailure(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	var c contextResponse
	_ = json.Unmarshal(e.do(http.MethodPost, "/contexts", `{}`).Body.Bytes(), &c)
	e.l.setFail(errors.New("no memory"))
	rec := e.do(http.MethodPost, "/contexts/"+c.ID+"/restart", "")
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "Failed to restart context "+c.ID+": "+internalErrorText {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestClosedManager(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	e.m.Close()
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/execute", `{"code":"x"}`},
		{http.MethodPost, "/contexts", `{}`},
		{http.MethodDelete, "/contexts/x", ``},
		{http.MethodPost, "/contexts/x/restart", ``},
	}
	for _, tc := range cases {
		if rec := e.do(tc.method, tc.path, tc.body); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d %q, want 503", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestHealth(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	rec := e.do(http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK || rec.Body.String() != `"OK"` || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	if rec := e.do(http.MethodGet, "/execute", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /execute = %d, want 405", rec.Code)
	}
}

func TestRunEndsAfterKernelDiesOrContextRestarts(t *testing.T) {
	restarting := `{"type":"error","name":"ContextRestarting","value":"Context was restarted","traceback":""}`
	cases := []struct {
		name   string
		code   string
		method string
		path   string
		want   string
	}{
		{name: "kernel died", code: "die",
			want: `{"type":"error","name":"UnexpectedEndOfExecution","value":"Connection to the execution was closed before the execution was finished","traceback":""}`},
		{name: "restarted mid-run", code: "ignore", method: http.MethodPost, path: "/restart", want: restarting},
		{name: "deleted mid-run", code: "ignore", method: http.MethodDelete, want: restarting},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, time.Hour)
			id := e.mustDefault(t, "python")
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- e.do(http.MethodPost, "/execute", `{"code":"`+tc.code+`"}`) }()
			if tc.method != "" {
				waitFor(t, "the run to start", func() bool {
					ks := e.l.kernels()
					if len(ks) == 0 {
						return false
					}
					_, _, running := ks[0].state()
					return running
				})
				if rec := e.do(tc.method, "/contexts/"+id+tc.path, ""); rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", tc.method, rec.Code, rec.Body.String())
				}
			}
			rec := <-done
			lines := splitLines(t, rec.Body.String())
			want := []string{`{"type":"number_of_executions","execution_count":1}`, tc.want, `{"type":"end_of_execution"}`}
			if strings.Join(lines, "\n") != strings.Join(want, "\n") {
				t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestLaunchFailureAfterHeaders(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	e.l.setFail(&codeinterp.MissingInterpreterError{Language: "python", Programs: []string{"python3", "python"}})
	rec := e.do(http.MethodPost, "/execute", `{"code":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	want := []string{
		`{"type":"error","name":"InterpreterNotFound","value":"python interpreter not found in the sandbox (looked for [python3 python])","traceback":""}`,
		`{"type":"end_of_execution"}`,
	}
	if got := splitLines(t, rec.Body.String()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines = %q", got)
	}
}

// Env the interpreter cannot hold is the caller's mistake: 400 text/plain
// before the stream starts, as for E2B's other request errors. It used to
// show as a 200 stream that ended in an error line.
func TestExecuteInvalidEnv(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	for _, env := range []string{`{"A=B":"c"}`, `{"":"c"}`, `{"A":"b\u0000c"}`} {
		rec := e.do(http.MethodPost, "/execute", `{"code":"print x","env_vars":`+env+`}`)
		if rec.Code != http.StatusBadRequest || !strings.HasPrefix(rec.Body.String(), "invalid environment variable") ||
			!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("env %s = %d %q %q", env, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
	}
	if ks := e.l.kernels(); len(ks) != 0 {
		t.Fatalf("an interpreter started for a refused run: %d", len(ks))
	}
}

// Errors the adapter does not know can carry host paths (a WASM module
// file in sandboxd's state, a driver script). They are logged whole; the
// client gets a generic message. The known kinds keep theirs.
func TestUnknownErrorsAreGeneric(t *testing.T) {
	const secret = "open /var/lib/aerolvm/wasm/modules/python.wasm: permission denied"
	e := newTestEnv(t, time.Hour)
	var logs strings.Builder
	var mu sync.Mutex
	e.h.logger = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	e.do(http.MethodGet, "/health", "") // registers the defaults, kernels not started
	var c contextResponse
	_ = json.Unmarshal(e.do(http.MethodPost, "/contexts", `{}`).Body.Bytes(), &c)
	e.l.setFail(errors.New(secret))

	if rec := e.do(http.MethodPost, "/contexts", `{}`); rec.Code != http.StatusInternalServerError ||
		rec.Body.String() != "Failed to create context: "+internalErrorText {
		t.Errorf("create = %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(http.MethodPost, "/contexts/"+c.ID+"/restart", ""); rec.Code != http.StatusInternalServerError ||
		rec.Body.String() != "Failed to restart context "+c.ID+": "+internalErrorText {
		t.Errorf("restart = %d %q", rec.Code, rec.Body.String())
	}
	// The python default's kernel starts on its first run, which fails.
	rec := e.do(http.MethodPost, "/execute", `{"code":"x"}`)
	want := `{"type":"error","name":"InterpreterError","value":"` + internalErrorText + `","traceback":""}`
	if lines := splitLines(t, rec.Body.String()); len(lines) != 2 || lines[0] != want {
		t.Errorf("execute = %q", lines)
	}
	mu.Lock()
	logged := logs.String()
	mu.Unlock()
	if n := strings.Count(logged, "/var/lib/aerolvm/wasm/modules/python.wasm"); n != 3 {
		t.Fatalf("log has the full error %d times, want 3: %q", n, logged)
	}
	if strings.Contains(rec.Body.String(), "/var/lib") {
		t.Fatal("a host path reached the client")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestNewHandlerDefaults(t *testing.T) {
	m := codeinterp.NewManager(codeinterp.Options{Launcher: newFakeLauncher(), ListDefaults: true})
	t.Cleanup(m.Close)
	h, ok := NewHandler(m, nil).(*handler)
	if !ok || h.keepalive != KeepaliveInterval || h.maxBody != codeinterp.MaxFramePayload || h.logger == nil {
		t.Fatalf("NewHandler = %+v", h)
	}
	// A host that buffers bodies for many sandboxes passes its own bound;
	// zero keeps the default.
	if small := NewHandler(m, nil, WithMaxBodyBytes(1024)).(*handler); small.maxBody != 1024 {
		t.Fatalf("WithMaxBodyBytes(1024) = %d", small.maxBody)
	}
	if zero := NewHandler(m, nil, WithMaxBodyBytes(0)).(*handler); zero.maxBody != DefaultMaxBodyBytes {
		t.Fatalf("WithMaxBodyBytes(0) = %d", zero.maxBody)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d", rec.Code)
	}
}

func TestRunErrorName(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&codeinterp.MissingInterpreterError{Language: "r"}, "InterpreterNotFound"},
		{codeinterp.ErrQueueFull, "ContextBusy"},
		{codeinterp.ErrNotFound, "ContextNotFound"},
		{context.Canceled, "InterpreterError"},
	}
	for _, tc := range cases {
		if got := runErrorName(tc.err); got != tc.want {
			t.Errorf("runErrorName(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// readLine reads one NDJSON line from a live response.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v (got %q)", err, line)
	}
	return strings.TrimSuffix(line, "\n")
}

// sendExecute posts to /execute and returns once the response headers are
// in. It is safe off the test goroutine.
func sendExecute(ctx context.Context, srv *httptest.Server, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/execute", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	return srv.Client().Do(req)
}

func postExecute(t *testing.T, ctx context.Context, srv *httptest.Server, body string) *http.Response {
	t.Helper()
	resp, err := sendExecute(ctx, srv, body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

const keepalive = `{"type":"keepalive"}`

func TestKeepaliveWhileIdle(t *testing.T) {
	e := newTestEnv(t, 20*time.Millisecond)
	srv := e.server(t)
	resp := postExecute(t, context.Background(), srv, `{"code":"block"}`)
	r := bufio.NewReader(resp.Body)
	first := readLine(t, r)
	for first == keepalive { // a slow start may already have idled
		first = readLine(t, r)
	}
	if first != `{"type":"number_of_executions","execution_count":1}` {
		t.Fatalf("first line = %q", first)
	}
	// The run is blocked, so nothing but keepalives can come now.
	for i := 0; i < 2; i++ {
		if got := readLine(t, r); got != keepalive {
			t.Fatalf("idle line %d = %q, want a keepalive", i, got)
		}
	}
	close(e.l.release)
	// Keepalives may still be in flight; the output and the end follow them.
	var rest []string
	for {
		line := readLine(t, r)
		if line == keepalive {
			continue
		}
		rest = append(rest, line)
		if line == `{"type":"end_of_execution"}` {
			break
		}
	}
	want := []string{`{"type":"stdout","text":"released","timestamp":"` + testStamp + `"}`, `{"type":"end_of_execution"}`}
	if strings.Join(rest, "\n") != strings.Join(want, "\n") {
		t.Fatalf("after release: %q", rest)
	}
}

// Headers go out before the run waits for the context: a second run on a
// busy context gets its 200 at once.
func TestHeadersFlushedBeforeQueue(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	srv := e.server(t)
	first := postExecute(t, context.Background(), srv, `{"code":"block"}`)
	r1 := bufio.NewReader(first.Body)
	readLine(t, r1) // the first run holds the context now

	type result struct {
		resp *http.Response
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := sendExecute(context.Background(), srv, `{"code":"queued"}`)
		got <- result{resp, err}
	}()
	var second *http.Response
	select {
	case res := <-got:
		if res.err != nil {
			t.Fatal(res.err)
		}
		second = res.resp
		t.Cleanup(func() { _ = second.Body.Close() })
	case <-time.After(5 * time.Second):
		close(e.l.release)
		t.Fatal("headers of a queued run were held back until the context was free")
	}
	if second.StatusCode != http.StatusOK || second.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("queued run: %d %q", second.StatusCode, second.Header.Get("Content-Type"))
	}
	close(e.l.release)
	r2 := bufio.NewReader(second.Body)
	want := []string{
		`{"type":"number_of_executions","execution_count":2}`,
		`{"type":"result","text":"queued","extra":{},"is_main_result":true}`,
		`{"type":"end_of_execution"}`,
	}
	for _, w := range want {
		if got := readLine(t, r2); got != w {
			t.Fatalf("queued run line = %q, want %q", got, w)
		}
	}
}

// A client that goes away interrupts its run, and the context keeps its
// kernel (and so its state) for the next run.
func TestDisconnectInterruptsAndKeepsState(t *testing.T) {
	e := newTestEnv(t, time.Hour)
	srv := e.server(t)
	ctx, cancel := context.WithCancel(context.Background())
	resp := postExecute(t, ctx, srv, `{"code":"sleep"}`)
	readLine(t, bufio.NewReader(resp.Body))
	cancel()
	waitFor(t, "the interrupt", func() bool {
		_, interrupts, running := e.l.kernels()[0].state()
		return interrupts == 1 && !running
	})
	rec := e.do(http.MethodPost, "/execute", `{"code":"after"}`)
	if !strings.Contains(rec.Body.String(), `"execution_count":2`) || len(e.l.kernels()) != 1 {
		t.Fatalf("next run: %s (kernels %d), want the same kernel's second run", rec.Body.String(), len(e.l.kernels()))
	}
}
