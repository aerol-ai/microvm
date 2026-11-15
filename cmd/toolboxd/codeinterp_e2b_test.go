package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/pkg/api/e2b"
)

// e2bTestKernel answers every run with its execution count and the code
// echoed back as the main result.
type e2bTestKernel struct {
	mu   sync.Mutex
	runs int
	once sync.Once
	done chan struct{}
}

func (k *e2bTestKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	k.mu.Lock()
	k.runs++
	n := k.runs
	k.mu.Unlock()
	sink(codeinterp.Event{Kind: codeinterp.EventCount, Count: n})
	sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{"text/plain": "'" + req.Code + "'"}})
	return codeinterp.Outcome{Status: "ok"}, nil
}

func (k *e2bTestKernel) Interrupt() error { return nil }

func (k *e2bTestKernel) Close() error {
	k.once.Do(func() { close(k.done) })
	return nil
}

func (k *e2bTestKernel) Done() <-chan struct{} { return k.done }

type e2bTestLauncher struct {
	mu    sync.Mutex
	specs []codeinterp.Spec
	kerns []*e2bTestKernel
}

func (l *e2bTestLauncher) Launch(_ context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := &e2bTestKernel{done: make(chan struct{})}
	l.specs = append(l.specs, spec)
	l.kerns = append(l.kerns, k)
	return k, nil
}

// useE2BTestInterpreter swaps in a fake launcher and a temp default cwd,
// and kills every kernel the test started.
func useE2BTestInterpreter(t *testing.T) (*e2bTestLauncher, *atomic.Int32, string) {
	t.Helper()
	l := &e2bTestLauncher{}
	var built atomic.Int32
	cwd := t.TempDir()
	prevLauncher, prevOptions := newCodeInterpLauncher, e2bInterpOptions
	newCodeInterpLauncher = func() codeinterp.Launcher {
		built.Add(1)
		return l
	}
	e2bInterpOptions = func(launcher codeinterp.Launcher, lim *codeinterp.Limit) codeinterp.Options {
		return codeinterp.Options{Launcher: launcher, Limit: lim, DefaultCwd: cwd, ListDefaults: true}
	}
	t.Cleanup(func() {
		newCodeInterpLauncher, e2bInterpOptions = prevLauncher, prevOptions
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, k := range l.kerns {
			_ = k.Close()
		}
	})
	return l, &built, cwd
}

func serveToolbox(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestE2BInterpreterRoutes(t *testing.T) {
	l, built, cwd := useE2BTestInterpreter(t)
	srv := newDaytonaTestServer(t)
	h := authedRoutes(srv)

	rec := serveToolbox(h, http.MethodGet, "/interpreter/e2b/health", "")
	if rec.Code != http.StatusOK || rec.Body.String() != `"OK"` {
		t.Fatalf("health: %d %q", rec.Code, rec.Body.String())
	}

	rec = serveToolbox(h, http.MethodPost, "/interpreter/e2b/contexts", `{"language":"python"}`)
	var created struct{ ID, Language, Cwd string }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if created.Language != "python" || created.Cwd != cwd {
		t.Fatalf("create = %+v, want python in %s", created, cwd)
	}

	rec = serveToolbox(h, http.MethodGet, "/interpreter/e2b/contexts", "")
	var list []struct{ ID, Language string }
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Language != "python" || list[1].Language != "javascript" || list[2].ID != created.ID {
		t.Fatalf("list = %+v, want both defaults, then the new context", list)
	}

	rec = serveToolbox(h, http.MethodPost, "/interpreter/e2b/execute", `{"code":"hi","context_id":"`+created.ID+`"}`)
	want := `{"type":"number_of_executions","execution_count":1}` + "\n" +
		`{"type":"result","text":"hi","extra":{},"is_main_result":true}` + "\n" +
		`{"type":"end_of_execution"}` + "\n"
	if rec.Code != http.StatusOK || rec.Body.String() != want || rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("execute: %d %q", rec.Code, rec.Body.String())
	}

	if rec := serveToolbox(h, http.MethodDelete, "/interpreter/e2b/contexts/"+created.ID, ""); rec.Code != http.StatusOK || rec.Body.String() != "null" {
		t.Fatalf("delete: %d %q", rec.Code, rec.Body.String())
	}

	// A sandbox-id prefix (the generic toolbox proxy's shape) still lands.
	if rec := serveToolbox(h, http.MethodGet, "/sb-x/interpreter/e2b/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("prefixed path: %d %s", rec.Code, rec.Body.String())
	}

	// Built once, on first use, from the shared launcher (the context made
	// above outliving its request already shows one Manager serves all).
	srv.e2bInterpreter()
	if built.Load() != 1 {
		t.Fatalf("interpreter built %d launchers", built.Load())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.specs) != 1 {
		t.Fatalf("launched %d kernels, want only the create's: defaults start on their first run", len(l.specs))
	}
}

func TestE2BInterpreterNeedsTheToken(t *testing.T) {
	useE2BTestInterpreter(t)
	srv := newDaytonaTestServer(t)
	srv.authToken = testToolboxToken
	h := srv.routes()
	cases := []struct {
		name, auth string
		want       int
	}{
		{name: "no token", want: http.StatusUnauthorized},
		{name: "wrong token", auth: "Bearer nope", want: http.StatusUnauthorized},
		{name: "token", auth: "Bearer " + testToolboxToken, want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/interpreter/e2b/contexts", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// The E2B interpreter shares the sandbox's context cap with Daytona's.
func TestE2BInterpreterSharesTheContextCap(t *testing.T) {
	useE2BTestInterpreter(t)
	srv := newDaytonaTestServer(t)
	h := authedRoutes(srv)
	serveToolbox(h, http.MethodGet, "/interpreter/e2b/health", "") // two defaults
	for i := 2; i < codeInterpContextLimit; i++ {
		if rec := serveToolbox(h, http.MethodPost, "/interpreter/e2b/contexts", `{}`); rec.Code != http.StatusOK {
			t.Fatalf("context %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := serveToolbox(h, http.MethodPost, "/interpreter/e2b/contexts", `{}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("context over the cap: %d %s", rec.Code, rec.Body.String())
	}
	other := codeinterp.NewManager(codeinterp.Options{Launcher: srv.codeInterp().launcher, Limit: srv.codeInterp().limit})
	t.Cleanup(other.Close)
	if _, err := other.Create(context.Background(), "python", ""); err == nil {
		t.Fatal("another adapter's Manager got a context past the shared cap")
	}
}

// Plan X2 for the interpreter: every path the E2B facade forwards for port
// 49999 reaches the E2B interpreter handler, not toolboxd's "no such
// route" or the handler's own unknown-route answers.
func TestFacadeInterpreterCallsExistInToolboxd(t *testing.T) {
	useE2BTestInterpreter(t)
	h := authedRoutes(newDaytonaTestServer(t))
	calls := e2b.InterpreterCalls()
	if len(calls) < 5 {
		t.Fatalf("only %d interpreter calls listed", len(calls))
	}
	for _, c := range calls {
		body := ""
		if c.Method == http.MethodPost {
			body = "{}"
		}
		rec := serveToolbox(h, c.Method, c.Path, body)
		if rec.Header().Get(routeMissingHeader) != "" || rec.Body.String() == "404 page not found\n" ||
			rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotImplemented {
			t.Errorf("e2b forwards %s %s, but toolboxd does not serve it: %d %q", c.Method, c.Path, rec.Code, rec.Body.String())
		}
	}
}

func TestIsKnownToolboxPathE2BInterpreter(t *testing.T) {
	if !isKnownToolboxPath("/interpreter/e2b/execute") {
		t.Fatal("interpreter path not known")
	}
	if got := normalizeSandboxPath("/some-proxy/interpreter/e2b/contexts", ""); got != "/interpreter/e2b/contexts" {
		t.Fatalf("normalized = %q", got)
	}
	if isKnownToolboxPath("/interpreter/other") {
		t.Fatal("only the E2B interpreter prefix is a toolbox path")
	}
}
