package e2b

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// fakeKernel runs "code" as a named script (see fakeScripts); any other
// code comes back as a main text/plain result holding the code's repr.
type fakeKernel struct {
	spec    codeinterp.Spec
	release chan struct{}

	mu          sync.Mutex
	done        chan struct{}
	interrupted chan struct{}
	closed      bool
	interrupts  int
	runs        int
	running     bool
}

var fakeScripts = map[string]func(k *fakeKernel, req codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome{
	// Every kind of event, in one run.
	"all": func(_ *fakeKernel, _ codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome {
		sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: "a\n"})
		sink(codeinterp.Event{Kind: codeinterp.EventStderr, Text: "b\n"})
		sink(codeinterp.Event{Kind: codeinterp.EventResult, Bundle: map[string]any{"image/png": "iVBO"}})
		sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{"text/plain": "'x'", "text/html": "<b>x</b>"}})
		sink(codeinterp.Event{Kind: codeinterp.EventError, ErrName: "ValueError", ErrValue: "bad", ErrTraceback: "tb"})
		return codeinterp.Outcome{Status: "error"}
	},
	// Blocks until interrupted (KeyboardInterrupt) or killed.
	"sleep": func(k *fakeKernel, _ codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome {
		select {
		case <-k.interrupted:
			sink(codeinterp.Event{Kind: codeinterp.EventError, ErrName: "KeyboardInterrupt"})
			return codeinterp.Outcome{Status: "interrupted"}
		case <-k.done:
			return codeinterp.Outcome{Died: true}
		}
	},
	// Ignores interrupts; only a kill ends it.
	"ignore": func(k *fakeKernel, _ codeinterp.Request, _ codeinterp.Sink) codeinterp.Outcome {
		<-k.done
		return codeinterp.Outcome{Died: true}
	},
	"die": func(k *fakeKernel, _ codeinterp.Request, _ codeinterp.Sink) codeinterp.Outcome {
		_ = k.Close()
		return codeinterp.Outcome{Died: true}
	},
	// Waits for the test to release it, then prints.
	"block": func(k *fakeKernel, _ codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome {
		select {
		case <-k.release:
		case <-k.done:
			return codeinterp.Outcome{Died: true}
		}
		sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: "released"})
		return codeinterp.Outcome{Status: "ok"}
	},
	"env": func(_ *fakeKernel, req codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome {
		sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: req.Env["K"]})
		return codeinterp.Outcome{Status: "ok"}
	},
	"whoami": func(k *fakeKernel, _ codeinterp.Request, sink codeinterp.Sink) codeinterp.Outcome {
		sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: k.spec.Language + " " + k.spec.Cwd})
		return codeinterp.Outcome{Status: "ok"}
	},
}

func newFakeKernel(spec codeinterp.Spec, release chan struct{}) *fakeKernel {
	return &fakeKernel{spec: spec, release: release, done: make(chan struct{}), interrupted: make(chan struct{}, 8)}
}

func (k *fakeKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	k.mu.Lock()
	k.runs++
	n := k.runs
	k.running = true
	k.mu.Unlock()
	defer func() {
		k.mu.Lock()
		k.running = false
		k.mu.Unlock()
	}()
	sink(codeinterp.Event{Kind: codeinterp.EventCount, Count: n})
	if script, ok := fakeScripts[req.Code]; ok {
		return script(k, req, sink), nil
	}
	sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{"text/plain": "'" + req.Code + "'"}})
	return codeinterp.Outcome{Status: "ok"}, nil
}

func (k *fakeKernel) Interrupt() error {
	k.mu.Lock()
	k.interrupts++
	k.mu.Unlock()
	select {
	case k.interrupted <- struct{}{}:
	default:
	}
	return nil
}

func (k *fakeKernel) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.closed {
		k.closed = true
		close(k.done)
	}
	return nil
}

func (k *fakeKernel) Done() <-chan struct{} { return k.done }

func (k *fakeKernel) state() (runs, interrupts int, running bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.runs, k.interrupts, k.running
}

type fakeLauncher struct {
	release chan struct{}

	mu       sync.Mutex
	launched []*fakeKernel
	fail     error
}

func newFakeLauncher() *fakeLauncher { return &fakeLauncher{release: make(chan struct{})} }

func (l *fakeLauncher) Launch(_ context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail != nil {
		return nil, l.fail
	}
	k := newFakeKernel(spec, l.release)
	l.launched = append(l.launched, k)
	return k, nil
}

func (l *fakeLauncher) setFail(err error) {
	l.mu.Lock()
	l.fail = err
	l.mu.Unlock()
}

func (l *fakeLauncher) kernels() []*fakeKernel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*fakeKernel(nil), l.launched...)
}

// testNow is the clock every output line's timestamp reads.
var testNow = time.Date(2026, 11, 15, 1, 2, 3, 456000000, time.UTC)

const testStamp = "2026-11-15T01:02:03.456Z"

type testEnv struct {
	l   *fakeLauncher
	m   *codeinterp.Manager
	h   *handler
	lim *codeinterp.Limit
}

func newTestEnv(t *testing.T, keepalive time.Duration) *testEnv {
	t.Helper()
	l := newFakeLauncher()
	lim := codeinterp.NewLimit(8)
	opts := managerOptions(l, lim, "/home/user",
		func(string, os.FileMode) error { return nil },
		func() (string, error) { return "/unused", nil })
	m := codeinterp.NewManager(opts)
	t.Cleanup(m.Close)
	h := newHandler(m, slog.New(slog.NewTextHandler(io.Discard, nil)), keepalive)
	h.now = func() time.Time { return testNow }
	return &testEnv{l: l, m: m, h: h, lim: lim}
}

// do serves one request in process and returns the recorder.
func (e *testEnv) do(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// server serves the handler over real HTTP, for streaming and disconnects.
func (e *testEnv) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	return srv
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// contextIDs lists the ids GET /contexts returns.
func (e *testEnv) contextIDs() []string {
	var ids []string
	for _, c := range e.m.List() {
		ids = append(ids, c.ID)
	}
	return ids
}

// failingBody is a request body whose read fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, fmt.Errorf("connection reset") }

func (failingBody) Close() error { return nil }

var _ http.Handler = (*handler)(nil)
