package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// fakeKernel runs one command per line of code:
//
//	print X / err X   stdout / stderr X
//	result            a main result with a known and an unknown MIME type
//	show              a display() result (not main)
//	fail              an error event, status error
//	sleep             block until interrupted or closed
//	ignore            block until closed (ignores interrupts)
//	die               the kernel dies mid-run
//	killed            the kernel is killed by an interrupt (WASM)
//	wait D            sleep for duration D, then go on
//	env / cwd         print the run's K variable / the context's cwd
type fakeKernel struct {
	spec      codeinterp.Spec
	done      chan struct{}
	interrupt chan struct{}
	closeOnce sync.Once
	runs      atomic.Int32
	finished  atomic.Int32
}

func newFakeKernel(spec codeinterp.Spec) *fakeKernel {
	return &fakeKernel{spec: spec, done: make(chan struct{}), interrupt: make(chan struct{}, 4)}
}

func (k *fakeKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	n := int(k.runs.Add(1))
	defer k.finished.Add(1)
	sink(codeinterp.Event{Kind: codeinterp.EventCount, Count: n})
	status := "ok"
	for _, line := range strings.Split(req.Code, "\n") {
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch cmd {
		case "print":
			sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: arg})
		case "err":
			sink(codeinterp.Event{Kind: codeinterp.EventStderr, Text: arg})
		case "result":
			sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{
				"text/plain": "42", "image/png": "iVBOR", "application/json": map[string]any{"a": 1},
				"e2b/data": map[string]any{"c": []any{1}}, "application/x-custom": "c",
			}})
		case "show":
			sink(codeinterp.Event{Kind: codeinterp.EventResult, Bundle: map[string]any{"text/plain": "shown"}})
		case "fail":
			sink(codeinterp.Event{Kind: codeinterp.EventError, ErrName: "ValueError", ErrValue: "bad", ErrTraceback: "Traceback..."})
			status = "error"
		case "sleep":
			select {
			case <-k.interrupt:
				return codeinterp.Outcome{Status: "interrupted"}, nil
			case <-k.done:
				return codeinterp.Outcome{Died: true}, nil
			}
		case "ignore":
			<-k.done
			return codeinterp.Outcome{Died: true}, nil
		case "die":
			_ = k.Close()
			return codeinterp.Outcome{Died: true}, nil
		case "killed":
			// A WASM kernel's interrupt: the interpreter is killed.
			_ = k.Close()
			return codeinterp.Outcome{Status: "interrupted", Died: true}, nil
		case "wait":
			d, _ := time.ParseDuration(arg)
			time.Sleep(d)
		case "env":
			sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: req.Env["K"]})
		case "cwd":
			sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: k.spec.Cwd})
		}
	}
	return codeinterp.Outcome{Status: status}, nil
}

func (k *fakeKernel) Interrupt() error {
	select {
	case k.interrupt <- struct{}{}:
	default:
	}
	return nil
}

func (k *fakeKernel) Close() error {
	k.closeOnce.Do(func() { close(k.done) })
	return nil
}

func (k *fakeKernel) Done() <-chan struct{} { return k.done }

type fakeLauncher struct {
	mu       sync.Mutex
	kernels  []*fakeKernel
	fail     error
	langs    []string
	launches int
}

func (l *fakeLauncher) Launch(ctx context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launches++
	if l.fail != nil {
		return nil, l.fail
	}
	k := newFakeKernel(spec)
	l.kernels = append(l.kernels, k)
	return k, nil
}

func (l *fakeLauncher) Languages() []string { return l.langs }

func (l *fakeLauncher) last() *fakeKernel {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.kernels) == 0 {
		return nil
	}
	return l.kernels[len(l.kernels)-1]
}

func (l *fakeLauncher) setFail(err error) {
	l.mu.Lock()
	l.fail = err
	l.mu.Unlock()
}

type testEnv struct {
	m   *codeinterp.Manager
	h   *handler
	ts  *httptest.Server
	url string // base, ending in /process/interpreter
}

// newTestEnv mounts the handler the way toolboxd does.
func newTestEnv(t *testing.T, l codeinterp.Launcher, mutate func(*codeinterp.Options)) *testEnv {
	t.Helper()
	opts := ManagerOptions(l, codeinterp.NewLimit(4), "/work")
	if mutate != nil {
		mutate(&opts)
	}
	m := codeinterp.NewManager(opts)
	t.Cleanup(m.Close)
	h := newHandler(m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.closeWait = 500 * time.Millisecond
	mux := http.NewServeMux()
	mux.Handle("/process/interpreter/", http.StripPrefix("/process/interpreter", h))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &testEnv{m: m, h: h, ts: ts, url: ts.URL + "/process/interpreter"}
}

func (e *testEnv) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, e.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("%s %s: body %q is not JSON: %v", method, path, data, err)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("%s %s: Content-Type %q", method, path, ct)
		}
	}
	return resp.StatusCode, out
}

// wsResult is everything a client saw on one execute connection.
type wsResult struct {
	frames      []map[string]any
	closeCode   int
	closeReason string
	subprotocol string
}

func (r wsResult) types() []string {
	var out []string
	for _, f := range r.frames {
		out = append(out, f["type"].(string))
	}
	return out
}

func (r wsResult) text(typ string) string {
	var sb strings.Builder
	for _, f := range r.frames {
		if f["type"] == typ {
			sb.WriteString(f["text"].(string))
		}
	}
	return sb.String()
}

func (e *testEnv) dial(t *testing.T, header http.Header) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(e.url, "http") + "/execute"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v (%v)", err, resp)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// run sends first (a JSON value or a raw string) and reads to the close.
func (e *testEnv) run(t *testing.T, first any) wsResult {
	t.Helper()
	conn := e.dial(t, http.Header{"Sec-WebSocket-Protocol": {"sandbox.bearer, tok"}})
	return readAll(t, conn, first)
}

func readAll(t *testing.T, conn *websocket.Conn, first any) wsResult {
	t.Helper()
	res := wsResult{subprotocol: conn.Subprotocol()}
	var err error
	switch first := first.(type) {
	case nil:
		// The run was sent already.
	case string:
		err = conn.WriteMessage(websocket.TextMessage, []byte(first))
	default:
		err = conn.WriteJSON(first)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("read: %v (frames %v)", err, res.frames)
			}
			res.closeCode, res.closeReason = ce.Code, ce.Text
			return res
		}
		var f map[string]any
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("frame %q is not JSON", data)
		}
		res.frames = append(res.frames, f)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
