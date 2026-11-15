package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	toolbox "github.com/daytonaio/daytona/libs/toolbox-api-client-go"
	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// echoKernel answers every run with its code as stdout, so the toolboxd
// wiring is tested without an interpreter installed.
type echoKernel struct {
	done chan struct{}
	once sync.Once
}

func (k *echoKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: req.Code})
	return codeinterp.Outcome{Status: "ok"}, nil
}
func (k *echoKernel) Interrupt() error      { return nil }
func (k *echoKernel) Close() error          { k.once.Do(func() { close(k.done) }); return nil }
func (k *echoKernel) Done() <-chan struct{} { return k.done }

type echoLauncher struct {
	mu    sync.Mutex
	specs []codeinterp.Spec
}

func (l *echoLauncher) Launch(_ context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	l.mu.Lock()
	l.specs = append(l.specs, spec)
	l.mu.Unlock()
	return &echoKernel{done: make(chan struct{})}, nil
}

func useEchoInterpreter(t *testing.T) *echoLauncher {
	t.Helper()
	l := &echoLauncher{}
	prev := newCodeInterpLauncher
	newCodeInterpLauncher = func() codeinterp.Launcher { return l }
	t.Cleanup(func() { newCodeInterpLauncher = prev })
	return l
}

func newInterpServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), sandboxID: "sb-test"}
	t.Cleanup(srv.closeCodeInterp)
	ts := httptest.NewServer(authedRoutes(srv))
	t.Cleanup(ts.Close)
	return srv, ts
}

func interpRequest(t *testing.T, ts *httptest.Server, method, path, body, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

type interpRun struct {
	frames      []map[string]any
	closeCode   int
	closeReason string
}

func (r interpRun) text(typ string) string {
	var sb strings.Builder
	for _, f := range r.frames {
		if f["type"] == typ {
			sb.WriteString(fmt.Sprint(f["text"]))
		}
	}
	return sb.String()
}

// runInterp runs one request on toolboxd's execute WebSocket.
func runInterp(t *testing.T, ts *httptest.Server, first any) interpRun {
	t.Helper()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/sb-test/process/interpreter/execute"
	conn, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + testToolboxToken}})
	if err != nil {
		t.Fatalf("dial: %v (%v)", err, resp)
	}
	defer conn.Close()
	if err := conn.WriteJSON(first); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var run interpRun
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("read: %v", err)
			}
			run.closeCode, run.closeReason = ce.Code, ce.Text
			return run
		}
		var f map[string]any
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("frame %q: %v", data, err)
		}
		run.frames = append(run.frames, f)
	}
}

func TestCodeInterpreterRoutes(t *testing.T) {
	l := useEchoInterpreter(t)
	srv, ts := newInterpServer(t)

	status, body := interpRequest(t, ts, http.MethodPost, "/sb-test/process/interpreter/context", "{}", testToolboxToken)
	if status != http.StatusOK {
		t.Fatalf("create = %d %s", status, body)
	}
	var created struct{ ID, Cwd string }
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if created.Cwd != wd || len(l.specs) != 1 || l.specs[0].Cwd != wd {
		t.Fatalf("context cwd = %q (launch %+v), want toolboxd's %q", created.Cwd, l.specs, wd)
	}

	run := runInterp(t, ts, map[string]any{"code": "hello", "contextId": created.ID})
	if run.text("stdout") != "hello" || run.text("control") != "completed" || run.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("run = %+v", run)
	}

	// An escaped path still reaches the adapter (its JSON 404).
	status, body = interpRequest(t, ts, http.MethodGet, "/sb-test/process/interpreter/context/a%2Fb", "", testToolboxToken)
	if status != http.StatusNotFound || !strings.Contains(body, `"message"`) {
		t.Fatalf("escaped path = %d %s", status, body)
	}
	// The bearer check still guards every interpreter route.
	if status, _ = interpRequest(t, ts, http.MethodGet, "/sb-test/process/interpreter/context", "", "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", status)
	}

	// One launcher and one cap for the sandbox, made once.
	if srv.codeInterp() != srv.codeInterp() || srv.daytonaInterpreter() == nil {
		t.Fatal("interpreter state made twice")
	}

	status, body = interpRequest(t, ts, http.MethodGet, "/version", "", testToolboxToken)
	var version struct{ Features []string }
	if err := json.Unmarshal([]byte(body), &version); err != nil || status != http.StatusOK || !slices.Contains(version.Features, "code.interpreter") {
		t.Fatalf("/version = %d %s", status, body)
	}
}

func TestCloseCodeInterpBeforeUse(t *testing.T) {
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv.closeCodeInterp()
	srv.closeCodeInterp()
}

// TestCodeInterpreterPythonEndToEnd is the whole path a Daytona or AerolVM
// client takes inside the sandbox: toolboxd's routes and auth, the Daytona
// adapter, the process launcher with toolboxd's tracked children, and
// python_driver.py.
func TestCodeInterpreterPythonEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	_, ts := newInterpServer(t)

	if run := runInterp(t, ts, map[string]any{"code": "x = 5"}); run.text("control") != "completed" {
		t.Fatalf("x = 5: %+v", run)
	}
	if run := runInterp(t, ts, map[string]any{"code": "print(x)"}); run.text("stdout") != "5\n" || run.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("print(x): %+v", run)
	}

	run := runInterp(t, ts, map[string]any{"code": "1/0"})
	if len(run.frames) != 2 || run.frames[0]["type"] != "error" || run.frames[0]["name"] != "ZeroDivisionError" ||
		!strings.Contains(fmt.Sprint(run.frames[0]["traceback"]), "ZeroDivisionError: division by zero") {
		t.Fatalf("1/0: %+v", run)
	}

	start := time.Now()
	run = runInterp(t, ts, map[string]any{"code": "import time; time.sleep(10)", "timeout": 1})
	if run.text("control") != "interrupted" || run.closeCode != 4008 || time.Since(start) > 8*time.Second {
		t.Fatalf("timeout: %+v after %s", run, time.Since(start))
	}

	if run = runInterp(t, ts, map[string]any{"code": `import os; os.system("echo sub")`}); run.text("stdout") != "sub\n" {
		t.Fatalf("os.system: %+v", run)
	}

	const size = 300 * 1024
	run = runInterp(t, ts, map[string]any{"code": fmt.Sprintf("print(''.join('%%07d\\n' %% i for i in range(%d)), end='')", size/8)})
	out := run.text("stdout")
	if len(out) != size {
		t.Fatalf("300 KB print: got %d bytes", len(out))
	}
	for i, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line != fmt.Sprintf("%07d", i) {
			t.Fatalf("300 KB print: line %d = %q", i, line)
		}
	}

	// The Daytona Go SDK, through the sandbox-id prefix its toolbox URL has.
	cfg := toolbox.NewConfiguration()
	cfg.Servers = toolbox.ServerConfigurations{{URL: ts.URL + "/sb-test"}}
	cfg.HTTPClient = ts.Client()
	cfg.AddDefaultHeader("Authorization", "Bearer "+testToolboxToken)
	ci := daytonasdk.NewCodeInterpreterService(toolbox.NewAPIClient(cfg), nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	created, err := ci.CreateContext(ctx, nil)
	if err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	id := created["id"].(string)
	for _, code := range []string{"y = 41", "print(y + 1)"} {
		ch, err := ci.RunCode(ctx, code, daytonaoptions.WithCustomContext(id))
		if err != nil {
			t.Fatalf("RunCode: %v", err)
		}
		for range ch.Stdout {
		}
		res := <-ch.Done
		if res.Error != nil || (code == "print(y + 1)" && res.Stdout != "42\n") {
			t.Fatalf("RunCode(%q) = %+v %+v", code, res, res.Error)
		}
	}
	if list, err := ci.ListContexts(ctx); err != nil || len(list) != 1 {
		t.Fatalf("ListContexts = %v, %v", list, err)
	}
	if err := ci.DeleteContext(ctx, id); err != nil {
		t.Fatalf("DeleteContext: %v", err)
	}
}
