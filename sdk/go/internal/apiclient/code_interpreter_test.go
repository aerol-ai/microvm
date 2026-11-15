package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// interpAgent plays sandboxd + toolboxd for the code interpreter: /version
// lists features (nil: an agent too old to list any), rest answers the
// context routes, and script drives the execute socket after the start
// frame. It records every request it saw.
type interpAgent struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []string
	start    map[string]any
	auth     string
}

func newInterpAgent(t *testing.T, features []string, rest http.HandlerFunc, script func(conn *websocket.Conn)) *interpAgent {
	t.Helper()
	a := &interpAgent{}
	var upgrader websocket.Upgrader
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.requests = append(a.requests, r.Method+" "+r.URL.EscapedPath())
		a.mu.Unlock()
		switch r.URL.Path {
		case "/v1/sandboxes/sb-1/toolbox/version":
			body := map[string]any{"version": "0.7.6"}
			if features != nil {
				body["features"] = features
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		case "/v1/sandboxes/sb-1/toolbox/process/interpreter/execute":
			a.mu.Lock()
			a.auth = r.Header.Get("Authorization")
			a.mu.Unlock()
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var start map[string]any
			if err := conn.ReadJSON(&start); err != nil {
				return
			}
			a.mu.Lock()
			a.start = start
			a.mu.Unlock()
			script(conn)
			return
		}
		if rest != nil {
			rest(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *interpAgent) client(t *testing.T) *Client {
	t.Helper()
	zero := 0
	return NewClient(a.srv.URL, ClientOptions{PATToken: "pat-token", HTTPClient: a.srv.Client(), Retry: &RetryConfig{MaxRetries: &zero}})
}

func (a *interpAgent) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}

func (a *interpAgent) startFrame() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.start
}

func sendFrame(conn *websocket.Conn, frame map[string]any) {
	// The agent's frames always carry these five fields.
	full := map[string]any{"text": "", "name": "", "value": "", "traceback": ""}
	for k, v := range frame {
		full[k] = v
	}
	_ = conn.WriteJSON(full)
}

func closeWith(conn *websocket.Conn, code int, reason string) {
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	// Wait for the client's reply so the close frame is not lost to a reset.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

var interpFeatures = []string{FeatureCodeInterpreter}

func TestRunCodeStreamsOutputAndResults(t *testing.T) {
	agent := newInterpAgent(t, interpFeatures, nil, func(conn *websocket.Conn) {
		sendFrame(conn, map[string]any{"type": "execution_count", "count": 3})
		sendFrame(conn, map[string]any{"type": "stdout", "text": "hello\n"})
		sendFrame(conn, map[string]any{"type": "stderr", "text": "warn\n"})
		_ = conn.WriteMessage(websocket.TextMessage, []byte("not json"))
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{1, 2})
		sendFrame(conn, map[string]any{"type": "something-new", "text": "ignored"})
		sendFrame(conn, map[string]any{"type": "result", "text": "", "png": "iVBORw0K", "extra": map[string]any{"image/x-b": "b", "application/x-a": "a"}})
		sendFrame(conn, map[string]any{"type": "result", "text": "42", "json": map[string]any{"v": 42.0}, "data": []any{"not", "an", "object"}, "is_main_result": true})
		sendFrame(conn, map[string]any{"type": "control", "text": "completed"})
		closeWith(conn, websocket.CloseNormalClosure, "")
	})

	var mu sync.Mutex
	var stdout, stderr []string
	var results []CodeResult
	exec, err := agent.client(t).RunCode(context.Background(), "sb-1", "print('hello')\n6*7", RunCodeOptions{
		OnStdout: func(text string) { mu.Lock(); stdout = append(stdout, text); mu.Unlock() },
		OnStderr: func(text string) { mu.Lock(); stderr = append(stderr, text); mu.Unlock() },
		OnResult: func(r CodeResult) { mu.Lock(); results = append(results, r); mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("RunCode: %v", err)
	}

	if got, want := agent.startFrame(), map[string]any{"code": "print('hello')\n6*7", "richOutput": true}; !reflect.DeepEqual(got, want) {
		t.Fatalf("start frame = %v, want %v", got, want)
	}
	agent.mu.Lock()
	auth := agent.auth
	agent.mu.Unlock()
	if auth != "Bearer pat-token" {
		t.Fatalf("auth = %q", auth)
	}
	if !reflect.DeepEqual(exec.Logs.Stdout, []string{"hello\n"}) || !reflect.DeepEqual(exec.Logs.Stderr, []string{"warn\n"}) {
		t.Fatalf("logs = %+v", exec.Logs)
	}
	mu.Lock()
	if !reflect.DeepEqual(stdout, exec.Logs.Stdout) || !reflect.DeepEqual(stderr, exec.Logs.Stderr) || len(results) != 2 {
		t.Fatalf("callbacks stdout=%v stderr=%v results=%d", stdout, stderr, len(results))
	}
	mu.Unlock()
	if exec.ExecutionCount == nil || *exec.ExecutionCount != 3 {
		t.Fatalf("execution count = %v", exec.ExecutionCount)
	}
	if len(exec.Results) != 2 || exec.Text() != "42" || exec.Interrupted || exec.Error != nil {
		t.Fatalf("exec = %+v", exec)
	}
	if got := exec.Results[0].Formats(); !reflect.DeepEqual(got, []string{"png", "application/x-a", "image/x-b"}) {
		t.Fatalf("first result formats = %v", got)
	}
	// A json value that is not an object drops that field only.
	main := exec.Results[1]
	if !main.IsMainResult || main.JSON["v"] != 42.0 || main.Data != nil {
		t.Fatalf("main result = %+v", main)
	}
}

func TestRunCodeStartFrame(t *testing.T) {
	zero, thirty := 0, 30
	cases := []struct {
		name string
		opts RunCodeOptions
		want map[string]any
	}{
		{"context and no timeout", RunCodeOptions{ContextID: "ctx-1", TimeoutSeconds: &zero},
			map[string]any{"code": "x", "contextId": "ctx-1", "timeout": 0.0, "richOutput": true}},
		{"language, envs and a timeout", RunCodeOptions{Language: "javascript", Envs: map[string]string{"A": "1"}, TimeoutSeconds: &thirty},
			map[string]any{"code": "x", "language": "javascript", "envs": map[string]any{"A": "1"}, "timeout": 30.0, "richOutput": true}},
		{"empty envs are left out", RunCodeOptions{Envs: map[string]string{}},
			map[string]any{"code": "x", "richOutput": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newInterpAgent(t, interpFeatures, nil, func(conn *websocket.Conn) {
				closeWith(conn, websocket.CloseNormalClosure, "")
			})
			if _, err := agent.client(t).RunCode(context.Background(), "sb-1", "x", tc.opts); err != nil {
				t.Fatalf("RunCode: %v", err)
			}
			if got := agent.startFrame(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("start frame = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunCodeOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		script func(conn *websocket.Conn)
		check  func(t *testing.T, exec *Execution, err error, codeErrs []ExecutionError)
	}{
		{
			name: "the code's exception is part of a normal run",
			script: func(conn *websocket.Conn) {
				sendFrame(conn, map[string]any{"type": "error", "name": "NameError", "value": "name 'y' is not defined", "traceback": "Traceback..."})
				sendFrame(conn, map[string]any{"type": "control", "text": "completed"})
				closeWith(conn, websocket.CloseNormalClosure, "")
			},
			check: func(t *testing.T, exec *Execution, err error, codeErrs []ExecutionError) {
				want := ExecutionError{Name: "NameError", Value: "name 'y' is not defined", Traceback: "Traceback..."}
				if err != nil || exec.Error == nil || *exec.Error != want || len(codeErrs) != 1 || codeErrs[0] != want {
					t.Fatalf("err=%v exec.Error=%+v callbacks=%+v", err, exec.Error, codeErrs)
				}
			},
		},
		{
			name: "interrupted control",
			script: func(conn *websocket.Conn) {
				sendFrame(conn, map[string]any{"type": "control", "text": "interrupted"})
				closeWith(conn, websocket.CloseNormalClosure, "")
			},
			check: func(t *testing.T, exec *Execution, err error, _ []ExecutionError) {
				if err != nil || !exec.Interrupted {
					t.Fatalf("err=%v interrupted=%v", err, exec.Interrupted)
				}
			},
		},
		{
			name: "a close frame with no status is a normal end",
			script: func(conn *websocket.Conn) {
				sendFrame(conn, map[string]any{"type": "stdout", "text": "ok"})
				_ = conn.WriteControl(websocket.CloseMessage, []byte{}, time.Now().Add(time.Second))
				_, _, _ = conn.ReadMessage()
			},
			check: func(t *testing.T, exec *Execution, err error, _ []ExecutionError) {
				if err != nil || len(exec.Logs.Stdout) != 1 {
					t.Fatalf("err=%v exec=%+v", err, exec)
				}
			},
		},
		{
			name: "timeout keeps the partial output",
			script: func(conn *websocket.Conn) {
				sendFrame(conn, map[string]any{"type": "stdout", "text": "tick\n"})
				closeWith(conn, CloseCodeRunTimeout, "execution timed out")
			},
			check: func(t *testing.T, exec *Execution, err error, _ []ExecutionError) {
				var runErr *CodeRunError
				if !errors.As(err, &runErr) || !runErr.Timeout() || !errors.Is(err, ErrCodeRunTimeout) {
					t.Fatalf("err = %v, want a timeout *CodeRunError", err)
				}
				if err.Error() != "code run timed out: execution timed out" {
					t.Fatalf("message = %q", err.Error())
				}
				if runErr.Execution != exec || exec == nil || !reflect.DeepEqual(exec.Logs.Stdout, []string{"tick\n"}) {
					t.Fatalf("partial execution = %+v", exec)
				}
			},
		},
		{
			name: "refused with a reason",
			script: func(conn *websocket.Conn) {
				closeWith(conn, websocket.ClosePolicyViolation, "context not found: abc")
			},
			check: func(t *testing.T, exec *Execution, err error, _ []ExecutionError) {
				var runErr *CodeRunError
				if !errors.As(err, &runErr) || runErr.CloseCode != 1008 || runErr.Reason != "context not found: abc" || errors.Is(err, ErrCodeRunTimeout) {
					t.Fatalf("err = %#v", err)
				}
				if err.Error() != "code run failed (close 1008): context not found: abc" || exec == nil {
					t.Fatalf("message = %q exec=%v", err.Error(), exec)
				}
			},
		},
		{
			name: "worker died",
			script: func(conn *websocket.Conn) {
				closeWith(conn, websocket.CloseInternalServerErr, "worker process ended")
			},
			check: func(t *testing.T, _ *Execution, err error, _ []ExecutionError) {
				var runErr *CodeRunError
				if !errors.As(err, &runErr) || runErr.CloseCode != 1011 || runErr.Reason != "worker process ended" {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name: "connection lost",
			script: func(conn *websocket.Conn) {
				sendFrame(conn, map[string]any{"type": "stdout", "text": "partial"})
				_ = conn.UnderlyingConn().Close()
			},
			check: func(t *testing.T, exec *Execution, err error, _ []ExecutionError) {
				var runErr *CodeRunError
				if !errors.As(err, &runErr) || runErr.CloseCode != websocket.CloseAbnormalClosure || len(exec.Logs.Stdout) != 1 {
					t.Fatalf("err=%v exec=%+v", err, exec)
				}
				if !strings.HasPrefix(err.Error(), "code run failed (close 1006)") {
					t.Fatalf("message = %q", err.Error())
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newInterpAgent(t, interpFeatures, nil, tc.script)
			var codeErrs []ExecutionError
			exec, err := agent.client(t).RunCode(context.Background(), "sb-1", "x", RunCodeOptions{
				OnError: func(e ExecutionError) { codeErrs = append(codeErrs, e) },
			})
			tc.check(t, exec, err, codeErrs)
		})
	}
}

// readInterrupt reads the next client frame and reports whether it is the
// interrupt request.
func readInterrupt(conn *websocket.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg map[string]any
	if err := conn.ReadJSON(&msg); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Time{})
	return reflect.DeepEqual(msg, map[string]any{"type": "interrupt"})
}

func TestRunCodeCancelInterruptsTheRun(t *testing.T) {
	agent := newInterpAgent(t, interpFeatures, nil, func(conn *websocket.Conn) {
		sendFrame(conn, map[string]any{"type": "stdout", "text": "working"})
		if !readInterrupt(conn) {
			closeWith(conn, websocket.CloseInternalServerErr, "no interrupt")
			return
		}
		sendFrame(conn, map[string]any{"type": "control", "text": "interrupted"})
		closeWith(conn, websocket.CloseNormalClosure, "")
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exec, err := agent.client(t).RunCode(ctx, "sb-1", "while True: pass", RunCodeOptions{OnStdout: func(string) { cancel() }})
	if err != nil || !exec.Interrupted || !reflect.DeepEqual(exec.Logs.Stdout, []string{"working"}) {
		t.Fatalf("err=%v exec=%+v", err, exec)
	}
}

func TestRunCodeCancelGivesUpAfterTheGrace(t *testing.T) {
	old := codeRunInterruptGrace
	codeRunInterruptGrace = 50 * time.Millisecond
	t.Cleanup(func() { codeRunInterruptGrace = old })

	interrupted := make(chan bool, 1)
	agent := newInterpAgent(t, interpFeatures, nil, func(conn *websocket.Conn) {
		sendFrame(conn, map[string]any{"type": "stdout", "text": "stuck"})
		interrupted <- readInterrupt(conn)
		// Say nothing more: the client must give up on its own.
		_, _, _ = conn.ReadMessage()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	exec, err := agent.client(t).RunCode(ctx, "sb-1", "x", RunCodeOptions{OnStdout: func(string) { cancel() }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if exec == nil || !reflect.DeepEqual(exec.Logs.Stdout, []string{"stuck"}) || exec.Interrupted {
		t.Fatalf("partial exec = %+v", exec)
	}
	if !<-interrupted {
		t.Fatal("the agent never got the interrupt")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("gave up after %v", elapsed)
	}
}

func TestRunCodeCancelledBeforeTheSocketOpens(t *testing.T) {
	agent := newInterpAgent(t, interpFeatures, nil, func(conn *websocket.Conn) {
		closeWith(conn, websocket.CloseNormalClosure, "")
	})
	client := agent.client(t)
	if err := client.RequireToolboxFeatures(context.Background(), "sb-1", FeatureCodeInterpreter); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if exec, err := client.RunCode(ctx, "sb-1", "x", RunCodeOptions{}); err == nil || exec != nil {
		t.Fatalf("RunCode on a cancelled ctx = (%v, %v)", exec, err)
	}
	if agent.startFrame() != nil {
		t.Fatal("a cancelled run sent its code")
	}
}

func TestRunCodeRefusesContextAndLanguage(t *testing.T) {
	agent := newInterpAgent(t, interpFeatures, nil, nil)
	_, err := agent.client(t).RunCode(context.Background(), "sb-1", "x", RunCodeOptions{ContextID: "c", Language: "python"})
	if err == nil || err.Error() != "set context or language, not both" {
		t.Fatalf("err = %v", err)
	}
	if seen := agent.seen(); len(seen) != 0 {
		t.Fatalf("requests sent: %v", seen)
	}
}

func TestRunCodeHandshakeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/toolbox/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"features": interpFeatures})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = io.WriteString(w, `{"error":"not supported"}`)
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, ClientOptions{PATToken: "p", HTTPClient: srv.Client()})
	_, err := client.RunCode(context.Background(), "sb-1", "x", RunCodeOptions{})
	if err == nil || !strings.Contains(err.Error(), "code run websocket dial") || !strings.Contains(err.Error(), "status=501") {
		t.Fatalf("err = %v", err)
	}
}

// Every interpreter call checks the agent first; an older one never sees an
// interpreter request.
func TestCodeInterpreterFeatureGate(t *testing.T) {
	calls := map[string]func(c *Client) error{
		"create": func(c *Client) error {
			_, err := c.CreateCodeContext(context.Background(), "sb-1", CodeContextOptions{})
			return err
		},
		"list":    func(c *Client) error { _, err := c.ListCodeContexts(context.Background(), "sb-1"); return err },
		"get":     func(c *Client) error { _, err := c.GetCodeContext(context.Background(), "sb-1", "c1"); return err },
		"delete":  func(c *Client) error { return c.DeleteCodeContext(context.Background(), "sb-1", "c1") },
		"restart": func(c *Client) error { _, err := c.RestartCodeContext(context.Background(), "sb-1", "c1"); return err },
		"run": func(c *Client) error {
			_, err := c.RunCode(context.Background(), "sb-1", "x", RunCodeOptions{})
			return err
		},
	}
	for _, features := range [][]string{nil, {}, {"exec.argv"}} {
		for name, call := range calls {
			agent := newInterpAgent(t, features, nil, func(conn *websocket.Conn) {})
			err := call(agent.client(t))
			var unsupported *UnsupportedFeatureError
			if !errors.As(err, &unsupported) || !reflect.DeepEqual(unsupported.Features, []string{FeatureCodeInterpreter}) {
				t.Fatalf("%s with features %v: err = %v", name, features, err)
			}
			if seen := agent.seen(); !reflect.DeepEqual(seen, []string{"GET /v1/sandboxes/sb-1/toolbox/version"}) {
				t.Fatalf("%s with features %v sent %v", name, features, seen)
			}
		}
	}
}

func TestCodeContextCalls(t *testing.T) {
	ctxJSON := `{"id":"c/1","language":"javascript","cwd":"/w","createdAt":"2026-11-15T10:00:00Z","active":true}`
	want := CodeContext{ID: "c/1", Language: "javascript", Cwd: "/w", CreatedAt: "2026-11-15T10:00:00Z", Active: true}
	var bodies []string
	var listBody = `{"contexts":[` + ctxJSON + `]}`
	agent := newInterpAgent(t, interpFeatures, func(w http.ResponseWriter, r *http.Request) {
		const base = "/v1/sandboxes/sb-1/toolbox/process/interpreter/context"
		body, _ := io.ReadAll(r.Body)
		switch r.Method + " " + r.URL.EscapedPath() {
		case "POST " + base:
			bodies = append(bodies, string(body))
			_, _ = io.WriteString(w, ctxJSON)
		case "GET " + base:
			_, _ = io.WriteString(w, listBody)
		case "GET " + base + "/c%2F1", "POST " + base + "/c%2F1/restart":
			_, _ = io.WriteString(w, ctxJSON)
		case "DELETE " + base + "/c%2F1":
			_, _ = io.WriteString(w, `{"message":"Context deleted successfully"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found","message":"context not found"}`)
		}
	}, nil)
	c := agent.client(t)
	ctx := context.Background()

	got, err := c.CreateCodeContext(ctx, "sb-1", CodeContextOptions{Language: "javascript", Cwd: "/w"})
	if err != nil || got != want {
		t.Fatalf("create = (%+v, %v)", got, err)
	}
	if _, err := c.CreateCodeContext(ctx, "sb-1", CodeContextOptions{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bodies, []string{`{"language":"javascript","cwd":"/w"}`, `{}`}) {
		t.Fatalf("create bodies = %q", bodies)
	}
	list, err := c.ListCodeContexts(ctx, "sb-1")
	if err != nil || len(list) != 1 || list[0] != want {
		t.Fatalf("list = (%+v, %v)", list, err)
	}
	listBody = `{"contexts":null}`
	if list, err := c.ListCodeContexts(ctx, "sb-1"); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("null list = (%#v, %v)", list, err)
	}
	if got, err := c.GetCodeContext(ctx, "sb-1", "c/1"); err != nil || got != want {
		t.Fatalf("get = (%+v, %v)", got, err)
	}
	if got, err := c.RestartCodeContext(ctx, "sb-1", "c/1"); err != nil || got != want {
		t.Fatalf("restart = (%+v, %v)", got, err)
	}
	if err := c.DeleteCodeContext(ctx, "sb-1", "c/1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.GetCodeContext(ctx, "sb-1", "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get unknown = %v, want ErrNotFound", err)
	}
	if err := c.DeleteCodeContext(ctx, "sb-1", "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete unknown = %v, want ErrNotFound", err)
	}
	before := len(agent.seen())
	for name, call := range map[string]func() error{
		"get":     func() error { _, err := c.GetCodeContext(ctx, "sb-1", " "); return err },
		"delete":  func() error { return c.DeleteCodeContext(ctx, "sb-1", "") },
		"restart": func() error { _, err := c.RestartCodeContext(ctx, "sb-1", ""); return err },
	} {
		if err := call(); err == nil || err.Error() != "context id is required" {
			t.Fatalf("%s with no id: %v", name, err)
		}
	}
	if after := len(agent.seen()); after != before {
		t.Fatalf("calls with no context id sent %d requests", after-before)
	}
}

// Create and restart are not retried once they may have reached the agent:
// a second create makes a second context, a second restart wipes a run.
func TestCodeContextWritesAreNotRetried(t *testing.T) {
	var mu sync.Mutex
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/toolbox/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"features": interpFeatures})
			return
		}
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	retries, delay := 3, 1
	c := NewClient(srv.URL, ClientOptions{PATToken: "p", HTTPClient: srv.Client(), Retry: &RetryConfig{MaxRetries: &retries, BaseDelayMs: &delay, MaxDelayMs: &delay}})
	if _, err := c.CreateCodeContext(context.Background(), "sb-1", CodeContextOptions{}); err == nil {
		t.Fatal("create succeeded on a 502")
	}
	if _, err := c.RestartCodeContext(context.Background(), "sb-1", "c1"); err == nil {
		t.Fatal("restart succeeded on a 502")
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 2 {
		t.Fatalf("%d POSTs for one create and one restart", posts)
	}
}
