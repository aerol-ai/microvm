package toolhost

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/daytona"
	"github.com/aerol-ai/microvm/internal/codeinterp/e2b"
)

// echoKernel answers every run with its code on stdout, a result and an
// execution count, like a python context would.
type echoKernel struct {
	count     int
	done      chan struct{}
	closeOnce sync.Once
}

func (k *echoKernel) Execute(req codeinterp.Request, sink codeinterp.Sink) (codeinterp.Outcome, error) {
	k.count++
	sink(codeinterp.Event{Kind: codeinterp.EventCount, Count: k.count})
	sink(codeinterp.Event{Kind: codeinterp.EventStdout, Text: "ran " + req.Code + "\n"})
	sink(codeinterp.Event{Kind: codeinterp.EventResult, Main: true, Bundle: map[string]any{"text/plain": "42"}})
	return codeinterp.Outcome{Status: "ok"}, nil
}

func (k *echoKernel) Interrupt() error      { return nil }
func (k *echoKernel) Done() <-chan struct{} { return k.done }
func (k *echoKernel) Close() error {
	k.closeOnce.Do(func() { close(k.done) })
	return nil
}

type echoLauncher struct {
	mu    sync.Mutex
	specs []codeinterp.Spec
}

func (l *echoLauncher) Launch(_ context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.specs = append(l.specs, spec)
	return &echoKernel{done: make(chan struct{})}, nil
}

func (l *echoLauncher) Languages() []string { return []string{codeinterp.LangPython} }

// fakeInterpreters builds the two adapters the way the WASM driver does:
// one Manager per protocol, a shared cap, cwd /work.
type fakeInterpreters struct {
	daytona, e2b http.Handler
}

func (f fakeInterpreters) Daytona() http.Handler { return f.daytona }
func (f fakeInterpreters) E2B() http.Handler     { return f.e2b }

func newFakeInterpreters(t *testing.T, l *echoLauncher) fakeInterpreters {
	t.Helper()
	lim := codeinterp.NewLimit(4)
	dm := codeinterp.NewManager(daytona.ManagerOptions(l, lim, "/work"))
	em := codeinterp.NewManager(e2b.ManagerOptionsAt(l, lim, "/work"))
	t.Cleanup(dm.Close)
	t.Cleanup(em.Close)
	return fakeInterpreters{daytona: daytona.NewHandler(dm, nil), e2b: e2b.NewHandler(em, nil)}
}

func interpServer(t *testing.T, interp Interpreters) string {
	t.Helper()
	h := New(Config{SandboxID: "sb-interp", AuthToken: "tok", WorkDir: t.TempDir(), Interpreters: interp})
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func authed(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestInterpreterDaytonaWebSocket(t *testing.T) {
	l := &echoLauncher{}
	base := interpServer(t, newFakeInterpreters(t, l))

	// A context made over REST (under the sandbox's own prefix, as the
	// toolbox proxy may send it) starts in /work.
	resp := authed(t, http.MethodPost, base+"/sb-interp/process/interpreter/context", `{}`)
	var ctxInfo struct {
		ID, Cwd, Language string
		Active            bool
	}
	if err := json.NewDecoder(resp.Body).Decode(&ctxInfo); err != nil || resp.StatusCode != http.StatusOK || ctxInfo.Cwd != "/work" || !ctxInfo.Active {
		t.Fatalf("create = %d %+v %v", resp.StatusCode, ctxInfo, err)
	}

	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/process/interpreter/execute", http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(map[string]any{"code": "x = 5", "contextId": ctxInfo.ID, "richOutput": true}); err != nil {
		t.Fatal(err)
	}
	var frames []map[string]any
	for {
		var f map[string]any
		if err := conn.ReadJSON(&f); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				t.Fatalf("read: %v (frames %v)", err, frames)
			}
			break
		}
		frames = append(frames, f)
	}
	want := []string{"execution_count", "stdout", "result", "control"}
	if len(frames) != len(want) {
		t.Fatalf("frames = %v", frames)
	}
	for i, typ := range want {
		if frames[i]["type"] != typ {
			t.Fatalf("frame %d = %v, want %s", i, frames[i], typ)
		}
	}
	if frames[1]["text"] != "ran x = 5\n" || frames[3]["text"] != "completed" {
		t.Fatalf("frames = %v", frames)
	}
	if len(l.specs) != 1 || l.specs[0].Cwd != "/work" || l.specs[0].Language != "python" {
		t.Fatalf("launched = %+v", l.specs)
	}

	// The list leaves the default out; an escaped path still routes.
	resp = authed(t, http.MethodGet, base+"/sb-interp/process/interpreter/%63ontext", "")
	var list struct{ Contexts []map[string]any }
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil || resp.StatusCode != http.StatusOK || len(list.Contexts) != 1 {
		t.Fatalf("list = %d %+v %v", resp.StatusCode, list, err)
	}
}

func TestInterpreterE2BStream(t *testing.T) {
	base := interpServer(t, newFakeInterpreters(t, &echoLauncher{}))
	resp := authed(t, http.MethodPost, base+"/interpreter/e2b/execute", `{"code":"print(1)","context_id":null,"language":null,"env_vars":null}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("execute = %d", resp.StatusCode)
	}
	var types []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		types = append(types, line["type"].(string))
		if line["type"] == "stdout" && line["text"] != "ran print(1)\n" {
			t.Fatalf("stdout = %v", line)
		}
	}
	if strings.Join(types, ",") != "number_of_executions,stdout,result,end_of_execution" {
		t.Fatalf("lines = %v", types)
	}

	// E2B's routes are a ServeMux, which matches the escaped path: the
	// sandbox prefix must not survive in RawPath.
	resp = authed(t, http.MethodGet, base+"/sb-interp/interpreter/e2b/%63ontexts", "")
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil || len(list) != 1 || list[0]["cwd"] != "/work" || list[0]["language"] != "python" {
		t.Fatalf("contexts = %v %v", list, err)
	}
	resp = authed(t, http.MethodPost, base+"/interpreter/e2b/execute", `{"code":"1","language":"js"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("javascript on wasm = %d", resp.StatusCode)
	}
	resp = authed(t, http.MethodGet, base+"/interpreter/e2b/health", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}
}

func TestInterpreterRoutes(t *testing.T) {
	withInterp := New(Config{AuthToken: "tok", WorkDir: t.TempDir(), Interpreters: newFakeInterpreters(t, &echoLauncher{})})
	without := New(Config{AuthToken: "tok", WorkDir: t.TempDir()})
	cases := []struct {
		name   string
		host   *Host
		method string
		path   string
		auth   bool
		want   int
		body   string
	}{
		{name: "daytona needs the token", host: withInterp, method: http.MethodGet, path: "/process/interpreter/context", want: http.StatusUnauthorized},
		{name: "e2b needs the token", host: withInterp, method: http.MethodGet, path: "/interpreter/e2b/contexts", want: http.StatusUnauthorized},
		{name: "daytona list", host: withInterp, method: http.MethodGet, path: "/process/interpreter/context", auth: true, want: http.StatusOK, body: `"contexts":[]`},
		{name: "e2b without a route", host: withInterp, method: http.MethodGet, path: "/interpreter/e2b", auth: true, want: http.StatusNotFound},
		{name: "e2b unknown route", host: withInterp, method: http.MethodGet, path: "/interpreter/e2b/nope", auth: true, want: http.StatusNotFound},
		{name: "daytona not wired", host: without, method: http.MethodGet, path: "/process/interpreter/context", auth: true, want: http.StatusNotImplemented},
		{name: "e2b not wired", host: without, method: http.MethodPost, path: "/interpreter/e2b/execute", auth: true, want: http.StatusNotImplemented},
		{name: "features with the interpreter", host: withInterp, method: http.MethodGet, path: "/version", want: http.StatusOK, body: `"features":["code.interpreter"]`},
		{name: "features without it", host: without, method: http.MethodGet, path: "/version", want: http.StatusOK, body: `"features":[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.auth {
				req.Header.Set("Authorization", "Bearer tok")
			}
			rec := httptest.NewRecorder()
			tc.host.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.body) {
				t.Fatalf("%s %s = %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}
