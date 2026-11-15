package daytona

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestManagerOptions(t *testing.T) {
	l := &fakeLauncher{langs: []string{codeinterp.LangPython}}
	lim := codeinterp.NewLimit(3)
	opts := ManagerOptions(l, lim, "/home/user")
	if opts.Launcher != l || opts.Limit != lim || opts.DefaultCwd != "/home/user" || !opts.ProtectDefaults || opts.ListDefaults {
		t.Fatalf("options = %+v", opts)
	}
	if opts.DefaultID(codeinterp.LangPython) != DefaultContextID || opts.DefaultID(codeinterp.LangBash) != "" {
		t.Fatal("python's default is not \"default\"")
	}
	if !reflect.DeepEqual(opts.Languages, []string{codeinterp.LangPython}) {
		t.Fatalf("languages = %v, want the launcher's", opts.Languages)
	}
	// A launcher that cannot list its languages leaves the Manager's default.
	if opts := ManagerOptions(launcherOnly{l}, nil, ""); opts.Languages != nil {
		t.Fatalf("languages = %v, want nil", opts.Languages)
	}
}

type launcherOnly struct{ codeinterp.Launcher }

func TestContextRoutes(t *testing.T) {
	l := &fakeLauncher{langs: []string{codeinterp.LangPython}}
	e := newTestEnv(t, l, nil)

	status, body := e.do(t, http.MethodPost, "/context", "")
	if status != http.StatusOK {
		t.Fatalf("create = %d %v", status, body)
	}
	for _, field := range []string{"id", "cwd", "createdAt", "active", "language"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("context lacks %q: %v", field, body)
		}
	}
	id := body["id"].(string)
	if body["cwd"] != "/work" || body["language"] != "python" || body["active"] != true {
		t.Fatalf("context = %v", body)
	}
	if created, err := time.Parse(time.RFC3339Nano, body["createdAt"].(string)); err != nil || created.Location() != time.UTC {
		t.Fatalf("createdAt = %v (%v)", body["createdAt"], err)
	}

	status, body = e.do(t, http.MethodPost, "/context", `{"cwd":"/tmp","language":"py"}`)
	if status != http.StatusOK || body["cwd"] != "/tmp" || body["language"] != "python" {
		t.Fatalf("create with cwd = %d %v", status, body)
	}
	second := body["id"].(string)

	// The default context exists, but is not listed.
	if status, body = e.do(t, http.MethodGet, "/context/default", ""); status != http.StatusOK || body["id"] != "default" {
		t.Fatalf("get default = %d %v", status, body)
	}
	status, body = e.do(t, http.MethodGet, "/context", "")
	list := body["contexts"].([]any)
	if status != http.StatusOK || len(list) != 2 || list[0].(map[string]any)["id"] != id || list[1].(map[string]any)["id"] != second {
		t.Fatalf("list = %d %v", status, body)
	}

	if status, body = e.do(t, http.MethodGet, "/context/"+id, ""); status != http.StatusOK || body["id"] != id {
		t.Fatalf("get = %d %v", status, body)
	}
	if status, body = e.do(t, http.MethodPost, "/context/"+id+"/restart", ""); status != http.StatusOK || body["id"] != id || body["active"] != true {
		t.Fatalf("restart = %d %v", status, body)
	}
	if status, _ = e.do(t, http.MethodPost, "/context/default/restart", ""); status != http.StatusOK {
		t.Fatalf("restart default = %d", status)
	}
	if status, body = e.do(t, http.MethodDelete, "/context/"+id, ""); status != http.StatusOK || body["message"] != "Context deleted successfully" {
		t.Fatalf("delete = %d %v", status, body)
	}

	errorCases := []struct {
		method, path, body string
		status             int
		msg                string
	}{
		{http.MethodDelete, "/context/" + id, "", http.StatusNotFound, "context not found: " + id},
		{http.MethodGet, "/context/nope", "", http.StatusNotFound, "context not found: nope"},
		{http.MethodPost, "/context/nope/restart", "", http.StatusNotFound, "context not found: nope"},
		{http.MethodDelete, "/context/default", "", http.StatusBadRequest, "the default context cannot be deleted"},
		{http.MethodPost, "/context", `{"cwd":`, http.StatusBadRequest, "invalid request body"},
		{http.MethodPost, "/context", `{"language":"cobol"}`, http.StatusBadRequest, "unsupported language"},
		{http.MethodPost, "/context", `{"language":"javascript"}`, http.StatusBadRequest, "unsupported language: javascript"},
		{http.MethodPost, "/context", strings.Repeat(" ", maxBody+1), http.StatusBadRequest, "invalid request body"},
		{http.MethodPut, "/context", "", http.StatusMethodNotAllowed, "method not allowed"},
		{http.MethodPost, "/context/x", "", http.StatusMethodNotAllowed, "method not allowed"},
		{http.MethodGet, "/context/x/restart", "", http.StatusMethodNotAllowed, "method not allowed"},
		{http.MethodPost, "/execute", "", http.StatusMethodNotAllowed, "method not allowed"},
		{http.MethodGet, "/context/a/b", "", http.StatusNotFound, "not found"},
		{http.MethodGet, "/nothing", "", http.StatusNotFound, "not found"},
	}
	for _, tc := range errorCases {
		status, body := e.do(t, tc.method, tc.path, tc.body)
		if status != tc.status || !strings.HasPrefix(body["error"].(string), tc.msg) || body["message"] != body["error"] {
			t.Errorf("%s %s = %d %v, want %d %q", tc.method, tc.path, status, body, tc.status, tc.msg)
		}
	}
}

func TestContextRouteFailures(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, func(o *codeinterp.Options) { o.Limit = codeinterp.NewLimit(1) })

	// An empty list is [], never null.
	if _, body := e.do(t, http.MethodGet, "/context", ""); body["contexts"] == nil {
		t.Fatalf("list = %v", body)
	}

	l.setFail(&codeinterp.MissingInterpreterError{Language: "python", Programs: []string{"python3", "python"}})
	status, body := e.do(t, http.MethodPost, "/context", "{}")
	if status != http.StatusInternalServerError || !strings.Contains(body["error"].(string), "python interpreter not found") {
		t.Fatalf("launch failure = %d %v", status, body)
	}
	l.setFail(nil)

	if status, _ = e.do(t, http.MethodPost, "/context", "{}"); status != http.StatusOK {
		t.Fatalf("create = %d", status)
	}
	if status, body = e.do(t, http.MethodPost, "/context", "{}"); status != http.StatusTooManyRequests {
		t.Fatalf("over the limit = %d %v", status, body)
	}
	// "default" needs a slot too.
	if status, _ = e.do(t, http.MethodGet, "/context/default", ""); status != http.StatusTooManyRequests {
		t.Fatalf("default over the limit = %d", status)
	}

	id := e.m.List()[0].ID
	l.setFail(errors.New("driver broke"))
	if status, body = e.do(t, http.MethodPost, "/context/"+id+"/restart", ""); status != http.StatusInternalServerError || body["error"] != internalErrorText {
		t.Fatalf("failed restart = %d %v", status, body)
	}

	e.m.Close()
	if status, _ = e.do(t, http.MethodGet, "/context/"+id, ""); status != http.StatusServiceUnavailable {
		t.Fatalf("closed manager = %d", status)
	}
}

func TestExecuteFrames(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)

	res := e.run(t, ExecuteRequest{Code: "print hello\nerr warn\nresult\nshow\nfail"})
	if res.subprotocol != "sandbox.bearer" {
		t.Fatalf("subprotocol = %q", res.subprotocol)
	}
	if want := []string{"stdout", "stderr", "error", "control"}; !reflect.DeepEqual(res.types(), want) {
		t.Fatalf("frames = %v, want %v (no rich frames for a Daytona client)", res.frames, want)
	}
	for _, f := range res.frames {
		for _, field := range []string{"type", "text", "name", "value", "traceback"} {
			if _, ok := f[field]; !ok {
				t.Fatalf("frame %v lacks %q", f, field)
			}
		}
	}
	if res.frames[2]["name"] != "ValueError" || res.frames[2]["value"] != "bad" || res.frames[2]["traceback"] != "Traceback..." {
		t.Fatalf("error frame = %v", res.frames[2])
	}
	if res.text("control") != "completed" || res.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("end = %v %d", res.frames[3], res.closeCode)
	}

	// The same run with richOutput gets results and the count.
	res = e.run(t, ExecuteRequest{Code: "result\nshow", RichOutput: true})
	if want := []string{"execution_count", "result", "result", "control"}; !reflect.DeepEqual(res.types(), want) {
		t.Fatalf("rich frames = %v", res.types())
	}
	if res.frames[0]["count"] != float64(2) {
		t.Fatalf("count = %v", res.frames[0])
	}
	main := res.frames[1]
	if main["text"] != "42" || main["png"] != "iVBOR" || main["is_main_result"] != true ||
		!reflect.DeepEqual(main["json"], map[string]any{"a": float64(1)}) ||
		!reflect.DeepEqual(main["data"], map[string]any{"c": []any{float64(1)}}) ||
		!reflect.DeepEqual(main["extra"], map[string]any{"application/x-custom": "c"}) {
		t.Fatalf("main result = %v", main)
	}
	if shown := res.frames[2]; shown["text"] != "shown" || shown["is_main_result"] != false || shown["extra"] != nil {
		t.Fatalf("display result = %v", shown)
	}

	// Env and cwd reach the run; envs are per run.
	if res = e.run(t, map[string]any{"code": "env\ncwd", "envs": map[string]string{"K": "v"}}); res.text("stdout") != "v/work" {
		t.Fatalf("env/cwd = %q", res.text("stdout"))
	}
}

func TestExecuteContexts(t *testing.T) {
	l := &fakeLauncher{langs: []string{codeinterp.LangPython}}
	e := newTestEnv(t, l, nil)

	// No contextId: python's "default", one kernel for every such run.
	e.run(t, ExecuteRequest{Code: "print a"})
	e.run(t, ExecuteRequest{Code: "print b"})
	if info, err := e.m.Get(DefaultContextID); err != nil || l.launches != 1 || info.Language != "python" {
		t.Fatalf("default = %+v %v, launches %d", info, err, l.launches)
	}
	// An explicit "default" is the same context.
	if res := e.run(t, ExecuteRequest{Code: "print c", ContextID: "default"}); res.text("stdout") != "c" || l.launches != 1 {
		t.Fatalf("contextId default = %v, launches %d", res.frames, l.launches)
	}

	info, err := e.m.Create(t.Context(), "python", "/srv")
	if err != nil {
		t.Fatal(err)
	}
	if res := e.run(t, ExecuteRequest{Code: "cwd", ContextID: info.ID}); res.text("stdout") != "/srv" {
		t.Fatalf("run in a context = %v", res.frames)
	}

	cases := []struct {
		name   string
		first  any
		code   int
		reason string
	}{
		{"bad json", "{nope", websocket.CloseProtocolError, "invalid execute request"},
		{"empty code", ExecuteRequest{Code: "  \n"}, websocket.ClosePolicyViolation, "code is required"},
		{"negative timeout", map[string]any{"code": "x", "timeout": -1}, websocket.ClosePolicyViolation, "timeout must be"},
		{"unknown context", ExecuteRequest{Code: "x", ContextID: "nope"}, websocket.ClosePolicyViolation, "context not found: nope"},
		{"unsupported language", ExecuteRequest{Code: "x", Language: "javascript"}, websocket.ClosePolicyViolation, "unsupported language: javascript"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.run(t, tc.first)
			if res.closeCode != tc.code || !strings.HasPrefix(res.closeReason, tc.reason) || len(res.frames) != 0 {
				t.Fatalf("close = %d %q (frames %v), want %d %q", res.closeCode, res.closeReason, res.frames, tc.code, tc.reason)
			}
		})
	}
}

func TestExecuteLimitsAndLaunchFailure(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, func(o *codeinterp.Options) {
		o.Limit = codeinterp.NewLimit(1)
		o.QueueLimit = 1
	})
	info, err := e.m.Create(t.Context(), "python", "")
	if err != nil {
		t.Fatal(err)
	}
	// The default context needs a slot the limit no longer has.
	if res := e.run(t, ExecuteRequest{Code: "x"}); res.closeCode != websocket.ClosePolicyViolation || !strings.Contains(res.closeReason, "too many") {
		t.Fatalf("over the limit = %d %q", res.closeCode, res.closeReason)
	}

	// One run in flight fills the queue of one; the next is refused.
	busy := e.dial(t, nil)
	if err := busy.WriteJSON(ExecuteRequest{Code: "sleep", ContextID: info.ID}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "run in flight", func() bool { k := l.last(); return k != nil && k.runs.Load() == 1 })
	queued := e.dial(t, nil)
	if err := queued.WriteJSON(ExecuteRequest{Code: "print q", ContextID: info.ID}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if res := e.run(t, ExecuteRequest{Code: "x", ContextID: info.ID}); res.closeCode != websocket.ClosePolicyViolation || !strings.Contains(res.closeReason, "too many runs") {
		t.Fatalf("queue full = %d %q", res.closeCode, res.closeReason)
	}
	if err := e.m.Interrupt(info.ID); err != nil {
		t.Fatal(err)
	}
	if res := readAll(t, busy, nil); res.text("control") != "interrupted" || res.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("interrupted run = %v %d", res.frames, res.closeCode)
	}

	// A kernel that cannot start: 1011 with the reason.
	l.setFail(&codeinterp.MissingInterpreterError{Language: "python", Programs: []string{"python3", "python"},
		Detail: strings.Repeat("very long detail ", 20)})
	if _, err := e.m.Restart(t.Context(), info.ID); err == nil {
		t.Fatal("restart with a broken launcher succeeded")
	}
	res := e.run(t, ExecuteRequest{Code: "x", ContextID: info.ID})
	if res.closeCode != websocket.CloseInternalServerErr || !strings.HasPrefix(res.closeReason, "python interpreter not found") || len(res.closeReason) > maxCloseReason {
		t.Fatalf("launch failure = %d %q", res.closeCode, res.closeReason)
	}
}

func TestExecuteTimeoutDeathRestart(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	info, err := e.m.Create(t.Context(), "python", "")
	if err != nil {
		t.Fatal(err)
	}

	// A timeout interrupts; code that stops ends "interrupted" + 4008.
	res := e.run(t, map[string]any{"code": "sleep", "contextId": info.ID, "timeout": 0.2})
	if res.text("control") != "interrupted" || res.closeCode != CloseTimeout {
		t.Fatalf("timeout = %v %d", res.frames, res.closeCode)
	}
	// Code that ignores the interrupt is killed after the grace period.
	start := time.Now()
	res = e.run(t, map[string]any{"code": "ignore", "contextId": info.ID, "timeout": 0.1})
	if res.closeCode != CloseTimeout || time.Since(start) < interruptGrace {
		t.Fatalf("kill after grace = %d after %s", res.closeCode, time.Since(start))
	}
	if got, _ := e.m.Get(info.ID); got.Active {
		t.Fatal("context still active after its kernel was killed")
	}

	if res = e.run(t, ExecuteRequest{Code: "print x\ndie", ContextID: info.ID}); res.closeCode != websocket.CloseGoingAway || res.closeReason != "worker process ended" || res.text("stdout") != "x" {
		t.Fatalf("death = %v %d %q", res.frames, res.closeCode, res.closeReason)
	}
	// An interrupt that killed the interpreter (WASM) still ends as an
	// interrupt; the context has lost its state.
	if res = e.run(t, ExecuteRequest{Code: "print x\nkilled", ContextID: info.ID}); res.closeCode != websocket.CloseNormalClosure || res.text("control") != "interrupted" {
		t.Fatalf("killed by interrupt = %v %d %q", res.frames, res.closeCode, res.closeReason)
	}
	if got, _ := e.m.Get(info.ID); got.Active {
		t.Fatal("context active after an interrupt killed its kernel")
	}

	// Deleting the context under a run ends it with "context shutdown".
	conn := e.dial(t, nil)
	if err := conn.WriteJSON(ExecuteRequest{Code: "sleep", ContextID: info.ID}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "run in flight", func() bool { k := l.last(); return k != nil && k.runs.Load() == 1 })
	if status, _ := e.do(t, http.MethodDelete, "/context/"+info.ID, ""); status != http.StatusOK {
		t.Fatalf("delete = %d", status)
	}
	if res = readAll(t, conn, nil); res.closeCode != websocket.CloseGoingAway || res.closeReason != "context shutdown" {
		t.Fatalf("deleted under the run = %d %q", res.closeCode, res.closeReason)
	}

	// A timeout of 0 means none; a huge one is none too.
	if res = e.run(t, map[string]any{"code": "wait 50ms\nprint ok", "timeout": 0}); res.text("control") != "completed" {
		t.Fatalf("timeout 0 = %v", res.frames)
	}
	if res = e.run(t, map[string]any{"code": "print ok", "timeout": 1e300}); res.text("control") != "completed" {
		t.Fatalf("huge timeout = %v", res.frames)
	}
}

func TestExecuteInterruptMessageAndDisconnect(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)

	conn := e.dial(t, nil)
	if err := conn.WriteJSON(ExecuteRequest{Code: "print started\nsleep"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "run in flight", func() bool { k := l.last(); return k != nil && k.runs.Load() == 1 })
	for _, msg := range []string{`{"type":"noise"}`, `not json`, `{"type":"interrupt"}`} {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	if res := readAll(t, conn, nil); res.text("control") != "interrupted" || res.text("stdout") != "started" {
		t.Fatalf("interrupt = %v", res.frames)
	}

	// A client that goes away does not stop its run.
	conn = e.dial(t, nil)
	if err := conn.WriteJSON(ExecuteRequest{Code: "wait 300ms\nprint late"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "second run", func() bool { return l.last().runs.Load() == 2 })
	_ = conn.Close()
	waitUntil(t, "run to finish without its client", func() bool { return l.last().finished.Load() == 2 })
	if res := e.run(t, ExecuteRequest{Code: "print next"}); res.text("stdout") != "next" {
		t.Fatalf("next run = %v", res.frames)
	}
}

func TestExecutePingsAndSilentClient(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	e.h.live = liveness{interval: 50 * time.Millisecond, pongWait: 300 * time.Millisecond, writeWait: time.Second}

	conn := e.dial(t, nil)
	pings := make(chan struct{}, 16)
	conn.SetPingHandler(func(string) error {
		pings <- struct{}{}
		return conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})
	if err := conn.WriteJSON(ExecuteRequest{Code: "wait 400ms\nprint done"}); err != nil {
		t.Fatal(err)
	}
	res := readAll(t, conn, nil)
	if len(pings) < 2 || res.text("stdout") != "done" || res.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("%d pings, frames %v, close %d", len(pings), res.frames, res.closeCode)
	}

	// A client that sends its run and then never reads (so never answers a
	// ping) is dropped; the run still ends.
	silent := e.dial(t, nil)
	if err := silent.WriteJSON(ExecuteRequest{Code: "wait 600ms\nprint unseen"}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "silent client's run to end", func() bool { return l.last().finished.Load() == 2 })

	// No first message in time: 1002.
	e.h.firstWait = 100 * time.Millisecond
	idle := e.dial(t, nil)
	_ = idle.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := idle.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.CloseProtocolError {
		t.Fatalf("idle client = %v", err)
	}
}

func TestUpgradeFailureIsJSON(t *testing.T) {
	e := newTestEnv(t, &fakeLauncher{}, nil)
	status, body := e.do(t, http.MethodGet, "/execute", "")
	if status != http.StatusBadRequest || body["error"] == nil {
		t.Fatalf("plain GET /execute = %d %v", status, body)
	}
}

func TestNewHandlerDefaults(t *testing.T) {
	m := codeinterp.NewManager(ManagerOptions(&fakeLauncher{}, nil, ""))
	defer m.Close()
	h, ok := NewHandler(m, nil).(*handler)
	if !ok || h.logger == nil || h.live != defaultLiveness || h.firstWait != firstMessageWait || h.maxMessage != DefaultMaxMessageBytes {
		t.Fatalf("handler = %+v", h)
	}
	if zero := NewHandler(m, nil, WithMaxMessageBytes(0)).(*handler); zero.maxMessage != DefaultMaxMessageBytes {
		t.Fatalf("WithMaxMessageBytes(0) = %d", zero.maxMessage)
	}
}

// A host that buffers messages for many sandboxes passes a smaller cap; a
// first message over it ends the connection with 1009 and runs nothing.
func TestExecuteMessageLimit(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	WithMaxMessageBytes(1024)(e.h)
	res := e.run(t, ExecuteRequest{Code: "print " + strings.Repeat("x", 2048)})
	if res.closeCode != websocket.CloseMessageTooBig || len(res.frames) != 0 || l.launches != 0 {
		t.Fatalf("2 KiB message = %d %q (frames %v, launches %d)", res.closeCode, res.closeReason, res.frames, l.launches)
	}
	if res := e.run(t, ExecuteRequest{Code: "print small"}); res.text("stdout") != "small" {
		t.Fatalf("small message = %v", res.frames)
	}
}

func TestCloseFor(t *testing.T) {
	h := newHandler(nil, nil)
	for _, tc := range []struct {
		err    error
		code   int
		reason string
	}{
		{codeinterp.ErrNotFound, websocket.ClosePolicyViolation, "context not found: id"},
		{codeinterp.ErrQueueFull, websocket.ClosePolicyViolation, codeinterp.ErrQueueFull.Error()},
		{fmt.Errorf("%w: empty name", codeinterp.ErrInvalidEnv), websocket.ClosePolicyViolation, "invalid environment variable: empty name"},
		{codeinterp.ErrClosed, websocket.CloseGoingAway, codeinterp.ErrClosed.Error()},
		{fmt.Errorf("launch: %w", &codeinterp.MissingInterpreterError{Language: "r", Programs: []string{"Rscript"}}),
			websocket.CloseInternalServerErr, "r interpreter not found in the sandbox (looked for [Rscript])"},
		{errors.New("driver /tmp/x/driver.py broke"), websocket.CloseInternalServerErr, internalErrorText},
	} {
		if code, reason := h.closeFor(tc.err, "id"); code != tc.code || reason != tc.reason {
			t.Errorf("closeFor(%v) = %d %q, want %d %q", tc.err, code, reason, tc.code, tc.reason)
		}
	}
}

func TestCloseReason(t *testing.T) {
	if got := closeReason("short"); got != "short" {
		t.Fatal(got)
	}
	long := strings.Repeat("é", 100) // 200 bytes
	got := closeReason(long)
	if len(got) > maxCloseReason || !strings.HasPrefix(long, got) || len(got) != 122 {
		t.Fatalf("closeReason cut to %d bytes: %q", len(got), got)
	}
}

// A client's {"type":"interrupt"} stops its own run only. It used to call
// Manager.Interrupt, which stops whatever run the context has, so a client
// still waiting in the queue stopped another client's run.
func TestExecuteInterruptHitsOnlyItsOwnRun(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	info, err := e.m.Create(t.Context(), "python", "")
	if err != nil {
		t.Fatal(err)
	}
	busy := e.dial(t, nil)
	if err := busy.WriteJSON(ExecuteRequest{Code: "print a\nsleep", ContextID: info.ID}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "first run in flight", func() bool { k := l.last(); return k != nil && k.runs.Load() == 1 })
	queued := e.dial(t, nil)
	if err := queued.WriteJSON(ExecuteRequest{Code: "print b\nsleep", ContextID: info.ID}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	// The queued client gives up on its run.
	if err := queued.WriteMessage(websocket.TextMessage, []byte(`{"type":"interrupt"}`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := l.last().finished.Load(); n != 0 {
		t.Fatalf("the running client's run ended (%d finished): the interrupt reached it", n)
	}
	// The running client stops its own run; the queued one then starts and
	// ends at once, interrupted as its client asked.
	if err := busy.WriteMessage(websocket.TextMessage, []byte(`{"type":"interrupt"}`)); err != nil {
		t.Fatal(err)
	}
	if res := readAll(t, busy, nil); res.text("stdout") != "a" || res.text("control") != "interrupted" {
		t.Fatalf("running client = %v", res.frames)
	}
	if res := readAll(t, queued, nil); res.text("control") != "interrupted" || res.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("queued client = %v %d", res.frames, res.closeCode)
	}
	// An interrupt after the run is over is ignored, and the context is fine.
	if res := e.run(t, ExecuteRequest{Code: "print c", ContextID: info.ID}); res.text("control") != "completed" {
		t.Fatalf("next run = %v", res.frames)
	}
}

// Daytona's Go SDK reads close codes 1000 and 1001 as a normal end. A run
// whose interpreter died, or whose context was restarted or deleted, sends
// an error frame first, so the client sees a failure.
func TestExecuteKernelLossIsAnErrorFrame(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	info, err := e.m.Create(t.Context(), "python", "")
	if err != nil {
		t.Fatal(err)
	}
	res := e.run(t, ExecuteRequest{Code: "print x\ndie", ContextID: info.ID})
	want := map[string]any{"type": "error", "text": "", "name": "WorkerProcessEnded", "value": "worker process ended", "traceback": ""}
	if got := res.types(); !reflect.DeepEqual(got, []string{"stdout", "error"}) || !reflect.DeepEqual(res.frames[1], want) ||
		res.closeCode != websocket.CloseGoingAway || res.closeReason != "worker process ended" {
		t.Fatalf("death = %v %d %q", res.frames, res.closeCode, res.closeReason)
	}

	// A fresh context, so the run below is the only one its kernel saw.
	other, err := e.m.Create(t.Context(), "python", "")
	if err != nil {
		t.Fatal(err)
	}
	conn := e.dial(t, nil)
	if err := conn.WriteJSON(ExecuteRequest{Code: "sleep", ContextID: other.ID}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "run in flight", func() bool { k := l.last(); return k != nil && k.runs.Load() == 1 })
	if _, err := e.m.Restart(t.Context(), other.ID); err != nil {
		t.Fatal(err)
	}
	res = readAll(t, conn, nil)
	want = map[string]any{"type": "error", "text": "", "name": "ContextRestarting", "value": "context shutdown", "traceback": ""}
	if len(res.frames) != 1 || !reflect.DeepEqual(res.frames[0], want) ||
		res.closeCode != websocket.CloseGoingAway || res.closeReason != "context shutdown" {
		t.Fatalf("restarted under the run = %v %d %q", res.frames, res.closeCode, res.closeReason)
	}
}

// Env the interpreter cannot set is the client's mistake: 1008, as for
// other bad requests, not 1011.
func TestExecuteInvalidEnv(t *testing.T) {
	e := newTestEnv(t, &fakeLauncher{}, nil)
	res := e.run(t, map[string]any{"code": "print x", "envs": map[string]string{"A=B": "c"}})
	if res.closeCode != websocket.ClosePolicyViolation || !strings.HasPrefix(res.closeReason, "invalid environment variable") || len(res.frames) != 0 {
		t.Fatalf("invalid env = %v %d %q", res.frames, res.closeCode, res.closeReason)
	}
}

// An error the adapter does not know can carry host paths (a WASM module
// file, a driver script): it is logged whole and the client gets a generic
// reason. A missing interpreter keeps its message, which says what to
// install.
func TestUnknownErrorsAreGeneric(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	var logs strings.Builder
	var mu sync.Mutex
	e.h.logger = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	const secret = "open /var/lib/aerolvm/wasm/modules/python.wasm: permission denied"
	l.setFail(errors.New(secret))

	res := e.run(t, ExecuteRequest{Code: "x"})
	if res.closeCode != websocket.CloseInternalServerErr || res.closeReason != "code interpreter internal error" {
		t.Fatalf("execute = %d %q", res.closeCode, res.closeReason)
	}
	status, body := e.do(t, http.MethodPost, "/context", "{}")
	if status != http.StatusInternalServerError || body["error"] != "code interpreter internal error" {
		t.Fatalf("create = %d %v", status, body)
	}
	mu.Lock()
	logged := logs.String()
	mu.Unlock()
	if strings.Count(logged, "/var/lib/aerolvm/wasm/modules/python.wasm") != 2 {
		t.Fatalf("log = %q, want the full error twice", logged)
	}

	l.setFail(&codeinterp.MissingInterpreterError{Language: "python", Programs: []string{"python3"}})
	if res := e.run(t, ExecuteRequest{Code: "x"}); !strings.HasPrefix(res.closeReason, "python interpreter not found") {
		t.Fatalf("missing interpreter = %d %q", res.closeCode, res.closeReason)
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
