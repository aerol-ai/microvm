package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

func serveToolbox(d *Driver, id, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	d.ServeToolbox(req.Context(), id, "tok", rec, req)
	return rec
}

// The WASM toolbox runs in sandboxd, on the host. Its session routes used to
// hand the caller's command to a toolboxd sessions Manager, which started it
// with a host shell as the daemon user. Driven through ServeToolbox (the path
// the v1, SSH, Daytona and Runloop surfaces reach), interactive sessions
// answer 501, and a /process/session command runs inside the wasm engine as
// the sandbox's own module: the command each request carries would touch a
// marker file on the host, and on WASM it is only argv to the guest.
func TestServeToolboxSessionCommandsStayInTheEngine(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
	marker := filepath.Join(t.TempDir(), "host-marker")
	touch := "touch " + marker

	if rec := serveToolbox(d, id, http.MethodPost, "/sessions", `{"name":"s1","command":"`+touch+`"}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("native session = %d %s", rec.Code, rec.Body.String())
	}
	if rec := serveToolbox(d, id, http.MethodPost, "/process/session", `{"sessionId":"s1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	rec := serveToolbox(d, id, http.MethodPost, "/process/session/s1/exec", `{"command":"`+touch+`"}`)
	var res toolboxwire.SessionExecuteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("exec = %d %s", rec.Code, rec.Body.String())
	}
	// The stdio guest took "touch" as argv[0] and the marker path as an
	// unknown mode.
	if res.ExitCode == nil || *res.ExitCode != 2 || res.Stderr == nil || !strings.Contains(*res.Stderr, "unknown mode: "+marker) {
		t.Fatalf("exec result = %s", rec.Body.String())
	}
	rec = serveToolbox(d, id, http.MethodPost, "/process/session/s1/exec", `{"command":"`+touch+`","runAsync":true}`)
	res = toolboxwire.SessionExecuteResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.CmdID == "" || res.ExitCode != nil {
		t.Fatalf("async exec = %d %s", rec.Code, rec.Body.String())
	}
	waitFor(t, "async command to end", func() bool {
		rec := serveToolbox(d, id, http.MethodGet, "/process/session/s1/command/"+res.CmdID, "")
		return strings.Contains(rec.Body.String(), `"exitCode":2`)
	})
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a session command reached the host (stat err %v)", err)
	}
	inst, _ := d.instance(id)
	if _, err := os.Stat(filepath.Join(inst.workDir, ".aerol-sessions")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session recording dir exists (stat err %v): a toolboxd session manager was built", err)
	}
}

// A sandbox the driver does not know answers the toolbox's 404 before any
// session route runs; sessionsFor refuses it too.
func TestServeToolboxSessionsUnknownSandbox(t *testing.T) {
	d := New(Config{}, nil)
	if rec := serveToolbox(d, "missing", http.MethodGet, "/process/session", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown sandbox = %d", rec.Code)
	}
	s := sandboxSessions{driver: d, id: "missing"}
	if _, err := s.Create("x"); err == nil {
		t.Fatal("create on an unknown sandbox")
	}
	if got := s.List(); got != nil {
		t.Fatalf("list = %v", got)
	}
	if _, err := s.Get("x"); err == nil {
		t.Fatal("get on an unknown sandbox")
	}
	if err := s.Delete("x"); err == nil {
		t.Fatal("delete on an unknown sandbox")
	}
	if _, err := s.Exec(t.Context(), "x", toolhostCommand("mod"), false); err == nil {
		t.Fatal("exec on an unknown sandbox")
	}
	if _, err := s.Command("x", "y"); err == nil {
		t.Fatal("command on an unknown sandbox")
	}
	if _, _, err := s.Logs("x", "y", toolboxwire.LogQuery{}); err == nil {
		t.Fatal("logs on an unknown sandbox")
	}
	if _, err := s.Follow("x", "y"); err == nil {
		t.Fatal("follow on an unknown sandbox")
	}
	if err := s.Input(context.Background(), "x", "y", nil); err == nil {
		t.Fatal("input on an unknown sandbox")
	}
}

// Session routes driven over a real listener: a follow WebSocket through
// ServeToolbox sees a finished command's output and a clean close.
func TestServeToolboxSessionFollow(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.ServeToolbox(r.Context(), id, "tok", w, r)
	}))
	defer ts.Close()
	if rec := serveToolbox(d, id, http.MethodPost, "/process/session", `{"sessionId":"f"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	rec := serveToolbox(d, id, http.MethodPost, "/process/session/f/exec", `{"command":"aerolstdio args one two"}`)
	var res toolboxwire.SessionExecuteResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	frames := followFrames(t, ts.URL+"/process/session/f/command/"+res.CmdID+"/logs?follow=true")
	if strings.Join(frames, "") != "\x01\x01\x01one\ntwo\n" {
		t.Fatalf("follow = %q", frames)
	}
}

func toolhostCommand(argv ...string) toolhost.SessionCommand {
	return toolhost.SessionCommand{Text: strings.Join(argv, " "), Argv: argv}
}

// followFrames reads a follow WebSocket to its end, which must be a normal
// close.
func followFrames(t *testing.T, url string) []string {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http"), http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var frames []string
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				t.Fatalf("follow ended with %v", err)
			}
			return frames
		}
		frames = append(frames, string(data))
	}
}
