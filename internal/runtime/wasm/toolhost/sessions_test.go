package toolhost

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// sessionRoutes is every action of both session families, as the v1, SSH,
// Daytona and Runloop surfaces call them. The bodies carry a command, as a
// real caller's would; nothing may run it.
var sessionRoutes = []struct {
	method, path, body string
}{
	{http.MethodPost, "/sessions", `{"name":"s1","command":"id"}`},
	{http.MethodGet, "/sessions", ""},
	{http.MethodPut, "/sessions", ""},
	{http.MethodGet, "/sessions/s1", ""},
	{http.MethodDelete, "/sessions/s1", ""},
	{http.MethodPost, "/sessions/s1/signal", `{"signal":"INT"}`},
	{http.MethodPost, "/sessions/s1/resize", `{"cols":80,"rows":24}`},
	{http.MethodGet, "/sessions/s1/log", ""},
	{http.MethodGet, "/sessions/s1/recording", ""},
	{http.MethodGet, "/sessions/s1/attach", ""},
	{http.MethodPost, "/process/session", `{"sessionId":"s1"}`},
	{http.MethodGet, "/process/session", ""},
	{http.MethodGet, "/process/session/s1", ""},
	{http.MethodDelete, "/process/session/s1", ""},
	{http.MethodPost, "/process/session/s1/exec", `{"command":"id","runAsync":true}`},
	{http.MethodGet, "/process/session/s1/command/c1", ""},
	{http.MethodGet, "/process/session/s1/command/c1/logs", ""},
	{http.MethodGet, "/process/session/s1/command/c1/logs?follow=true", ""},
	{http.MethodPost, "/process/session/s1/command/c1/input", `{"data":"id"}`},
	{http.MethodGet, "/process/session/entrypoint", ""},
	{http.MethodGet, "/process/session/entrypoint/logs", ""},
	// The sandbox-prefixed form the proxy may pass through.
	{http.MethodPost, "/sb-test/sessions", `{"command":"id"}`},
}

// Sessions must fail closed on the wasm toolhost: it runs in-process in
// sandboxd, and a session was a host shell. Every action answers 501 behind
// auth, so the route never reaches anything that could start a process.
func TestSessionRoutesReturn501(t *testing.T) {
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok"})

	for _, tc := range sessionRoutes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer tok")
			h.serveHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501 (body %q)", rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not a JSON error: %v", rec.Body.String(), err)
			}
			if !strings.Contains(body["error"], "not supported on the wasm runtime") {
				t.Fatalf("error = %q, want a not-supported message", body["error"])
			}

			// Without the token the route answers 401 first, as before.
			rec = httptest.NewRecorder()
			req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			h.serveHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
			}
		})
	}
}

// The attach and follow-logs routes were WebSocket upgrades onto a running
// host process. A real handshake must be refused with 501, not upgraded.
func TestSessionWebSocketRoutesDoNotUpgrade(t *testing.T) {
	srv := httptest.NewServer(New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok"}).Handler())
	defer srv.Close()

	header := http.Header{"Authorization": {"Bearer tok"}}
	for _, path := range []string{
		"/sessions/s1/attach",
		"/process/session/s1/command/c1/logs?follow=true",
	} {
		conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+path, header)
		if err == nil {
			conn.Close()
			t.Fatalf("%s: WebSocket upgraded, want a refused handshake", path)
		}
		if !errors.Is(err, websocket.ErrBadHandshake) || resp == nil || resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s: err = %v, resp = %+v, want a 501 bad handshake", path, err, resp)
		}
		resp.Body.Close()
	}
}

func TestIsSessionPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/sessions":                      true,
		"/sessions/":                     true,
		"/sessions/s1/attach":            true,
		"/process/session":               true,
		"/process/session/s1/exec":       true,
		"/sessionsX":                     false,
		"/process/sessionX":              false,
		"/process/sessions":              false,
		"/process/execute":               false,
		"/":                              false,
		"/files/download?path=/sessions": false,
	} {
		if got := isSessionPath(path); got != want {
			t.Errorf("isSessionPath(%q) = %v, want %v", path, got, want)
		}
	}
}
