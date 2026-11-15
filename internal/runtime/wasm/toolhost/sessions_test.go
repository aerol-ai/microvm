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

// nativeSessionRoutes is every action of the native /sessions family, as
// the v1 and SSH surfaces call them. The bodies carry a command, as a real
// caller's would; nothing may run it.
var nativeSessionRoutes = []struct {
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
	// The sandbox-prefixed form the proxy may pass through.
	{http.MethodPost, "/sb-test/sessions", `{"command":"id"}`},
}

// Interactive sessions fail closed on the wasm toolhost: it runs in-process
// in sandboxd, and such a session is a host shell with a terminal. Every
// action answers 501 behind auth, even with Sessions wired, and the error
// points at what does work.
func TestNativeSessionRoutesReturn501(t *testing.T) {
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: &fakeSessions{}})

	for _, tc := range nativeSessionRoutes {
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
			for _, want := range []string{"not supported on the wasm runtime", "/process/session", "/process/exec/stream"} {
				if !strings.Contains(body["error"], want) {
					t.Fatalf("error = %q, want it to mention %q", body["error"], want)
				}
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

// Without Sessions (a host built without the driver), the Daytona-style
// family answers 501 too, behind auth.
func TestProcessSessionRoutesWithoutSessions(t *testing.T) {
	h := New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok"})
	for _, path := range []string{"/process/session", "/process/session/s1/exec", "/process/session/entrypoint/logs"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		h.serveHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "not available") {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h.serveHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated = %d", path, rec.Code)
		}
	}
}

// The attach route was a WebSocket upgrade onto a running host process. A
// real handshake must be refused with 501, not upgraded.
func TestNativeSessionAttachDoesNotUpgrade(t *testing.T) {
	srv := httptest.NewServer(New(Config{SandboxID: "sb-test", WorkDir: t.TempDir(), AuthToken: "tok", Sessions: &fakeSessions{}}).Handler())
	defer srv.Close()

	header := http.Header{"Authorization": {"Bearer tok"}}
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/sessions/s1/attach", header)
	if err == nil {
		conn.Close()
		t.Fatal("WebSocket upgraded, want a refused handshake")
	}
	if !errors.Is(err, websocket.ErrBadHandshake) || resp == nil || resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("err = %v, resp = %+v, want a 501 bad handshake", err, resp)
	}
	resp.Body.Close()
}

func TestSessionPathPredicates(t *testing.T) {
	for path, want := range map[string][2]bool{
		"/sessions":                      {true, false},
		"/sessions/":                     {true, false},
		"/sessions/s1/attach":            {true, false},
		"/process/session":               {false, true},
		"/process/session/s1/exec":       {false, true},
		"/sessionsX":                     {false, false},
		"/process/sessionX":              {false, false},
		"/process/sessions":              {false, false},
		"/process/execute":               {false, false},
		"/":                              {false, false},
		"/files/download?path=/sessions": {false, false},
	} {
		if got := [2]bool{isNativeSessionPath(path), isProcessSessionPath(path)}; got != want {
			t.Errorf("%q: native/process = %v, want %v", path, got, want)
		}
	}
}
