package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tokenCanary stands in for a sandbox's toolbox token: tests assert it never
// reaches a log line or an error.
const tokenCanary = "tok-canary-7f3e1b2a"

// tokenlessServer is toolboxd as a Firecracker guest booted from a template,
// a template snapshot or the warm pool starts it: no SB_TOOLBOX_TOKEN, not
// parked, sessions on, files reachable.
func tokenlessServer(t *testing.T) *server {
	t.Helper()
	srv := newEnvdTestServer(t)
	srv.authToken = ""
	srv.sandboxID = "tpl-hostname"
	return srv
}

// authedRequestCase is one request against an authenticated route.
type authedRequestCase struct {
	method, path, body string
	upgrade            bool
}

// everyAuthenticatedRoute is one request per authenticated route family in
// routes(): exec, code-run, the interpreter stub, Daytona process sessions,
// every file route, git, the admin port list, the exec stream and session
// websockets, the sessions API and the E2B envd surface.
func everyAuthenticatedRoute(marker, readable string) []authedRequestCase {
	exec := `{"command":"touch ` + marker + `"}`
	return []authedRequestCase{
		{method: http.MethodPost, path: "/process/execute", body: exec},
		{method: http.MethodPost, path: "/tpl-hostname/process/execute", body: exec},
		{method: http.MethodPost, path: "/sb-anything/process/execute", body: exec},
		{method: http.MethodPost, path: "/process/code-run", body: `{"code":"print(1)","language":"python"}`},
		{method: http.MethodGet, path: "/process/interpreter/context"},
		{method: http.MethodPost, path: "/process/session", body: `{"sessionId":"s1"}`},
		{method: http.MethodPost, path: "/process/session/s1/exec", body: `{"command":"touch ` + marker + `"}`},
		{method: http.MethodGet, path: "/files/download?path=" + readable},
		{method: http.MethodGet, path: "/files?path=/"},
		{method: http.MethodGet, path: "/files/info?path=" + readable},
		{method: http.MethodPost, path: "/files/move?source=" + readable + "&destination=" + marker},
		{method: http.MethodGet, path: "/files/search?path=/&pattern=*"},
		{method: http.MethodGet, path: "/files/find?path=/&pattern=secret"},
		{method: http.MethodGet, path: "/git/status?path=/"},
		{method: http.MethodPost, path: "/git/clone", body: `{"url":"https://example.invalid/r.git","path":"` + marker + `"}`},
		{method: http.MethodPost, path: "/admin/allowed-ports", body: `{"ports":[22,8080]}`},
		{method: http.MethodGet, path: "/process/exec/stream?command=touch+" + marker, upgrade: true},
		{method: http.MethodGet, path: "/sessions"},
		{method: http.MethodPost, path: "/sessions", body: `{"command":"touch ` + marker + `"}`},
		{method: http.MethodGet, path: "/sessions/s1/attach", upgrade: true},
		{method: http.MethodGet, path: "/envd/health"},
		{method: http.MethodPost, path: "/envd/process.Process/Start", body: `{"process":{"cmd":"/bin/sh","args":["-c","touch ` + marker + `"]}}`},
		{method: http.MethodGet, path: "/envd/files?path=" + readable},
		{method: http.MethodGet, path: "/proxy/8080/"},
		{method: http.MethodGet, path: "/"},
		{method: http.MethodGet, path: "/version"},
		{method: http.MethodGet, path: "/clone-generation"},
	}
}

func (c authedRequestCase) request(header string) *http.Request {
	req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
	if c.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	return req
}

// TestTokenlessAgentFailsClosed is the guest half of the Firecracker toolbox
// auth fix. On the base branch a toolboxd without SB_TOOLBOX_TOKEN (every
// guest booted from a template, a template snapshot or the warm pool)
// accepted every request: exec, files, sessions and envd, from anyone who
// reached port 2280. It must now answer only /health, run nothing and read
// nothing, whatever Authorization header the caller invents.
func TestTokenlessAgentFailsClosed(t *testing.T) {
	srv := tokenlessServer(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	readable := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(readable, []byte("bank-secret-contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := srv.routes()

	for _, header := range []string{"", "Bearer ", "Bearer guessed", "Bearer " + testToolboxToken, "Basic Zm9vOmJhcg=="} {
		for _, tc := range everyAuthenticatedRoute(marker, readable) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.request(header))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s (Authorization %q) = %d %q, want 503 before adoption", tc.method, tc.path, header, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "bank-secret-contents") {
				t.Fatalf("%s %s leaked a file before adoption", tc.method, tc.path)
			}
		}
	}

	// Upload is multipart; it must not write either.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", marker)
	fw, _ := mw.CreateFormFile("file", "x")
	_, _ = fw.Write([]byte("planted"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("upload before adoption = %d, want 503", rec.Code)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a request ran a command or wrote a file before adoption (stat %s: %v)", marker, err)
	}
	if got := srv.allowedPorts; len(got) != 0 {
		t.Fatalf("the admin port list changed before adoption: %v", got)
	}
	if srv.sessions != nil && len(srv.sessions.List()) != 0 {
		t.Fatalf("a session was created before adoption: %v", srv.sessions.List())
	}

	// /health is the one pre-adoption route: the container host's readiness
	// poll. It runs nothing and reads nothing.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sandbox") {
		t.Fatalf("/health before adoption = %d %q, want 200 status only", rec.Code, rec.Body.String())
	}
}

// adoptPipe runs the production vsock handler wired to srv, as main() wires
// it, and returns a function that sends one adopt op and returns the ack.
func adoptPipe(t *testing.T, srv *server, logs io.Writer) func(data any) VsockResponse {
	t.Helper()
	h := newQuiesceHandler(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil, nil)
	h.identity = srv
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, h)
	dec := json.NewDecoder(host)
	t.Cleanup(func() {
		closePipeWriter(host)
		<-done
	})
	return func(data any) VsockResponse {
		t.Helper()
		return sendVsock(t, host, dec, OpAdopt, data)
	}
}

func execWith(t *testing.T, h http.Handler, header, command string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"`+command+`"}`))
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// After the host's vsock adopt the agent serves its sandbox, and only to a
// caller with that sandbox's token.
func TestVsockAdoptThenServe(t *testing.T) {
	srv := tokenlessServer(t)
	var logs bytes.Buffer
	adopt := adoptPipe(t, srv, &logs)
	h := srv.routes()

	if rec := execWith(t, h, "Bearer "+tokenCanary, "echo hi"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("exec before adoption = %d, want 503", rec.Code)
	}
	if resp := adopt(map[string]string{"sandbox_id": "sb-adopted", "token": tokenCanary}); !resp.Ok {
		t.Fatalf("adopt ack = %+v, want ok", resp)
	}
	for _, header := range []string{"", "Bearer wrong", "Bearer " + tokenCanary + "x"} {
		if rec := execWith(t, h, header, "echo hi"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("exec with Authorization %q after adoption = %d, want 401", header, rec.Code)
		}
	}
	rec := execWith(t, h, "Bearer "+tokenCanary, "echo adopted")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "adopted") {
		t.Fatalf("exec with the adopted token = %d %q, want 200", rec.Code, rec.Body.String())
	}
	// The adopted sandbox ID is the one the proxy prefixes paths with.
	req := httptest.NewRequest(http.MethodGet, "/sb-adopted/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sb-adopted"`) {
		t.Fatalf("GET /sb-adopted/ = %d %q, want the adopted sandbox ID", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), tokenCanary) {
		t.Fatalf("the token reached the agent's log: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "adopt applied") {
		t.Fatalf("no adopt log line: %q", logs.String())
	}
}

// The first token sticks. The same token again converges (a retry after a
// lost ack); any other token is refused, so a template clone or warm slot
// adopted by one sandbox can never be taken over by a second.
func TestVsockAdoptIsOneWay(t *testing.T) {
	srv := tokenlessServer(t)
	var logs bytes.Buffer
	adopt := adoptPipe(t, srv, &logs)
	first := map[string]string{"sandbox_id": "sb-first", "token": tokenCanary}
	for i := 0; i < 3; i++ {
		if resp := adopt(first); !resp.Ok {
			t.Fatalf("adopt #%d of the same token = %+v, want ok", i+1, resp)
		}
	}
	resp := adopt(map[string]string{"sandbox_id": "sb-second", "token": "tok-second-sandbox"})
	if resp.Ok || !strings.Contains(resp.Error, "already holds another sandbox's identity") {
		t.Fatalf("adopt with a second token = %+v, want refused", resp)
	}
	if id, token := srv.identity(); id != "sb-first" || token != tokenCanary {
		t.Fatalf("identity after a refused re-adopt = %q, want sb-first and the first token", id)
	}
	h := srv.routes()
	if rec := execWith(t, h, "Bearer tok-second-sandbox", "echo hi"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the refused token was accepted: %d", rec.Code)
	}
	if rec := execWith(t, h, "Bearer "+tokenCanary, "echo hi"); rec.Code != http.StatusOK {
		t.Fatalf("the first token stopped working: %d", rec.Code)
	}
	if strings.Contains(logs.String(), tokenCanary) || strings.Contains(logs.String(), "tok-second-sandbox") || strings.Contains(resp.Error, "tok-") {
		t.Fatalf("a token reached the log or the ack: log=%q ack=%q", logs.String(), resp.Error)
	}
}

// A cold-booted guest already holds its token from /etc/toolboxd.env. The
// host's adopt with that token converges; a different token is refused.
func TestVsockAdoptOfABakedToken(t *testing.T) {
	srv := tokenlessServer(t)
	srv.authToken = tokenCanary
	adopt := adoptPipe(t, srv, io.Discard)
	if resp := adopt(map[string]string{"sandbox_id": "sb-cold", "token": " " + tokenCanary + " "}); !resp.Ok {
		t.Fatalf("adopt with the baked token = %+v, want ok", resp)
	}
	if id, _ := srv.identity(); id != "sb-cold" {
		t.Fatalf("sandbox ID = %q, want sb-cold", id)
	}
	if resp := adopt(map[string]string{"sandbox_id": "sb-cold", "token": "another"}); resp.Ok {
		t.Fatal("a cold-booted agent took a second token")
	}
}

func TestVsockAdoptRefusals(t *testing.T) {
	var logs bytes.Buffer
	srv := tokenlessServer(t)
	adopt := adoptPipe(t, srv, &logs)
	for _, tc := range []struct {
		name string
		data any
		want string
	}{
		{name: "no payload", data: nil, want: "malformed payload"},
		{name: "not an object", data: []string{tokenCanary}, want: "malformed payload"},
		{name: "empty token", data: map[string]string{"sandbox_id": "sb", "token": "  "}, want: "a token is required"},
	} {
		resp := adopt(tc.data)
		if resp.Ok || !strings.Contains(resp.Error, tc.want) || strings.Contains(resp.Error, tokenCanary) {
			t.Fatalf("%s: ack = %+v, want an error containing %q and no token", tc.name, resp, tc.want)
		}
	}
	if _, token := srv.identity(); token != "" {
		t.Fatal("a refused adopt left a token behind")
	}

	// A parked container is adopted over its ready socket only.
	parked := &server{parkedMode: true, authToken: "bootstrap"}
	if _, err := parked.adoptOverVsock("sb", "bootstrap"); err == nil || parked.servingRequests() {
		t.Fatalf("a parked agent took a vsock adopt: err=%v serving=%v", err, parked.servingRequests())
	}

	// No identity wired: refused; a handler without the capability answers
	// unknown op, which the host turns into a failed create.
	h := newQuiesceHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err := h.OnAdopt(context.Background(), json.RawMessage(`{"token":"x"}`)); err == nil || !strings.Contains(err.Error(), "cannot take an identity") {
		t.Fatalf("OnAdopt without an identity = %v", err)
	}
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, &recordingHandler{})
	resp := sendVsock(t, host, json.NewDecoder(host), OpAdopt, map[string]string{"token": "x"})
	if resp.Ok || !strings.Contains(resp.Error, `unknown op "adopt"`) {
		t.Fatalf("ack = %+v, want unknown op", resp)
	}
	closePipeWriter(host)
	<-done
	if strings.Contains(logs.String(), tokenCanary) {
		t.Fatalf("the token reached the log: %q", logs.String())
	}
}

// An adopted parked container keeps serving; one adopted with an empty token
// (a broken host) does not.
func TestServingRequestsNeedsAToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		srv  *server
		want bool
	}{
		{name: "tokenless", srv: &server{}, want: false},
		{name: "token", srv: &server{authToken: "t"}, want: true},
		{name: "parked, not adopted", srv: &server{parkedMode: true, authToken: "bootstrap"}, want: false},
		{name: "parked, adopted", srv: &server{parkedMode: true, authToken: "t", adopted: true}, want: true},
		{name: "parked, adopted without a token", srv: &server{parkedMode: true, adopted: true}, want: false},
	} {
		if got := tc.srv.servingRequests(); got != tc.want {
			t.Errorf("%s: servingRequests = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Adoption lands on the vsock goroutine while HTTP requests are in flight.
// Run with -race: the token and sandbox ID are read under the lock.
func TestAdoptRacesInFlightRequests(t *testing.T) {
	srv := tokenlessServer(t)
	h := srv.routes()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/sb-race/files/info?path=/", nil)
				req.Header.Set("Authorization", "Bearer "+tokenCanary)
				h.ServeHTTP(rec, req)
				if rec.Code == http.StatusUnauthorized {
					t.Error("the right token was refused mid-adoption")
					return
				}
			}
		}()
	}
	if _, err := srv.adoptOverVsock("sb-race", tokenCanary); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
}
