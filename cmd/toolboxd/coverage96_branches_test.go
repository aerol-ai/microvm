package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// errAfterReader yields prefix, then fails with err (not io.EOF), so a
// reader sees a transport failure rather than a short body.
type errAfterReader struct {
	prefix []byte
	err    error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return 0, r.err
}

func waitSessionDone(t *testing.T, sess *sessions.Session) {
	t.Helper()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not exit")
	}
}

// registerEnvdSession starts argv as a session and registers it with the
// envd table directly, so a test controls PTY/stdin flags and the process
// lifetime without holding a Start stream open.
func registerEnvdSession(t *testing.T, srv *server, argv []string, pty, stdin bool) (*sessions.Session, *envdProcessState) {
	t.Helper()
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name: uniqueEnvdSessionName("cov96b"),
		Argv: argv,
		PTY:  pty,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(sess.ID()) })
	state, err := srv.envd.registerSession(sess, "", envdProcessConfig{Cmd: argv[0]}, pty, stdin)
	if err != nil {
		t.Fatalf("registerSession: %v", err)
	}
	return sess, state
}

func pidSelectorJSON(pid int) string {
	return `{"process":{"pid":` + strconv.Itoa(pid) + `}}`
}

func envdStartRequestFor(t *testing.T, ctx context.Context, argv ...string) *http.Request {
	t.Helper()
	payload, err := json.Marshal(envdStartRequest{Process: envdProcessConfig{Cmd: argv[0], Args: argv[1:]}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(payload)))
	return req.WithContext(ctx)
}

func decodeEnvdEvents(t *testing.T, body []byte) []envdProcessStreamResponse {
	t.Helper()
	var out []envdProcessStreamResponse
	for _, env := range decodeConnectEnvelopesForTest(t, body) {
		if env.Flags&connectFlagEndStream != 0 {
			continue
		}
		var ev envdProcessStreamResponse
		if err := json.Unmarshal(env.Payload, &ev); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestEnvdOctetStreamWriteTruncatedGzip(t *testing.T) {
	srv := newEnvdTestServer(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(strings.Repeat("payload ", 64)))
	_ = zw.Close()
	truncated := gz.Bytes()[:gz.Len()-8] // drop the CRC/size trailer

	target := filepath.Join(t.TempDir(), "out.txt")
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+target, bytes.NewReader(truncated))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("truncated gzip must fail, got 200: %s", rec.Body.String())
	}
}

// A whitespace-only filename is still a file part (filepath.Base keeps
// it), but it resolves to no path at all.
func TestEnvdMultipartBlankFilenameRejected(t *testing.T) {
	srv := newEnvdTestServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename=" "`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("data"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "path is required") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReadConnectJSONRequestFailures(t *testing.T) {
	header := func(size int) []byte {
		h := make([]byte, connectEnvelopeHeaderLen)
		binary.BigEndian.PutUint32(h[1:], uint32(size))
		return h
	}
	boom := errors.New("read boom")
	cases := []struct {
		name    string
		body    *errAfterReader
		wantErr string
	}{
		{"header-read-error", &errAfterReader{err: boom}, "read boom"},
		{"payload-read-error", &errAfterReader{prefix: header(10), err: boom}, "read boom"},
		{"bad-json", &errAfterReader{prefix: append(header(3), []byte("{x}")...), err: errors.New("unreachable")}, "invalid character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", tc.body)
			var dst envdStartRequest
			err := readConnectJSONRequest(req, &dst)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestEnvdProcessStartBadEnvelope(t *testing.T) {
	srv := newEnvdTestServer(t)
	rec := httptest.NewRecorder()
	srv.handleEnvdProcessStart(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte{0, 0})))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "envelope") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnvdProcessStartReportsNonZeroExit(t *testing.T) {
	srv := newEnvdTestServer(t)
	rec := httptest.NewRecorder()
	srv.handleEnvdProcessStart(rec, envdStartRequestFor(t, context.Background(), "/bin/sh", "-c", "exit 3"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var end *envdProcessEndEvent
	for _, ev := range decodeEnvdEvents(t, rec.Body.Bytes()) {
		if ev.Event.End != nil {
			end = ev.Event.End
		}
	}
	if end == nil || end.ExitCode != 3 || end.Error != "process exited with code 3" {
		t.Fatalf("end event = %+v", end)
	}
}

// A client that disconnects mid-stream ends Start and Connect without
// waiting for the process.
func TestEnvdStreamsEndWhenClientGoesAway(t *testing.T) {
	srv := newEnvdTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	startRec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleEnvdProcessStart(startRec, envdStartRequestFor(t, ctx, "sleep", "30"))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after client cancel")
	}
	events := decodeEnvdEvents(t, startRec.Body.Bytes())
	if len(events) == 0 || events[0].Event.Start == nil {
		t.Fatalf("events = %+v", events)
	}
	pid := events[0].Event.Start.PID
	t.Cleanup(func() {
		if state, ok := srv.envd.lookup(envdProcessSelector{PID: &pid}); ok {
			_ = srv.sessions.Delete(state.SessionID)
		}
	})

	connectRec := httptest.NewRecorder()
	connectReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(pidSelectorJSON(pid))))).WithContext(ctx)
	srv.handleEnvdProcessConnect(connectRec, connectReq)
	events = decodeEnvdEvents(t, connectRec.Body.Bytes())
	if len(events) != 1 || events[0].Event.Start == nil || events[0].Event.Start.PID != pid {
		t.Fatalf("connect events = %+v", events)
	}
}

// Each envelope is two writes (header, payload); failAfter=2 lets the
// start event through and fails the next send.
func TestEnvdStreamSendFailures(t *testing.T) {
	cases := []struct {
		name      string
		argv      []string
		keepalive string
		failAfter int
	}{
		{"start-event", []string{"true"}, "", 0},
		{"end-event", []string{"true"}, "", 2},
		{"data-event", []string{"/bin/sh", "-c", "printf x; sleep 1"}, "", 2},
		{"keepalive-event", []string{"sleep", "2"}, "0.02", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newEnvdTestServer(t)
			fw := &failWriter{failAfter: tc.failAfter}
			fw.ResponseRecorder = *httptest.NewRecorder()
			req := envdStartRequestFor(t, context.Background(), tc.argv...)
			if tc.keepalive != "" {
				req.Header.Set("Keepalive-Ping-Interval", tc.keepalive)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.handleEnvdProcessStart(fw, req)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Start did not return after a failed send")
			}
			if fw.writes != tc.failAfter+1 {
				t.Fatalf("writes = %d, want %d (stream must stop at the first failed send)", fw.writes, tc.failAfter+1)
			}
		})
	}
}

func TestEnvdProcessUpdateResizesPTY(t *testing.T) {
	srv := newEnvdTestServer(t)
	_, state := registerEnvdSession(t, srv, []string{"sleep", "5"}, true, false)
	body := `{"process":{"pid":` + strconv.Itoa(state.PID) + `},"pty":{"size":{"cols":120,"rows":40}}}`
	rec := httptest.NewRecorder()
	srv.handleEnvdProcessUpdate(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnvdProcessSendInputBadEncoding(t *testing.T) {
	srv := newEnvdTestServer(t)
	_, state := registerEnvdSession(t, srv, []string{"sleep", "5"}, false, true)
	body := `{"process":{"pid":` + strconv.Itoa(state.PID) + `},"input":{"stdin":"!!not-base64"}}`
	rec := httptest.NewRecorder()
	srv.handleEnvdProcessSendInput(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid stdin input encoding") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Input sent after stdin was half-closed hits a closed pipe while the
// process is still alive and registered.
func TestEnvdProcessSendInputWriteError(t *testing.T) {
	srv := newEnvdTestServer(t)
	sess, state := registerEnvdSession(t, srv, []string{"sleep", "5"}, false, true)
	if err := sess.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	body := `{"process":{"pid":` + strconv.Itoa(state.PID) + `},"input":{"stdin":"eA=="}}`
	rec := httptest.NewRecorder()
	srv.handleEnvdProcessSendInput(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnvdProcessSelectorMisses(t *testing.T) {
	srv := newEnvdTestServer(t)
	missing := pidSelectorJSON(999999)
	handlers := map[string]func(http.ResponseWriter, *http.Request){
		"SendSignal": srv.handleEnvdProcessSendSignal,
		"CloseStdin": srv.handleEnvdProcessCloseStdin,
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(missing)))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestEnvdMakeDirMkdirFailsInReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	srv := newEnvdTestServer(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	body, _ := json.Marshal(envdMakeDirRequest{Path: filepath.Join(parent, "child")})
	rec := httptest.NewRecorder()
	srv.handleEnvdFilesystemMakeDir(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionsLookalikePathIs404(t *testing.T) {
	srv := newEnvdTestServer(t)
	// A single unknown segment is read as a sandbox-id prefix and collapses
	// to "/", so use two segments to reach the /sessions prefix match.
	req := httptest.NewRequest(http.MethodGet, "/sessionsX/foo", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Attaching to an exited session makes both "session done" and "frames
// closed" ready at once; either way the client must get an exit message.
// Repeating the attach exercises both select arms.
func TestPumpSessionAttachToExitedSessionSendsExit(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "exited-attach", Argv: []string{"/bin/sh", "-c", "exit 4"}})
	if err != nil {
		t.Fatal(err)
	}
	waitSessionDone(t, sess)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess.ID())
	}))
	t.Cleanup(httpSrv.Close)

	for i := 0; i < 16; i++ {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var exit sessionAttachControlOut
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("attach %d: no exit message: %v", i, err)
			}
			if mt == websocket.TextMessage {
				if err := json.Unmarshal(data, &exit); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		_ = conn.Close()
		if exit.Type != "exit" || exit.Code != 4 {
			t.Fatalf("attach %d: control = %+v", i, exit)
		}
	}
}

func TestDaytonaCommandStreamDropsFramesForFullSubscriber(t *testing.T) {
	stream := newDaytonaCommandStream()
	_, ch, _ := stream.subscribe()
	for i := 0; i < cap(ch)+10; i++ {
		stream.broadcast(sessions.StreamStdout, []byte("x"))
	}
	if len(ch) != cap(ch) {
		t.Fatalf("subscriber holds %d frames, want %d", len(ch), cap(ch))
	}
	stream.finish()
	initial, _, finished := stream.subscribe()
	if !finished || len(initial) != len(daytonaStdoutPrefix)+cap(ch)+10 {
		t.Fatalf("replay len=%d finished=%v; dropped live frames must still be in the replay", len(initial), finished)
	}
}

// runDaytonaSessionCommandIn runs command in a fresh pipe-mode shell
// session built from argv.
func runDaytonaSessionCommandIn(t *testing.T, argv []string, id, command string) *daytonaSessionExecuteResponse {
	t.Helper()
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "cov96b-" + id, Argv: argv})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(sess.ID()) })
	state := &daytonaSessionState{}
	cmd := &daytonaCommandState{id: id, command: command, running: true, createdAt: time.Now(), stream: newDaytonaCommandStream()}
	state.addCommand(cmd)

	type result struct {
		resp *daytonaSessionExecuteResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := srv.runDaytonaSessionCommand(sess, state, cmd)
		done <- result{resp, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("runDaytonaSessionCommand: %v", r.err)
		}
		return r.resp
	case <-time.After(10 * time.Second):
		t.Fatal("runDaytonaSessionCommand did not return")
		return nil
	}
}

func TestRunDaytonaSessionCommandMarkerParsing(t *testing.T) {
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}

	// /bin/echo is external on purpose. Dash (Ubuntu /bin/sh) runs echo as a
	// builtin whose output goes through the shell stdout buffer, so
	// `echo oops >&2` is written to stdout and this case never sees stderr.
	// The sleep gives the runner time to observe the start marker before
	// the stderr frame arrives.
	t.Run("stderr-after-start", func(t *testing.T) {
		resp := runDaytonaSessionCommandIn(t, []string{"/bin/sh"}, "err1", "sleep 0.2; /bin/echo oops >&2")
		if !strings.Contains(deref(resp.Stderr), "oops") || *resp.ExitCode != 0 {
			t.Fatalf("resp stderr=%q exit=%d", deref(resp.Stderr), *resp.ExitCode)
		}
	})

	// Shell noise before the start marker is discarded, and the buffer is
	// trimmed rather than growing without bound.
	t.Run("noise-before-start-marker", func(t *testing.T) {
		argv := []string{"/bin/sh", "-c", `printf '%0300d' 0; exec /bin/sh`}
		resp := runDaytonaSessionCommandIn(t, argv, "noise1", "echo real")
		if got := deref(resp.Stdout); strings.TrimSpace(got) != "real" {
			t.Fatalf("stdout = %q, want only the command output", got)
		}
	})

	// The command prints the end pattern with no newline, then the real
	// end marker follows: the first sighting has no exit-code line yet, and
	// the text after it is not a number, so the exit code falls back to 1.
	t.Run("end-pattern-without-code", func(t *testing.T) {
		resp := runDaytonaSessionCommandIn(t, []string{"/bin/sh"}, "end1", `printf '%s' '__SB_DAYTONA_END_end1__:'; sleep 0.3`)
		if *resp.ExitCode != 1 {
			t.Fatalf("exit = %d, want 1", *resp.ExitCode)
		}
	})

	// The shell exits inside the command while holding back a partial end
	// marker; that tail is flushed once the session closes.
	t.Run("session-exits-with-held-tail", func(t *testing.T) {
		resp := runDaytonaSessionCommandIn(t, []string{"/bin/sh"}, "tail1", `printf '__SB_DAYTONA_'; exit 5`)
		if got := deref(resp.Stdout); got != "__SB_DAYTONA_" {
			t.Fatalf("stdout = %q", got)
		}
		if *resp.ExitCode != 5 {
			t.Fatalf("exit = %d, want 5", *resp.ExitCode)
		}
	})
}
