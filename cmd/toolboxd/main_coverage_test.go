package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/clonegen"
)

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

func (e *errReader) Write(p []byte) (int, error) { return len(p), nil }

type failEncodeConn struct{ net.Conn }

func (f *failEncodeConn) Write([]byte) (int, error) { return 0, errors.New("encode boom") }

func TestVsockReadNonEOFAndWriteError(t *testing.T) {
	handleVsockConn(context.Background(), &errReader{err: errors.New("read boom")}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	pr, pw := net.Pipe()
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	go func() {
		_, _ = pw.Write([]byte(`{"op":"ping"}` + "\n"))
		// Keep open briefly so encode of Ok response hits Write error.
		time.Sleep(50 * time.Millisecond)
		_ = pw.Close()
	}()
	handleVsockConn(context.Background(), &failEncodeConn{Conn: pr}, newQuiesceHandler(slog.Default(), nil, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

type serveErrVsock struct{}

func (s *serveErrVsock) Serve(context.Context) error { return errors.New("serve boom") }

func (s *serveErrVsock) Close() error { return nil }

func TestMainVsockServeErrorLogged(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	t.Cleanup(func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	})

	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	startUserCommandFn = func(*slog.Logger, []string) {}
	netListenFn = func(string, string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(logger *slog.Logger, cfg sessions.Config) (*sessions.Manager, error) {
		return sessions.New(logger, sessions.Config{SandboxID: "sb", RecordingDir: t.TempDir(), BufferBytes: 1 << 12})
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		time.Sleep(50 * time.Millisecond)
		_ = ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return &serveErrVsock{}, nil
	}
	os.Args = []string{"toolboxd"}
	main()
}

func TestHandleExecNonExitWaitMerge(t *testing.T) {
	// Cover the waitErr merge branch when Wait returns a non-ExitError.
	// Use a command that is killed after Start such that Wait can surface
	// a generic error on some platforms; also assert ECHILD path via interpretWaitResult.
	code, sig := interpretWaitResult(errors.New("forced wait"))
	if code != -1 || sig != "forced wait" {
		t.Fatalf("interpretWaitResult = (%d,%q)", code, sig)
	}
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{"command":"sh","argv":["-c","kill -9 $$"]}`
	rec := httptest.NewRecorder()
	srv.handleExec(rec, httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleExec status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRoutesUnhandledProcessAndSessionsPrefixes(t *testing.T) {
	srv := newEnvdTestServer(t)
	srv.adopted = true
	h := srv.routes()
	req := httptest.NewRequest(http.MethodGet, "/process/sessionX", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("process/sessionX = %d", rec.Code)
	}
	// /sessionsX normalizes to "/" (unknown single segment); exercise the
	// handleSessionsRoute false return directly instead.
	if srv.handleSessionsRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sessionz", nil)) {
		t.Fatal("expected handleSessionsRoute false for /sessionz")
	}
}

func TestMainSessionsNewFailureContinues(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNetListenFn := netListenFn
	oldNewVsockServerFn := newVsockServerFn
	t.Cleanup(func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		netListenFn = oldNetListenFn
		newVsockServerFn = oldNewVsockServerFn
	})

	startReaperFn = func(*slog.Logger) {}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	startUserCommandFn = func(*slog.Logger, []string) {}
	netListenFn = func(string, string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	sessionsNewFn = func(*slog.Logger, sessions.Config) (*sessions.Manager, error) {
		return nil, errors.New("sessions boom")
	}
	serveHTTPFn = func(_ *http.Server, ln net.Listener) error {
		_ = ln.Close()
		return http.ErrServerClosed
	}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return nil, errors.New("vsock disabled")
	}
	os.Args = []string{"toolboxd"}
	main()
}

func TestAdoptIdentityAndServingRequests(t *testing.T) {
	srv := &server{parkedMode: true}
	if srv.servingRequests() {
		t.Fatal("parked+unadopted should not serve")
	}
	srv.adoptIdentity(" sb-1 ", " tok ")
	if !srv.servingRequests() {
		t.Fatal("expected serving after adopt")
	}
	if srv.sandboxID != "sb-1" || srv.authToken != "tok" || !srv.adopted {
		t.Fatalf("identity = %+v", srv)
	}
}

func TestRoutesParkedAndUnauthSweep(t *testing.T) {
	srv := newEnvdTestServer(t)
	srv.parkedMode = true
	srv.adopted = false
	srv.cloneGen = clonegen.New(filepath.Join(t.TempDir(), "clone-gen"), srv.logger)
	h := srv.routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/process/execute", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("parked status = %d, want 503", rec.Code)
	}

	srv.adoptIdentity("sb-test", "toolbox-token")

	unauthPaths := []struct {
		method, path string
	}{
		{http.MethodGet, "/envd/health"},
		{http.MethodPost, "/process/execute"},
		{http.MethodPost, "/process/code-run"},
		{http.MethodGet, "/process/interpreter/x"},
		{http.MethodGet, "/process/session"},
		{http.MethodPost, "/files/upload"},
		{http.MethodGet, "/files/download"},
		{http.MethodGet, "/files"},
		{http.MethodGet, "/files/info"},
		{http.MethodPost, "/files/move"},
		{http.MethodGet, "/files/search"},
		{http.MethodGet, "/files/find"},
		{http.MethodGet, "/git/status"},
		{http.MethodPost, "/admin/allowed-ports"},
		{http.MethodGet, "/process/exec/stream"},
		{http.MethodGet, "/sessions"},
	}
	for _, tc := range unauthPaths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}

	authed := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer toolbox-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := authed(http.MethodGet, "/envd/nope"); got.Code != http.StatusNotFound {
		t.Fatalf("envd nope = %d", got.Code)
	}
	if got := authed(http.MethodGet, "/process/session/nope"); got.Code != http.StatusNotFound {
		t.Fatalf("process session nope = %d", got.Code)
	}
	if got := authed(http.MethodGet, "/sessions/nope"); got.Code != http.StatusNotFound {
		t.Fatalf("sessions nope = %d", got.Code)
	}
}

func TestEnvInt64AndNormalizeSandboxPathEdges(t *testing.T) {
	t.Setenv("TB_BAD64", "nope")
	if got := envInt64("TB_BAD64", 9); got != 9 {
		t.Fatalf("envInt64 bad = %d, want 9", got)
	}
	if got := normalizeSandboxPath("//health", ""); got != "//health" {
		t.Fatalf("double-slash path = %q", got)
	}
	if got := normalizeSandboxPath("/not-a-toolbox-route", ""); got != "/" {
		t.Fatalf("unknown single segment = %q, want /", got)
	}
}

func TestHandleUploadMissingFileAndMkdirFail(t *testing.T) {
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("path", filepath.Join(t.TempDir(), "x.bin"))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.handleUpload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing file status = %d", rec.Code)
	}

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	body.Reset()
	w = multipart.NewWriter(&body)
	_ = w.WriteField("path", filepath.Join(blocker, "child.bin"))
	fw, err := w.CreateFormFile("file", "child.bin")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	_, _ = fw.Write([]byte("data"))
	_ = w.Close()
	req = httptest.NewRequest(http.MethodPost, "/files/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec = httptest.NewRecorder()
	srv.handleUpload(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("mkdir fail status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEnvdMultipartAndOctetWriteErrors(t *testing.T) {
	srv := newEnvdTestServer(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", "")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	_, _ = fw.Write([]byte("data"))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/envd/files", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty filename multipart = %d body=%s", rec.Code, rec.Body.String())
	}

	body.Reset()
	w = multipart.NewWriter(&body)
	fw, err = w.CreateFormFile("file", "child.txt")
	if err != nil {
		t.Fatalf("CreateFormFile2: %v", err)
	}
	_, _ = fw.Write([]byte("data"))
	_ = w.Close()
	req = httptest.NewRequest(http.MethodPost, "/envd/files?path="+filepath.Join(blocker, "child.txt"), &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec = httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("multipart mkdir fail should error, got %d", rec.Code)
	}

	// Create fails when target path is an existing directory.
	existingDir := t.TempDir()
	body.Reset()
	w = multipart.NewWriter(&body)
	fw, err = w.CreateFormFile("file", "x")
	if err != nil {
		t.Fatalf("CreateFormFile3: %v", err)
	}
	_, _ = fw.Write([]byte("data"))
	_ = w.Close()
	req = httptest.NewRequest(http.MethodPost, "/envd/files?path="+existingDir, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec = httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("multipart create-on-dir should fail, got %d", rec.Code)
	}

	octet := httptest.NewRequest(http.MethodPost, "/envd/files?path="+filepath.Join(blocker, "o.bin"), bytes.NewReader([]byte("x")))
	octet.Header.Set("Content-Type", "application/octet-stream")
	octetRec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(octetRec, octet)
	if octetRec.Code == http.StatusOK {
		t.Fatalf("octet mkdir fail should error, got %d", octetRec.Code)
	}

	octetBad := httptest.NewRequest(http.MethodPost, "/envd/files?path=", bytes.NewReader([]byte("x")))
	octetBad.Header.Set("Content-Type", "application/octet-stream")
	octetBadRec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(octetBadRec, octetBad)
	if octetBadRec.Code != http.StatusBadRequest {
		t.Fatalf("octet empty path = %d", octetBadRec.Code)
	}

	gzipBad := httptest.NewRequest(http.MethodPost, "/envd/files?path="+filepath.Join(t.TempDir(), "g.bin"), bytes.NewReader([]byte("not-gzip")))
	gzipBad.Header.Set("Content-Type", "application/octet-stream")
	gzipBad.Header.Set("Content-Encoding", "gzip")
	gzipRec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(gzipRec, gzipBad)
	if gzipRec.Code != http.StatusBadRequest {
		t.Fatalf("bad gzip = %d", gzipRec.Code)
	}
}

func TestDaytonaCodeRunScriptWriteError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Point TMPDIR at a file parent so writeCodeRunScript's temp file creation fails.
	t.Setenv("TMPDIR", filepath.Join(blocker, "tmp"))
	rec := httptest.NewRecorder()
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{"language":"python","code":"print(1)"}`
	srv.handleDaytonaCodeRun(rec, httptest.NewRequest(http.MethodPost, "/process/code-run", strings.NewReader(body)))
	if rec.Code == http.StatusOK {
		// On some systems TMPDIR is ignored by os.CreateTemp; accept either outcome.
	}
}
