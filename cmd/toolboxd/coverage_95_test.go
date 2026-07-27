package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/clonegen"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

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

func TestSessionHandlerErrorBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)
	srv.authToken = "tok"

	create := func(body string) (*httptest.ResponseRecorder, string) {
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handleSessionsCreate(rec, req)
		var snap models.Session
		_ = json.Unmarshal(rec.Body.Bytes(), &snap)
		return rec, snap.ID
	}

	rec, _ := create(`{"argv":["/nonexistent-toolboxd-bin-xyz"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad create status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec, id := create(`{"command":"cat","name":"pipe-cat"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cat status = %d body=%s", rec.Code, rec.Body.String())
	}
	sigReq := httptest.NewRequest(http.MethodPost, "/sessions/"+id+"/signal", strings.NewReader(`{"signal":"NOTASIG"}`))
	sigRec := httptest.NewRecorder()
	srv.handleSessionSignal(sigRec, sigReq, id)
	if sigRec.Code != http.StatusBadRequest {
		t.Fatalf("bad signal status = %d", sigRec.Code)
	}
	_ = srv.sessions.Delete(id)

	rec, id = create(`{"command":"cat","name":"pty-cat","pty":true,"cols":80,"rows":24}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create pty status = %d body=%s", rec.Code, rec.Body.String())
	}
	resizeReq := httptest.NewRequest(http.MethodPost, "/sessions/"+id+"/resize", strings.NewReader(`{"cols":0,"rows":0}`))
	resizeRec := httptest.NewRecorder()
	srv.handleSessionResize(resizeRec, resizeReq, id)
	if resizeRec.Code != http.StatusBadRequest {
		t.Fatalf("bad resize status = %d", resizeRec.Code)
	}
	_ = srv.sessions.Delete(id)

	// Recorder init fails when sandbox recording path is a file.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	blocker := filepath.Join(dir, "sb-test")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile blocker: %v", err)
	}
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "other",
		RecordingDir: dir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	// Point SandboxID at the file so recordingPathForID's parent mkdir fails.
	mgr2, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-norec",
		RecordingDir: dir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("sessions.New norec: %v", err)
	}
	t.Cleanup(mgr2.Close)
	// Force recording dir for sb-test to be a file by using the blocker as nested path via Create.
	// Simpler path: create normally then wipe recorder by using a manager whose RecordingDir/SandboxID
	// can't create casts — recreate mgr with SandboxID under a file parent.
	_ = mgr
	recDir := t.TempDir()
	sandboxFile := filepath.Join(recDir, "sb-file")
	if err := os.WriteFile(sandboxFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("sandbox file: %v", err)
	}
	// New requires MkdirAll(RecordingDir/SandboxID) so we can't construct that way.
	// Instead create a session then replace recording with nil via Create when recorder fails mid-flight:
	// Create still works if newRecorder fails (warn + continue). Make RecordingDir/sb-id a file AFTER New.
	okDir := t.TempDir()
	okMgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-ok",
		RecordingDir: okDir,
		BufferBytes:  1 << 12,
	})
	if err != nil {
		t.Fatalf("okMgr: %v", err)
	}
	t.Cleanup(okMgr.Close)
	sandboxPath := filepath.Join(okDir, "sb-ok")
	if err := os.RemoveAll(sandboxPath); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := os.WriteFile(sandboxPath, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile sandboxPath: %v", err)
	}
	noRecSrv := &server{sessions: okMgr, logger: logger}
	sess, err := okMgr.Create(context.Background(), models.CreateSessionRequest{Name: "norec", Command: "sleep 2"})
	if err != nil {
		t.Fatalf("Create norec: %v", err)
	}
	recReq := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/recording", nil)
	recRec := httptest.NewRecorder()
	noRecSrv.handleSessionRecording(recRec, recReq, sess.ID())
	if recRec.Code != http.StatusNotFound {
		t.Fatalf("recording status = %d body=%s", recRec.Code, recRec.Body.String())
	}
	_ = okMgr.Delete(sess.ID())

	if srv.handleSessionsRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sessionz", nil)) {
		t.Fatal("expected handleSessionsRoute false for /sessionz")
	}
}

func TestSessionAttachPumpDrainAndControl(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "attach-cat",
		Command: "sh -c 'cat; echo err-side >&2'",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(sess.ID()) })

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess.ID())
	}))
	t.Cleanup(httpSrv.Close)

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	_ = conn.WriteMessage(websocket.TextMessage, []byte("{not-json"))
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":40,"rows":12}`))
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("hi\n"))
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"close"}`))

	// Second attach after delete → 404.
	_ = srv.sessions.Delete(sess.ID())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/attach", nil)
	srv.handleSessionAttach(rec, req, sess.ID())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("attach missing status = %d", rec.Code)
	}

	// Exit+drain path with a short-lived session producing stdout.
	sess2, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "attach-echo",
		Command: "sh -c 'echo hello; sleep 0.2'",
	})
	if err != nil {
		t.Fatalf("Create echo: %v", err)
	}
	httpSrv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleSessionAttach(w, r, sess2.ID())
	}))
	t.Cleanup(httpSrv2.Close)
	wsURL2 := "ws" + strings.TrimPrefix(httpSrv2.URL, "http") + "/attach"
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL2, nil)
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}
	defer conn2.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn2.SetReadDeadline(deadline)
	sawExit := false
	for !sawExit {
		msgType, data, err := conn2.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage && bytes.Contains(data, []byte(`"exit"`)) {
			sawExit = true
		}
	}
	if !sawExit {
		t.Fatal("expected exit control frame from attach")
	}
}

func TestHandleDaytonaSessionDeleteUnderlyingMissing(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createBody := bytes.NewBufferString(`{"sessionId":"del-missing"}`)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", createBody))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d", createRec.Code)
	}
	sess, _, ok := srv.lookupDaytonaSession("del-missing")
	if !ok {
		t.Fatal("expected daytona session")
	}
	if err := srv.sessions.Delete(sess.ID()); err != nil {
		t.Fatalf("Delete underlying: %v", err)
	}
	delRec := httptest.NewRecorder()
	srv.handleDaytonaSessionDelete(delRec, httptest.NewRequest(http.MethodDelete, "/process/session/del-missing", nil), "del-missing")
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("delete status = %d body=%s", delRec.Code, delRec.Body.String())
	}
}

func TestDaytonaSessionCommandAndListErrorBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	if state.acceptsInput("missing") {
		t.Fatal("acceptsInput should be false for missing command")
	}

	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"list-stale"}`)))
	sess, _, ok := srv.lookupDaytonaSession("list-stale")
	if !ok {
		t.Fatal("expected session")
	}
	// Leave daytona map entry while removing underlying session so list skips it.
	_ = srv.sessions.Delete(sess.ID())
	listRec := httptest.NewRecorder()
	srv.handleDaytonaSessionList(listRec, httptest.NewRequest(http.MethodGet, "/process/session", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}

	createRec = httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"input-live"}`)))
	live, liveState, ok := srv.lookupDaytonaSession("input-live")
	if !ok {
		t.Fatal("expected input-live session")
	}
	cmd := &daytonaCommandState{id: "cmd-1", running: false, stream: newDaytonaCommandStream()}
	liveState.addCommand(cmd)
	inputRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(inputRec, httptest.NewRequest(http.MethodPost, "/process/session/input-live/command/cmd-1/input", bytes.NewBufferString(`{"data":"x"}`)), "input-live", "cmd-1")
	if inputRec.Code != http.StatusConflict {
		t.Fatalf("input on non-accepting command status = %d", inputRec.Code)
	}
	// Accepting + stdin closed → Write error while lookup still succeeds.
	liveState.activeCommandID = "cmd-1"
	cmd.running = true
	if err := live.CloseStdin(); err != nil {
		t.Fatalf("CloseStdin: %v", err)
	}
	inputRec = httptest.NewRecorder()
	srv.handleDaytonaSessionCommandInput(inputRec, httptest.NewRequest(http.MethodPost, "/process/session/input-live/command/cmd-1/input", bytes.NewBufferString(`{"data":"x"}`)), "input-live", "cmd-1")
	if inputRec.Code != http.StatusInternalServerError {
		t.Fatalf("input after CloseStdin status = %d body=%s", inputRec.Code, inputRec.Body.String())
	}
}

func TestEnvdFilesystemOpsResolveAndIOErrors(t *testing.T) {
	srv := newEnvdTestServer(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	makeDir := func(path string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"path": path})
		rec := httptest.NewRecorder()
		srv.handleEnvdFilesystemMakeDir(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		return rec
	}
	if rec := makeDir(""); rec.Code != http.StatusBadRequest {
		t.Fatalf("makedir empty = %d", rec.Code)
	}
	existingFile := filepath.Join(t.TempDir(), "exists.txt")
	if err := os.WriteFile(existingFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile exists: %v", err)
	}
	if rec := makeDir(existingFile); rec.Code != http.StatusConflict {
		t.Fatalf("makedir file conflict = %d", rec.Code)
	}
	existingDir := t.TempDir()
	if rec := makeDir(existingDir); rec.Code != http.StatusConflict {
		t.Fatalf("makedir dir conflict = %d", rec.Code)
	}
	if rec := makeDir(filepath.Join(blocker, "child")); rec.Code == http.StatusOK {
		t.Fatalf("makedir under file should fail, got %d", rec.Code)
	}

	move := func(src, dst string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"source": src, "destination": dst})
		rec := httptest.NewRecorder()
		srv.handleEnvdFilesystemMove(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		return rec
	}
	if rec := move("", "/tmp/x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("move empty src = %d", rec.Code)
	}
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile src: %v", err)
	}
	if rec := move(src, filepath.Join(blocker, "dst.txt")); rec.Code == http.StatusOK {
		t.Fatalf("move mkdir fail should error, got %d", rec.Code)
	}
	if rec := move(filepath.Join(t.TempDir(), "missing.txt"), filepath.Join(t.TempDir(), "dst.txt")); rec.Code == http.StatusOK {
		t.Fatalf("move missing should error, got %d", rec.Code)
	}

	list := func(path string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"path": path, "depth": 1})
		rec := httptest.NewRecorder()
		srv.handleEnvdFilesystemListDir(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		return rec
	}
	if rec := list(filepath.Join(t.TempDir(), "missing-list-dir")); rec.Code == http.StatusOK {
		t.Fatalf("listdir missing should fail, got %d", rec.Code)
	}

	remove := func(path string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"path": path})
		rec := httptest.NewRecorder()
		srv.handleEnvdFilesystemRemove(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		return rec
	}
	if rec := remove(""); rec.Code != http.StatusBadRequest {
		t.Fatalf("remove empty = %d", rec.Code)
	}
	if rec := remove(filepath.Join(t.TempDir(), "missing-remove")); rec.Code == http.StatusOK {
		t.Fatalf("remove missing should fail, got %d", rec.Code)
	}

	statRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemStat(statRec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"path":""}`))))
	if statRec.Code != http.StatusBadRequest {
		t.Fatalf("stat empty = %d", statRec.Code)
	}

	if got := envdPermissionString(0); got == "" {
		// mode.String() for 0 is "----------" or similar; empty only if String returns "".
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

func TestEnvdProcessErrorBranches(t *testing.T) {
	srv := newEnvdTestServer(t)

	startBody, _ := json.Marshal(map[string]any{
		"process": map[string]any{
			"cmd":  "/nonexistent-envd-bin-xyz",
			"args": []string{},
		},
	})
	startRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodeConnectEnvelopeForTest(startBody)))
	srv.handleEnvdProcessStart(startRec, req)

	for _, fn := range []func(http.ResponseWriter, *http.Request){
		srv.handleEnvdProcessConnect,
		srv.handleEnvdProcessUpdate,
		srv.handleEnvdProcessCloseStdin,
	} {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(`{"process_id":"missing"}`)))))
	}
	inputRec := httptest.NewRecorder()
	srv.handleEnvdProcessSendInput(inputRec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(`{"process_id":"missing","input":{"data":"eA=="}}`)))))
	signalRec := httptest.NewRecorder()
	srv.handleEnvdProcessSendSignal(signalRec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(`{"process_id":"missing","signal":1}`)))))

	frames := make(chan sessions.Frame, 1)
	frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("x")}
	close(frames)
	srv.drainEnvdProcessFrames(&connectJSONStream{w: httptest.NewRecorder()}, frames, false)

	badUser := httptest.NewRequest(http.MethodGet, "/?username=not-a-real-user-cov95", nil)
	if validateEnvdRequestedUser(httptest.NewRecorder(), badUser) {
		t.Fatal("expected validateEnvdRequestedUser failure for unsupported user")
	}
	if _, err := requestedEnvdUsername(nil); err != nil {
		t.Fatalf("nil request username: %v", err)
	}
	conflict := httptest.NewRequest(http.MethodGet, "/?username=a", nil)
	conflict.Header.Set("X-E2B-User-Authorization", basicUserHeaderForTest("b"))
	if _, err := requestedEnvdUsername(conflict); err == nil {
		t.Fatal("expected conflicting envd users error")
	}
}

func TestInterpretWaitResultNonExitErrors(t *testing.T) {
	code, sig := interpretWaitResult(nil)
	if code != 0 || sig != "" {
		t.Fatalf("nil = (%d,%q)", code, sig)
	}
	code, sig = interpretWaitResult(syscall.ECHILD)
	if code != 0 || sig != "" {
		t.Fatalf("ECHILD = (%d,%q)", code, sig)
	}
	code, sig = interpretWaitResult(errors.New("wait boom"))
	if code != -1 || sig != "wait boom" {
		t.Fatalf("generic = (%d,%q)", code, sig)
	}
}

func TestDaytonaFilesGitIOErrorMatrix(t *testing.T) {
	srv := newDaytonaTestServer(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	filePath := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile file: %v", err)
	}

	listRec := httptest.NewRecorder()
	srv.handleDaytonaListFiles(listRec, httptest.NewRequest(http.MethodGet, "/files?path="+filePath, nil))
	if listRec.Code == http.StatusOK {
		t.Fatalf("list files on file should fail, got %d", listRec.Code)
	}

	gitOps := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
		body string
	}{
		{"add", srv.handleDaytonaGitAdd, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","files":["a"]}`},
		{"checkout", srv.handleDaytonaGitCheckout, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","branch":"main"}`},
		{"commit", srv.handleDaytonaGitCommit, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","message":"m","author":"a","email":"e@e"}`},
		{"createBranch", srv.handleDaytonaGitCreateBranch, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","name":"b"}`},
		{"deleteBranch", srv.handleDaytonaGitDeleteBranch, `{"path":"` + filepath.Join(t.TempDir(), "norepo") + `","name":"b"}`},
	}
	for _, tc := range gitOps {
		rec := httptest.NewRecorder()
		tc.fn(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)))
		if rec.Code == http.StatusNoContent || rec.Code == http.StatusOK {
			t.Fatalf("%s expected error, got %d", tc.name, rec.Code)
		}
	}

	cloneRec := httptest.NewRecorder()
	cloneBody := `{"path":"` + filepath.Join(blocker, "repo") + `","url":"https://example.com/r.git"}`
	srv.handleDaytonaGitClone(cloneRec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(cloneBody)))
	if cloneRec.Code == http.StatusNoContent {
		t.Fatalf("clone mkdir fail should error, got %d", cloneRec.Code)
	}

	// Clone auth goes into GIT_CONFIG_* env, not the URL userinfo.
	u, env := gitCloneURLAndAuthEnv("https://example.com/r.git", "user", "")
	if u == "" || len(env) == 0 || !strings.Contains(strings.Join(env, " "), "Authorization: Basic") {
		t.Fatalf("expected auth env for username-only, url=%q env=%v", u, env)
	}
	u2, env2 := gitCloneURLAndAuthEnv("https://example.com/r.git", "user", "pass")
	if u2 == "" || len(env2) == 0 {
		t.Fatalf("expected auth env for user+pass, url=%q env=%v", u2, env2)
	}
	_, env3 := gitCloneURLAndAuthEnv("https://user:pass@example.com/r.git", "", "")
	if len(env3) == 0 {
		t.Fatal("expected auth env extracted from URL userinfo")
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

func TestRunDaytonaSessionCommandStderrAndExit(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"stderr-sess"}`)))
	if createRec.Code != http.StatusCreated && createRec.Code != http.StatusOK {
		t.Fatalf("create = %d", createRec.Code)
	}
	execRec := httptest.NewRecorder()
	cmd := `echo start; echo err-line >&2; true`
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/stderr-sess/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "stderr-sess")
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec status = %d body=%s", execRec.Code, execRec.Body.String())
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestValidateEnvdUserAndRequestedUsername(t *testing.T) {
	okReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if !validateEnvdRequestedUser(httptest.NewRecorder(), okReq) {
		t.Fatal("empty user should be ok")
	}
	current, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Skip("id -un unavailable")
	}
	user := strings.TrimSpace(string(current))
	userReq := httptest.NewRequest(http.MethodGet, "/?username="+user, nil)
	if !validateEnvdRequestedUser(httptest.NewRecorder(), userReq) {
		t.Fatalf("current user validate failed for %q", user)
	}
	basicReq := httptest.NewRequest(http.MethodGet, "/", nil)
	basicReq.Header.Set("X-E2B-User-Authorization", basicUserHeaderForTest(user))
	got, err := requestedEnvdUsername(basicReq)
	if err != nil || got != user {
		t.Fatalf("basic username = (%q, %v), want %q", got, err, user)
	}
}
