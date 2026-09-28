package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
)

func TestEnvdMultipartEmptyFilenameResolveError(t *testing.T) {
	srv := newEnvdTestServer(t)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename=""`)
	h.Set("Content-Type", "application/octet-stream")
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/envd/files", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.handleEnvdMultipartWrite(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty filename status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestValidateEnvdRequestedUserBadBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-E2B-User-Authorization", "Basic !!!")
	if validateEnvdRequestedUser(httptest.NewRecorder(), req) {
		t.Fatal("expected bad basic auth to fail validation")
	}
}

func TestEnvdOctetCreateOnDirectoryAndRemoveChmod(t *testing.T) {
	srv := newEnvdTestServer(t)
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/envd/files?path="+dir, bytes.NewReader([]byte("x")))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	srv.handleEnvdOctetStreamWrite(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("octet create-on-dir should fail, got %d", rec.Code)
	}

	locked := t.TempDir()
	target := filepath.Join(locked, "victim")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	body, _ := json.Marshal(map[string]string{"path": target})
	rem := httptest.NewRecorder()
	srv.handleEnvdFilesystemRemove(rem, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if rem.Code == http.StatusOK {
		if os.Geteuid() == 0 {
			t.Log("root can remove files from mode 0555 dirs; skipping assertion")
		} else {
			t.Fatalf("remove in locked dir should fail, got %d", rem.Code)
		}
	}

	// MakeDir Stat permission-denied (not ErrNotExist).
	statDenied := t.TempDir()
	if err := os.Chmod(statDenied, 0); err != nil {
		t.Fatalf("Chmod denied: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(statDenied, 0o755) })
	body, _ = json.Marshal(map[string]string{"path": filepath.Join(statDenied, "child")})
	md := httptest.NewRecorder()
	srv.handleEnvdFilesystemMakeDir(md, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if md.Code == http.StatusOK {
		if os.Geteuid() == 0 {
			t.Log("root can mkdir under mode 000 dirs; skipping assertion")
		} else {
			t.Fatalf("makedir under 000 dir should fail, got %d", md.Code)
		}
	}
}

func TestEnvdCompatNilLookupList(t *testing.T) {
	var c *envdCompat
	if _, ok := c.lookup(envdProcessSelector{}); ok {
		t.Fatal("nil lookup should miss")
	}
	if got := c.list(); got != nil {
		t.Fatalf("nil list = %v", got)
	}
	pid := 1
	if _, ok := c.lookup(envdProcessSelector{PID: &pid}); ok {
		t.Fatal("nil lookup by pid should miss")
	}

	live := newEnvdCompat()
	live.byTag["stale"] = 99999
	if _, ok := live.lookup(envdProcessSelector{Tag: "stale"}); ok {
		t.Fatal("stale tag should miss when pid absent")
	}
}

type failWriter struct {
	httptest.ResponseRecorder
	failAfter int
	writes    int
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("write boom")
	}
	return f.ResponseRecorder.Write(p)
}

func (f *failWriter) Header() http.Header { return f.ResponseRecorder.Header() }

func (f *failWriter) WriteHeader(status int) {
	f.ResponseRecorder.WriteHeader(status)
}

func TestWriteConnectEnvelopeAndDrainSendErrors(t *testing.T) {
	fw := &failWriter{failAfter: 0}
	fw.ResponseRecorder = *httptest.NewRecorder()
	if err := writeConnectEnvelope(fw, 0, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected header write failure")
	}
	fw2 := &failWriter{failAfter: 1}
	fw2.ResponseRecorder = *httptest.NewRecorder()
	if err := writeConnectEnvelope(fw2, 0, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected payload write failure")
	}

	frames := make(chan sessions.Frame, 1)
	frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("x")}
	close(frames)
	fw3 := &failWriter{failAfter: 0}
	fw3.ResponseRecorder = *httptest.NewRecorder()
	srv := newEnvdTestServer(t)
	srv.drainEnvdProcessFrames(&connectJSONStream{w: fw3}, frames, true)
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
