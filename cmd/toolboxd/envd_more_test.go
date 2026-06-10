package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
)

func makeEnvdRegisteredProcess(t *testing.T, srv *server, name string, pty, stdin bool) (*sessions.Session, *envdProcessState) {
	t.Helper()
	req := models.CreateSessionRequest{
		Name:    name,
		Command: "sleep 5",
		PTY:     pty,
	}
	if pty {
		req.Cols = 80
		req.Rows = 24
	}
	sess, err := srv.sessions.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create session %q: %v", name, err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(sess.ID()) })

	state, err := srv.envd.registerSession(sess, strings.TrimSpace(name), envdProcessConfig{
		Cmd:  "sleep",
		Args: []string{"5"},
		Envs: map[string]string{"TEST": name},
		Cwd:  "",
	}, pty, stdin)
	if err != nil {
		t.Fatalf("registerSession %q: %v", name, err)
	}
	return sess, state
}

func TestEnvdCompatAndRequestHelpers(t *testing.T) {
	srv := newEnvdTestServer(t)

	var nilCompat *envdCompat
	if _, err := nilCompat.registerSession(nil, "", envdProcessConfig{}, false, false); err == nil {
		t.Fatal("expected nil compat to fail")
	}
	if _, err := srv.envd.registerSession(nil, "", envdProcessConfig{}, false, false); err == nil {
		t.Fatal("expected nil session to fail")
	}

	pipeSessA, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "envd-a", Command: "sleep 5"})
	if err != nil {
		t.Fatalf("Create envd-a: %v", err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(pipeSessA.ID()) })
	pipeSessB, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "envd-b", Command: "sleep 5"})
	if err != nil {
		t.Fatalf("Create envd-b: %v", err)
	}
	t.Cleanup(func() { _ = srv.sessions.Delete(pipeSessB.ID()) })

	origEnv := map[string]string{"A": "1"}
	stateA, err := srv.envd.registerSession(pipeSessA, " tag-a ", envdProcessConfig{
		Cmd:  "echo",
		Args: []string{"hello"},
		Envs: origEnv,
		Cwd:  " /tmp ",
	}, false, false)
	if err != nil {
		t.Fatalf("registerSession tag-a: %v", err)
	}
	origEnv["A"] = "mutated"
	if stateA.Tag != "tag-a" || stateA.Config.Cmd != "echo" || stateA.Config.Cwd != "/tmp" || stateA.Config.Envs["A"] != "1" {
		t.Fatalf("unexpected cloned envd state: %+v", stateA)
	}

	if _, err := srv.envd.registerSession(pipeSessB, "tag-a", envdProcessConfig{}, false, false); !errors.Is(err, errEnvdProcessTagConflict) {
		t.Fatalf("expected tag conflict, got %v", err)
	}

	if got, ok := srv.envd.lookup(envdProcessSelector{PID: &stateA.PID}); !ok || got.PID != stateA.PID {
		t.Fatalf("lookup by pid = (%v, %v)", got, ok)
	}
	if got, ok := srv.envd.lookup(envdProcessSelector{Tag: "tag-a"}); !ok || got.Tag != "tag-a" {
		t.Fatalf("lookup by tag = (%v, %v)", got, ok)
	}
	srv.envd.removeSession(stateA.PID, "wrong-session")
	if got, ok := srv.envd.lookup(envdProcessSelector{Tag: "tag-a"}); !ok || got.PID != stateA.PID {
		t.Fatalf("removeSession wrong id removed state unexpectedly: (%v, %v)", got, ok)
	}
	srv.envd.removeSession(stateA.PID, pipeSessA.ID())
	if _, ok := srv.envd.lookup(envdProcessSelector{Tag: "tag-a"}); ok {
		t.Fatal("expected removed envd state to disappear")
	}

	cloned := cloneEnvdProcessState(&envdProcessState{PID: 1, SessionID: "s", Tag: "t", Config: envdProcessConfig{
		Cmd:  "cmd",
		Args: []string{"a"},
		Envs: map[string]string{"K": "V"},
		Cwd:  "cwd",
	}})
	cloned.Config.Envs["K"] = "mutated"
	if cloned.Config.Envs["K"] != "mutated" {
		t.Fatal("cloneEnvdProcessState did not return a mutable copy")
	}
	if out := cloneEnvdStringMap(nil); len(out) != 0 {
		t.Fatalf("cloneEnvdStringMap(nil) = %v, want empty map", out)
	}

	req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
	req.Header.Set("X-E2B-User-Authorization", basicUserHeaderForTest("bob"))
	if _, err := requestedEnvdUsername(req); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("requestedEnvdUsername conflict = %v", err)
	}
	if _, err := requestedEnvdUsername(httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatalf("requestedEnvdUsername nil auth = %v", err)
	}
	if _, err := parseEnvdBasicUsername("Digest abc"); err == nil {
		t.Fatal("expected invalid auth scheme error")
	}
	validBasic := basicUserHeaderForTest("carol")
	if got, err := parseEnvdBasicUsername(validBasic); err != nil || got != "carol" {
		t.Fatalf("parseEnvdBasicUsername = (%q, %v), want carol/nil", got, err)
	}

	input := envdProcessInput{PTY: base64.StdEncoding.EncodeToString([]byte("tty"))}
	if payload, isPTY, err := input.decode(); err != nil || !isPTY || string(payload) != "tty" {
		t.Fatalf("decode PTY = (%q, %v, %v)", payload, isPTY, err)
	}
	if _, _, err := (envdProcessInput{}).decode(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("decode missing input = %v", err)
	}
	if _, _, err := (envdProcessInput{Stdin: "not-base64"}).decode(); err == nil || !strings.Contains(err.Error(), "encoding") {
		t.Fatalf("decode invalid stdin = %v", err)
	}

	if got, err := mapEnvdSignal("TERM"); err != nil || got != "TERM" {
		t.Fatalf("mapEnvdSignal(TERM) = (%q, %v)", got, err)
	}
	if got, err := mapEnvdSignal("bogus"); err == nil || got != "" {
		t.Fatalf("mapEnvdSignal(bogus) = (%q, %v)", got, err)
	}
	if !isSupportedEnvdUser("") {
		t.Fatal("expected blank envd user to be supported")
	}
	if user := strings.TrimSpace(os.Getenv("USER")); user != "" && !isSupportedEnvdUser(user) {
		t.Fatalf("expected current USER %q to be supported", user)
	}
	if isSupportedEnvdUser("definitely-unsupported-user") {
		t.Fatal("expected unsupported envd user to be rejected")
	}

	shortReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader([]byte{0, 0, 0, 0}))
	var startDst envdStartRequest
	if err := readConnectJSONRequest(shortReq, &startDst); err == nil || !strings.Contains(err.Error(), "invalid connect request envelope") {
		t.Fatalf("truncated connect envelope = %v", err)
	}
	compressedHeader := make([]byte, connectEnvelopeHeaderLen)
	compressedHeader[0] = connectFlagCompressed
	binary.BigEndian.PutUint32(compressedHeader[1:], 0)
	compressedReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(compressedHeader))
	if err := readConnectJSONRequest(compressedReq, &startDst); err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("compressed connect envelope = %v", err)
	}
	payload, _ := json.Marshal(envdStartRequest{Process: envdProcessConfig{Cmd: "echo"}})
	truncated := append(make([]byte, connectEnvelopeHeaderLen), payload[:len(payload)-1]...)
	binary.BigEndian.PutUint32(truncated[1:], uint32(len(payload)))
	truncatedReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(truncated))
	if err := readConnectJSONRequest(truncatedReq, &startDst); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated payload = %v", err)
	}

	ticker := newKeepaliveTicker(httptest.NewRequest(http.MethodGet, "/", nil))
	if ticker != nil {
		t.Fatalf("newKeepaliveTicker without header = %v", ticker)
	}
	withTicker := httptest.NewRequest(http.MethodGet, "/", nil)
	withTicker.Header.Set("Keepalive-Ping-Interval", "1")
	ticker = newKeepaliveTicker(withTicker)
	if ticker == nil {
		t.Fatal("expected keepalive ticker")
	}
	ticker.Stop()

	if got := writeConnectEnvelope(httptest.NewRecorder(), 0, map[string]any{"hello": "world"}); got != nil {
		t.Fatalf("writeConnectEnvelope = %v", got)
	}

	rec := httptest.NewRecorder()
	stream := startConnectJSONStream(rec)
	if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{Keepalive: &struct{}{}}}); err != nil {
		t.Fatalf("stream.Send: %v", err)
	}
	if err := stream.End(); err != nil {
		t.Fatalf("stream.End: %v", err)
	}

	missingPath := filepath.Join(t.TempDir(), "missing")
	if _, err := buildEnvdEntryInfoAt(missingPath, missingPath); err == nil {
		t.Fatal("expected buildEnvdEntryInfoAt missing path to fail")
	}

	symlinkRoot := t.TempDir()
	realFile := filepath.Join(symlinkRoot, "real.txt")
	linkFile := filepath.Join(symlinkRoot, "link.txt")
	if err := os.WriteFile(realFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	entry, err := buildEnvdEntryInfoAt(linkFile, linkFile)
	if err != nil {
		t.Fatalf("buildEnvdEntryInfoAt symlink: %v", err)
	}
	if entry.SymlinkTarget == nil || *entry.SymlinkTarget != realFile {
		t.Fatalf("expected symlink target %q, got %+v", realFile, entry.SymlinkTarget)
	}
	if perm := envdPermissionString(os.FileMode(0)); perm == "" {
		t.Fatal("expected permission string for zero mode")
	}

	if rec := httptest.NewRecorder(); func() int {
		writeEnvdFilesystemError(rec, os.ErrNotExist)
		return rec.Code
	}() != http.StatusNotFound {
		t.Fatal("writeEnvdFilesystemError not exist mismatch")
	}

	if rec := httptest.NewRecorder(); func() int {
		writeEnvdFilesystemError(rec, os.ErrPermission)
		return rec.Code
	}() != http.StatusForbidden {
		t.Fatal("writeEnvdFilesystemError permission mismatch")
	}

	if rec := httptest.NewRecorder(); func() int {
		writeEnvdFilesystemError(rec, os.ErrExist)
		return rec.Code
	}() != http.StatusConflict {
		t.Fatal("writeEnvdFilesystemError exist mismatch")
	}
}

func TestEnvdHandlerErrorBranches(t *testing.T) {
	srv := newEnvdTestServer(t)

	t.Run("file_write_errors", func(t *testing.T) {
		octetBody := bytes.NewBuffer([]byte("bad"))
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+filepath.Join(t.TempDir(), "x.txt"), octetBody)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
		rr := httptest.NewRecorder()
		srv.handleEnvdOctetStreamWrite(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("octet stream status = %d, want 400", rr.Code)
		}

		invalidMultipart := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+filepath.Join(t.TempDir(), "x.txt"), strings.NewReader("not multipart"))
		invalidMultipart.Header.Set("Content-Type", "multipart/form-data; boundary=missing")
		rr = httptest.NewRecorder()
		srv.handleEnvdMultipartWrite(rr, invalidMultipart)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid multipart status = %d, want 400", rr.Code)
		}

		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.Close()
		missingFileReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+filepath.Join(t.TempDir(), "x.txt"), &body)
		missingFileReq.Header.Set("Content-Type", mw.FormDataContentType())
		rr = httptest.NewRecorder()
		srv.handleEnvdMultipartWrite(rr, missingFileReq)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("missing file multipart status = %d, want 400", rr.Code)
		}
	})

	t.Run("process_handlers", func(t *testing.T) {
		srvNil := &server{logger: srv.logger, envd: newEnvdCompat(), sessions: nil}
		rr := httptest.NewRecorder()
		srvNil.handleEnvdProcessList(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/List", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("process list disabled status = %d, want 503", rr.Code)
		}
		rr = httptest.NewRecorder()
		srvNil.handleEnvdProcessStart(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(nil))))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("process start disabled status = %d, want 503", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdProcessStart(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(`{"process":{"cmd":""}}`)))))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("process start missing cmd status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdProcessConnect(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Connect", bytes.NewReader([]byte{0x00, 0x00})))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("process connect invalid envelope status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdProcessUpdate(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("process update invalid JSON status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdProcessUpdate(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader(`{"process":{}}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("process update missing selector status = %d, want 404", rr.Code)
		}

		pipeSess, pipeState := makeEnvdRegisteredProcess(t, srv, "pipe", false, false)
		pipePID := pipeState.PID
		stdinBody, _ := json.Marshal(envdSendInputRequest{
			Process: envdProcessSelector{PID: &pipePID},
			Input:   envdProcessInput{Stdin: base64.StdEncoding.EncodeToString([]byte("hello"))},
		})
		rr = httptest.NewRecorder()
		srv.handleEnvdProcessSendInput(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(stdinBody)))
		if rr.Code != http.StatusFailedDependency {
			t.Fatalf("pipe stdin disabled status = %d, want 424", rr.Code)
		}

		ptySess, ptyState := makeEnvdRegisteredProcess(t, srv, "pty", true, true)
		ptyPID := ptyState.PID
		ptyBody, _ := json.Marshal(envdSendInputRequest{
			Process: envdProcessSelector{PID: &ptyPID},
			Input:   envdProcessInput{Stdin: base64.StdEncoding.EncodeToString([]byte("hello"))},
		})
		rr = httptest.NewRecorder()
		srv.handleEnvdProcessSendInput(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(ptyBody)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("pty stdin mismatch status = %d, want 400", rr.Code)
		}

		signalBody, _ := json.Marshal(envdSendSignalRequest{
			Process: envdProcessSelector{PID: &pipePID},
			Signal:  "bogus",
		})
		rr = httptest.NewRecorder()
		srv.handleEnvdProcessSendSignal(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", bytes.NewReader(signalBody)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("process send signal invalid status = %d, want 400", rr.Code)
		}

		closeBody, _ := json.Marshal(envdCloseStdinRequest{Process: envdProcessSelector{PID: &pipePID}})
		rr = httptest.NewRecorder()
		srv.handleEnvdProcessCloseStdin(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", bytes.NewReader(closeBody)))
		if rr.Code != http.StatusOK {
			t.Fatalf("process close stdin noop status = %d, want 200", rr.Code)
		}

		t.Cleanup(func() {
			_ = srv.sessions.Delete(pipeSess.ID())
			_ = srv.sessions.Delete(ptySess.ID())
		})
	})

	t.Run("filesystem_handlers", func(t *testing.T) {
		rr := httptest.NewRecorder()
		srv.handleEnvdFilesystemStat(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Stat", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("filesystem stat invalid JSON status = %d, want 400", rr.Code)
		}

		dir := t.TempDir()
		rr = httptest.NewRecorder()
		srv.handleEnvdFilesystemMakeDir(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader(`{"path":"`+dir+`"}`)))
		if rr.Code != http.StatusConflict {
			t.Fatalf("filesystem make dir conflict status = %d, want 409", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdFilesystemMove(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("filesystem move invalid JSON status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		srv.handleEnvdFilesystemListDir(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/ListDir", strings.NewReader("{bad")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("filesystem list dir invalid JSON status = %d, want 400", rr.Code)
		}

		rr = httptest.NewRecorder()
		missingPath := filepath.Join(t.TempDir(), "missing")
		srv.handleEnvdFilesystemRemove(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Remove", strings.NewReader(`{"path":"`+missingPath+`"}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("filesystem remove missing path status = %d, want 404", rr.Code)
		}
	})
}

func TestEnvdFilesystemAndProcessSuccessBranches(t *testing.T) {
	srv := newEnvdTestServer(t)

	root := t.TempDir()
	targetDir := filepath.Join(root, "dir")
	makeDirReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader(`{"path":"`+targetDir+`"}`))
	makeDirRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemMakeDir(makeDirRec, makeDirReq)
	if makeDirRec.Code != http.StatusOK {
		t.Fatalf("make dir status = %d body=%s", makeDirRec.Code, makeDirRec.Body.String())
	}

	sourceFile := filepath.Join(targetDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("hello-envd"), 0o600); err != nil {
		t.Fatalf("WriteFile source: %v", err)
	}
	destinationFile := filepath.Join(targetDir, "destination.txt")
	moveReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", strings.NewReader(`{"source":"`+sourceFile+`","destination":"`+destinationFile+`"}`))
	moveRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemMove(moveRec, moveReq)
	if moveRec.Code != http.StatusOK {
		t.Fatalf("move status = %d body=%s", moveRec.Code, moveRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/ListDir", strings.NewReader(`{"path":"`+targetDir+`","depth":2}`))
	listRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemListDir(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list dir status = %d body=%s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), "destination.txt") {
		t.Fatalf("list dir body missing moved file: %s", listRec.Body.String())
	}

	statReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Stat", strings.NewReader(`{"path":"`+destinationFile+`"}`))
	statRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemStat(statRec, statReq)
	if statRec.Code != http.StatusOK {
		t.Fatalf("stat status = %d body=%s", statRec.Code, statRec.Body.String())
	}

	removeReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Remove", strings.NewReader(`{"path":"`+destinationFile+`"}`))
	removeRec := httptest.NewRecorder()
	srv.handleEnvdFilesystemRemove(removeRec, removeReq)
	if removeRec.Code != http.StatusOK {
		t.Fatalf("remove status = %d body=%s", removeRec.Code, removeRec.Body.String())
	}

	oversizedHeader := make([]byte, connectEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(oversizedHeader[1:], connectJSONMaxPayloadLen+1)
	if err := readConnectJSONRequest(httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(oversizedHeader)), &envdStartRequest{}); err == nil {
		t.Fatal("expected oversize connect envelope to fail")
	}
	if err := writeConnectEnvelope(httptest.NewRecorder(), 0, make(chan int)); err == nil {
		t.Fatal("expected writeConnectEnvelope marshal failure")
	}

	pipeSess, pipeState := makeEnvdRegisteredProcess(t, srv, "pipe-success", false, true)
	pipePID := pipeState.PID

	inputBody, err := json.Marshal(envdSendInputRequest{
		Process: envdProcessSelector{PID: &pipePID},
		Input:   envdProcessInput{Stdin: base64.StdEncoding.EncodeToString([]byte("hello"))},
	})
	if err != nil {
		t.Fatalf("marshal send input request: %v", err)
	}
	inputRec := httptest.NewRecorder()
	srv.handleEnvdProcessSendInput(inputRec, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(inputBody)))
	if inputRec.Code != http.StatusOK {
		t.Fatalf("send input status = %d body=%s", inputRec.Code, inputRec.Body.String())
	}

	closeBody, err := json.Marshal(envdCloseStdinRequest{Process: envdProcessSelector{PID: &pipePID}})
	if err != nil {
		t.Fatalf("marshal close stdin request: %v", err)
	}
	closeRec := httptest.NewRecorder()
	srv.handleEnvdProcessCloseStdin(closeRec, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", bytes.NewReader(closeBody)))
	if closeRec.Code != http.StatusOK {
		t.Fatalf("close stdin status = %d body=%s", closeRec.Code, closeRec.Body.String())
	}

	signalBody, err := json.Marshal(envdSendSignalRequest{
		Process: envdProcessSelector{PID: &pipePID},
		Signal:  "TERM",
	})
	if err != nil {
		t.Fatalf("marshal send signal request: %v", err)
	}
	signalRec := httptest.NewRecorder()
	srv.handleEnvdProcessSendSignal(signalRec, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", bytes.NewReader(signalBody)))
	if signalRec.Code != http.StatusOK {
		t.Fatalf("send signal status = %d body=%s", signalRec.Code, signalRec.Body.String())
	}

	t.Cleanup(func() { _ = srv.sessions.Delete(pipeSess.ID()) })

	ptySess, ptyState := makeEnvdRegisteredProcess(t, srv, "pty-success", true, true)
	ptyPID := ptyState.PID
	ptyInputBody, err := json.Marshal(envdSendInputRequest{
		Process: envdProcessSelector{PID: &ptyPID},
		Input:   envdProcessInput{PTY: base64.StdEncoding.EncodeToString([]byte("pty"))},
	})
	if err != nil {
		t.Fatalf("marshal PTY send input request: %v", err)
	}
	ptyInputRec := httptest.NewRecorder()
	srv.handleEnvdProcessSendInput(ptyInputRec, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(ptyInputBody)))
	if ptyInputRec.Code != http.StatusOK {
		t.Fatalf("pty send input status = %d body=%s", ptyInputRec.Code, ptyInputRec.Body.String())
	}

	ptyCloseBody, err := json.Marshal(envdCloseStdinRequest{Process: envdProcessSelector{PID: &ptyPID}})
	if err != nil {
		t.Fatalf("marshal PTY close stdin request: %v", err)
	}
	ptyCloseRec := httptest.NewRecorder()
	srv.handleEnvdProcessCloseStdin(ptyCloseRec, httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", bytes.NewReader(ptyCloseBody)))
	if ptyCloseRec.Code != http.StatusOK {
		t.Fatalf("pty close stdin status = %d body=%s", ptyCloseRec.Code, ptyCloseRec.Body.String())
	}

	t.Cleanup(func() { _ = srv.sessions.Delete(ptySess.ID()) })
}
