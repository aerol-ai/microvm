package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

func TestEnvdCompatHelpersAndSelectors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-envd",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 16,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Name:    "envd-state",
		Command: "sleep 30",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	compat := newEnvdCompat()
	if _, err := (*envdCompat)(nil).registerSession(sess, "", envdProcessConfig{}, false, false); err == nil {
		t.Fatal("nil compat registerSession expected error")
	}
	if _, err := compat.registerSession(nil, "", envdProcessConfig{}, false, false); err == nil {
		t.Fatal("nil session registerSession expected error")
	}
	if _, err := compat.registerSession(&sessions.Session{}, "", envdProcessConfig{}, false, false); err == nil {
		t.Fatal("session without pid registerSession expected error")
	}

	state, err := compat.registerSession(sess, "tag-1", envdProcessConfig{
		Cmd:  " sleep ",
		Args: []string{"1"},
		Envs: map[string]string{"A": "1"},
		Cwd:  " /tmp ",
	}, false, true)
	if err != nil {
		t.Fatalf("registerSession: %v", err)
	}
	if state.Tag != "tag-1" || state.Config.Cmd != "sleep" || state.Config.Cwd != "/tmp" || !state.Stdin {
		t.Fatalf("unexpected registered state: %+v", state)
	}
	if _, err := compat.registerSession(sess, "tag-1", envdProcessConfig{}, false, false); !errors.Is(err, errEnvdProcessTagConflict) {
		t.Fatalf("tag conflict err = %v", err)
	}

	clone := cloneEnvdProcessState(state)
	clone.Config.Args[0] = "changed"
	clone.Config.Envs["A"] = "2"
	if state.Config.Args[0] != "1" || state.Config.Envs["A"] != "1" {
		t.Fatal("cloneEnvdProcessState did not deep-clone config")
	}
	if got := cloneEnvdStringMap(nil); len(got) != 0 {
		t.Fatalf("cloneEnvdStringMap(nil) len = %d, want 0", len(got))
	}

	if _, ok := compat.lookup(envdProcessSelector{}); ok {
		t.Fatal("lookup with empty selector should miss")
	}
	if _, ok := compat.lookup(envdProcessSelector{Tag: "missing"}); ok {
		t.Fatal("lookup missing tag should miss")
	}
	lookedUp, ok := compat.lookup(envdProcessSelector{Tag: "tag-1"})
	if !ok || lookedUp.PID != state.PID {
		t.Fatalf("lookup by tag = (%+v,%v)", lookedUp, ok)
	}
	pid := state.PID
	lookedUp, ok = compat.lookup(envdProcessSelector{PID: &pid})
	if !ok || lookedUp.SessionID != state.SessionID {
		t.Fatalf("lookup by pid = (%+v,%v)", lookedUp, ok)
	}
	if items := compat.list(); len(items) != 1 || items[0].PID != state.PID {
		t.Fatalf("list = %+v", items)
	}

	compat.removeSession(-1, state.SessionID)
	compat.removeSession(state.PID, "wrong")
	if _, ok := compat.lookup(envdProcessSelector{Tag: "tag-1"}); !ok {
		t.Fatal("removeSession with wrong session id should not remove entry")
	}
	compat.removeSession(state.PID, state.SessionID)
	if _, ok := compat.lookup(envdProcessSelector{Tag: "tag-1"}); ok {
		t.Fatal("removeSession should remove entry")
	}
}

func TestEnvdHelperCoverage(t *testing.T) {
	if payload, isPTY, err := (envdProcessInput{}).decode(); err == nil || payload != nil || isPTY {
		t.Fatal("decode with empty input expected error")
	}
	if payload, isPTY, err := (envdProcessInput{PTY: "%%%"}).decode(); err == nil || payload != nil || isPTY {
		t.Fatal("decode invalid PTY expected error")
	}
	if payload, isPTY, err := (envdProcessInput{Stdin: "%%%"}).decode(); err == nil || payload != nil || isPTY {
		t.Fatal("decode invalid stdin expected error")
	}
	ptyPayload, isPTY, err := (envdProcessInput{PTY: base64.StdEncoding.EncodeToString([]byte("abc"))}).decode()
	if err != nil || !isPTY || string(ptyPayload) != "abc" {
		t.Fatalf("PTY decode = (%q,%v,%v)", string(ptyPayload), isPTY, err)
	}
	stdinPayload, isPTY, err := (envdProcessInput{Stdin: base64.StdEncoding.EncodeToString([]byte("xyz"))}).decode()
	if err != nil || isPTY || string(stdinPayload) != "xyz" {
		t.Fatalf("stdin decode = (%q,%v,%v)", string(stdinPayload), isPTY, err)
	}

	if sig, err := mapEnvdSignal(""); err != nil || sig != "TERM" {
		t.Fatalf("mapEnvdSignal(\"\") = (%q,%v)", sig, err)
	}
	if _, err := mapEnvdSignal("BOGUS"); err == nil {
		t.Fatal("mapEnvdSignal(BOGUS) expected error")
	}
	if got := uniqueEnvdSessionName(""); !strings.HasPrefix(got, "envd-") {
		t.Fatalf("uniqueEnvdSessionName(empty) = %q", got)
	}
	if got := uniqueEnvdSessionName("tag"); !strings.HasPrefix(got, "envd-tag-") {
		t.Fatalf("uniqueEnvdSessionName(tag) = %q", got)
	}

	req := httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader([]byte{0, 0, 0}))
	var dst map[string]any
	if err := readConnectJSONRequest(req, &dst); err == nil {
		t.Fatal("truncated connect request expected error")
	}

	header := make([]byte, connectEnvelopeHeaderLen)
	header[0] = connectFlagCompressed
	binary.BigEndian.PutUint32(header[1:], 2)
	req = httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(append(header, []byte("{}")...)))
	if err := readConnectJSONRequest(req, &dst); err == nil {
		t.Fatal("compressed connect request expected error")
	}

	header = make([]byte, connectEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(header[1:], connectJSONMaxPayloadLen+1)
	req = httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(header))
	if err := readConnectJSONRequest(req, &dst); err == nil {
		t.Fatal("oversized connect request expected error")
	}

	payload, _ := json.Marshal(map[string]any{"x": "y"})
	header = make([]byte, connectEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	req = httptest.NewRequest(http.MethodPost, "/connect", bytes.NewReader(append(header, payload...)))
	if err := readConnectJSONRequest(req, &dst); err != nil || dst["x"] != "y" {
		t.Fatalf("readConnectJSONRequest ok err=%v dst=%v", err, dst)
	}

	req = httptest.NewRequest(http.MethodGet, "/connect", nil)
	if ticker := newKeepaliveTicker(req); ticker != nil {
		t.Fatal("newKeepaliveTicker without header should be nil")
	}
	req.Header.Set("Keepalive-Ping-Interval", "bad")
	if ticker := newKeepaliveTicker(req); ticker != nil {
		t.Fatal("newKeepaliveTicker with bad header should be nil")
	}
	req.Header.Set("Keepalive-Ping-Interval", "1")
	ticker := newKeepaliveTicker(req)
	if ticker == nil {
		t.Fatal("newKeepaliveTicker expected non-nil ticker")
	}
	defer ticker.Stop()
	select {
	case <-keepaliveChan(ticker):
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("keepalive ticker did not fire")
	}
	if ch := keepaliveChan(nil); ch != nil {
		t.Fatal("keepaliveChan(nil) should be nil")
	}
}

func TestDaytonaAndSessionRouteErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	disabled := &server{logger: logger, daytona: newDaytonaCompat()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/session", nil)
	if !disabled.handleDaytonaProcessRoute(rr, req) || rr.Code != http.StatusNotImplemented {
		t.Fatalf("sessions disabled status = %d", rr.Code)
	}

	srv := newDaytonaTestServer(t)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/entrypoint", nil)
	if !srv.handleDaytonaProcessRoute(rr, req) || rr.Code != http.StatusNotImplemented {
		t.Fatalf("entrypoint status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"delete-me"}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("session create status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/delete-me", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/delete-me", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/nope/command/cmd/input", strings.NewReader("{bad"))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing session input status = %d", rr.Code)
	}

	h := (&server{logger: logger, sessions: nil}).routes()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/abc", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("sessions route with nil manager status = %d", rr.Code)
	}
}

func TestEnvdProcessRouteBranches(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	startBody, _ := json.Marshal(map[string]any{
		"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "cat"}},
		"tag":     "pipe-proc",
		"stdin":   true,
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startBody)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	go h.ServeHTTP(rr, req)
	waitForEnvdStateTag(t, srv, "pipe-proc")

	t.Run("update_invalid_json_and_no_resize", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader("{bad"))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid update status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader(`{"process":{"tag":"pipe-proc"}}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("no-resize update status = %d", rr.Code)
		}
	})

	t.Run("send_input_variants", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", strings.NewReader("{bad"))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid send input status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", strings.NewReader(`{"process":{"tag":"missing"},"input":{"stdin":"YQ=="}}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("missing process send input status = %d", rr.Code)
		}

		body := `{"process":{"tag":"pipe-proc"},"input":{"pty":"` + base64.StdEncoding.EncodeToString([]byte("a")) + `"}}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("PTY-to-pipe send input status = %d", rr.Code)
		}
	})

	t.Run("close_stdin_invalid_json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", strings.NewReader("{bad"))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid close stdin status = %d", rr.Code)
		}
	})
}

func TestEnvdProcessStreamAndSelectorCleanup(t *testing.T) {
	srv := newEnvdTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{
		Name:    "selector-test",
		Command: "printf selector",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	state, err := srv.envd.registerSession(sess, "selector-tag", envdProcessConfig{Cmd: "printf", Args: []string{"selector"}}, false, false)
	if err != nil {
		t.Fatalf("registerSession: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not exit")
	}

	rr := httptest.NewRecorder()
	if _, _, ok := srv.lookupEnvdProcessSessionFromSelector(rr, envdProcessSelector{Tag: "selector-tag"}); ok {
		t.Fatal("lookupEnvdProcessSessionFromSelector should fail for exited session")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("lookup exited selector status = %d", rr.Code)
	}
	if _, ok := srv.envd.lookup(envdProcessSelector{PID: &state.PID}); ok {
		t.Fatal("exited session should be removed from envd state")
	}
}

func TestEnvdSelectorAndFilesystemErrorHelpers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, envd: newEnvdCompat()}

	rr := httptest.NewRecorder()
	if _, _, ok := srv.lookupEnvdProcessSessionFromSelector(rr, envdProcessSelector{Tag: "x"}); ok {
		t.Fatal("lookup with nil sessions should fail")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil sessions selector status = %d", rr.Code)
	}

	srv.sessions = newTestSessionsManagerForMain(t, logger)
	pid := 99999
	srv.envd.byPID[pid] = &envdProcessState{PID: pid, SessionID: "missing-session", Tag: "missing"}
	srv.envd.byTag["missing"] = pid
	rr = httptest.NewRecorder()
	if _, _, ok := srv.lookupEnvdProcessSessionFromSelector(rr, envdProcessSelector{Tag: "missing"}); ok {
		t.Fatal("lookup with missing session should fail")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing session selector status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	writeEnvdFilesystemError(rr, os.ErrPermission)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("permission error status = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	writeEnvdFilesystemError(rr, os.ErrExist)
	if rr.Code != http.StatusConflict {
		t.Fatalf("exist error status = %d", rr.Code)
	}
}

func newTestSessionsManagerForMain(t *testing.T, logger *slog.Logger) *sessions.Manager {
	t.Helper()
	mgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-main",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 16,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	return mgr
}

func TestDaytonaCommandErrorBranches(t *testing.T) {
	srv := newDaytonaTestServer(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/session", strings.NewReader(`{"sessionId":"cmd-errors"}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("create status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/cmd-errors/exec", strings.NewReader("{bad"))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad exec json status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/cmd-errors/exec", strings.NewReader(`{"command":"   "}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty exec command status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/cmd-errors/command/missing", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing command get status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/cmd-errors/command/missing/logs", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing command logs status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/cmd-errors/command/missing/logs?follow=true", nil)
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing command follow logs status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/cmd-errors/command//input", strings.NewReader(`{"data":"x"}`))
	srv.handleDaytonaProcessRoute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing command id status = %d", rr.Code)
	}
}

func TestDrainAndDaytonaLogStreaming(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	received := make(chan []byte, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		frames := make(chan sessions.Frame, 2)
		frames <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("out")}
		frames <- sessions.Frame{Stream: sessions.StreamStderr, Data: []byte("err")}
		close(frames)
		drain(conn, frames)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 2; i++ {
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		received <- data
	}
	close(received)

	var got [][]byte
	for msg := range received {
		got = append(got, msg)
	}
	if len(got) != 2 || got[0][0] != streamFramePrefixStdoutSession || got[1][0] != streamFramePrefixStderrSession {
		t.Fatalf("unexpected drained frames: %v", got)
	}
}

func TestProxyAdminAndSandboxHelpers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, sandboxID: "sb-proxy", allowedPorts: map[int]struct{}{65535: {}}}
	h := s.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy/not-a-port", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid port status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/proxy/65535/test", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("unreachable proxy status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/allowed-ports", strings.NewReader("{bad"))
	s.handleSetAllowedPorts(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("admin invalid json status = %d", rr.Code)
	}

	if got := readSandboxID(); got == "" {
		t.Fatal("readSandboxID returned empty")
	}
}
