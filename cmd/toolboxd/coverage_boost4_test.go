package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestQuiesceHandlerOnPing(t *testing.T) {
	h := newQuiesceHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err := h.OnPing(t.Context()); err != nil {
		t.Fatalf("OnPing: %v", err)
	}
}

func TestStartUserCommand_StartAndFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userCommandPID.Store(0)
	startUserCommand(logger, []string{"/bin/sh", "-c", "sleep 30"})
	if userCommandPID.Load() <= 0 {
		t.Fatal("userCommandPID was not set")
	}
	_ = syscall.Kill(-int(userCommandPID.Load()), syscall.SIGKILL)
	userCommandPID.Store(0)

	startUserCommand(logger, []string{"/definitely/missing-command"})
	if userCommandPID.Load() != 0 {
		t.Fatalf("userCommandPID after failed start = %d, want 0", userCommandPID.Load())
	}
}

func TestMainVersionSubprocess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainVersion", "--", "--version")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_MAIN_VERSION=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version helper failed: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatal("version output was empty")
	}
}

func TestHelperProcessMainVersion(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_MAIN_VERSION") != "1" {
		return
	}
	os.Args = []string{"toolboxd", "--version"}
	main()
	os.Exit(0)
}

func TestForwardShutdownSignalsSubprocess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessForwardShutdownSignals")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_FORWARD_SHUTDOWN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("forwardShutdownSignals helper failed: %v: %s", err, out)
	}
}

func TestHelperProcessForwardShutdownSignals(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_FORWARD_SHUTDOWN") != "1" {
		return
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		os.Exit(2)
	}
	go srv.Serve(ln)
	go forwardShutdownSignals(logger, srv)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}

func TestMainServeSubprocess(t *testing.T) {
	recordingDir := filepath.Join(t.TempDir(), "recordings")
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainServe")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS_MAIN_SERVE=1",
		"SB_TOOLBOX_PORT=0",
		"SB_RECORDING_DIR="+recordingDir,
		"SB_RECORDING_RETENTION=1h",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal helper: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait helper: %v output=%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "toolboxd listening") {
		t.Fatalf("helper output missing startup log: %s", text)
	}
}

func TestHelperProcessMainServe(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_MAIN_SERVE") != "1" {
		return
	}
	os.Args = []string{"toolboxd"}
	main()
	os.Exit(0)
}

func TestMainServeWithUserCommandSubprocess(t *testing.T) {
	recordingDir := filepath.Join(t.TempDir(), "recordings")
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainServeWithUserCommand")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS_MAIN_SERVE_WITH_USER_COMMAND=1",
		"SB_TOOLBOX_PORT=0",
		"SB_RECORDING_DIR="+recordingDir,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal helper: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait helper: %v output=%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "user command started") {
		t.Fatalf("helper output missing user command startup log: %s", text)
	}
}

func TestHelperProcessMainServeWithUserCommand(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_MAIN_SERVE_WITH_USER_COMMAND") != "1" {
		return
	}
	os.Args = []string{"toolboxd", "/bin/sh", "-c", "sleep 30"}
	main()
	os.Exit(0)
}

func TestStartReaperSubprocess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessStartReaper")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_START_REAPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("startReaper helper failed: %v: %s", err, out)
	}
}

func TestHelperProcessStartReaper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_START_REAPER") != "1" {
		return
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	startReaper(logger)

	cmd1 := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd1.Start(); err != nil {
		os.Exit(2)
	}
	userCommandPID.Store(int64(cmd1.Process.Pid))

	cmd2 := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd2.Start(); err != nil {
		os.Exit(2)
	}

	time.Sleep(400 * time.Millisecond)
	os.Exit(0)
}

func TestEnvdProcessStartConflictAndPtyInputBranches(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	startPTYBody, _ := json.Marshal(map[string]any{
		"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "cat"}},
		"tag":     "pty-proc",
		"pty":     map[string]any{"size": map[string]any{"cols": 80, "rows": 24}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startPTYBody)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	go h.ServeHTTP(rr, req)
	waitForEnvdStateTag(t, srv, "pty-proc")

	t.Run("start_conflict", func(t *testing.T) {
		conflictBody, _ := json.Marshal(map[string]any{
			"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "sleep 1"}},
			"tag":     "pty-proc",
		})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(conflictBody)))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/connect+json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("conflict start status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("pty_process_rejects_stdin_payload", func(t *testing.T) {
		body := `{"process":{"tag":"pty-proc"},"input":{"stdin":"` + base64.StdEncoding.EncodeToString([]byte("abc")) + `"}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("stdin-to-pty status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("pty_resize_invalid", func(t *testing.T) {
		body := `{"process":{"tag":"pty-proc"},"pty":{"size":{"cols":0,"rows":0}}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid PTY resize status = %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid_signal_payload", func(t *testing.T) {
		body := `{"process":{"tag":"pty-proc"},"signal":"NOPE"}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid signal status = %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestEnvdConnectKeepaliveAndCloseStdinNoop(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	root := t.TempDir()
	startBody, _ := json.Marshal(map[string]any{
		"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "sleep 2"}, "cwd": root},
		"tag":     "keepalive-proc",
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startBody)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	go h.ServeHTTP(rr, req)
	waitForEnvdStateTag(t, srv, "keepalive-proc")

	connectReqBody, _ := json.Marshal(map[string]any{"process": map[string]any{"tag": "keepalive-proc"}})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Connect", bytes.NewReader(encodeConnectEnvelopeForTest(connectReqBody)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	req.Header.Set("Keepalive-Ping-Interval", "1")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("connect status = %d body=%s", rr.Code, rr.Body.String())
	}
	envelopes := decodeConnectEnvelopesForTest(t, rr.Body.Bytes())
	sawKeepalive := false
	for _, envelope := range envelopes {
		var event envdProcessStreamResponse
		if len(envelope.Payload) == 0 {
			continue
		}
		if err := json.Unmarshal(envelope.Payload, &event); err == nil && event.Event.Keepalive != nil {
			sawKeepalive = true
			break
		}
	}
	if !sawKeepalive {
		t.Fatalf("expected keepalive event in envelopes: %+v", envelopes)
	}
}

func TestEnvdCloseStdinNoopWhileRunning(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	startBody, _ := json.Marshal(map[string]any{
		"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "sleep 30"}},
		"tag":     "close-stdin-noop",
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startBody)))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("Content-Type", "application/connect+json")
	go h.ServeHTTP(rr, req)
	waitForEnvdStateTag(t, srv, "close-stdin-noop")

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", strings.NewReader(`{"process":{"tag":"close-stdin-noop"}}`))
	req.Header.Set("Authorization", "Bearer toolbox-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("close stdin noop status = %d", rr.Code)
	}
}

func TestExecStreamAdditionalBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	defer httpSrv.Close()

	t.Run("missing_command", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WriteJSON(map[string]any{"tty": false}); err != nil {
			t.Fatalf("write start: %v", err)
		}
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if msgType != websocket.TextMessage || !strings.Contains(string(payload), "command is required") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	})

	t.Run("bad_workdir_pipe", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WriteJSON(map[string]any{"command": "echo hi", "tty": false, "workdir": "/definitely/missing/workdir"}); err != nil {
			t.Fatalf("write start: %v", err)
		}
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.Contains(string(payload), "start:") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	})

	t.Run("bad_workdir_pty", func(t *testing.T) {
		wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WriteJSON(map[string]any{"command": "echo hi", "tty": true, "workdir": "/definitely/missing/workdir"}); err != nil {
			t.Fatalf("write start: %v", err)
		}
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.Contains(string(payload), "start pty:") {
			t.Fatalf("unexpected payload: %s", payload)
		}
	})
}
