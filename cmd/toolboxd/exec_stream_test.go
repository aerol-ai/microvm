package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestInterpretWaitResultTreatsWrappedECHILDAsSuccess(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "direct syscall error",
			err:  &os.SyscallError{Syscall: "waitid", Err: syscall.ECHILD},
		},
		{
			name: "wrapped syscall error",
			err:  fmt.Errorf("wrapped: %w", &os.SyscallError{Syscall: "waitid", Err: syscall.ECHILD}),
		},
		{
			name: "wrapped sentinel",
			err:  fmt.Errorf("wrapped: %w", syscall.ECHILD),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, signal := interpretWaitResult(tc.err)
			if code != 0 || signal != "" {
				t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (0, \"\")", tc.err, code, signal)
			}
		})
	}
}

func TestInterpretWaitResultPreservesExitCode(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 17")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit error")
	}

	code, signal := interpretWaitResult(err)
	if code != 17 || signal != "" {
		t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (17, \"\")", err, code, signal)
	}
}

func TestInterpretWaitResultPreservesSignal(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected signal exit error")
	}

	code, signal := interpretWaitResult(err)
	if code != -1 || signal != syscall.SIGTERM.String() {
		t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (-1, %q)", err, code, signal, syscall.SIGTERM.String())
	}
}

func TestExecStream_WebsocketRunWithPipes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if err := conn.WriteJSON(map[string]any{"command": "cat", "tty": false}); err != nil {
		t.Fatalf("write start message: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello-stream")); err != nil {
		t.Fatalf("write stdin frame: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "close"}); err != nil {
		t.Fatalf("write close control: %v", err)
	}

	seenStdout := false
	seenExit := false
	for i := 0; i < 8 && !(seenStdout && seenExit); i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read message: %v", err)
		}
		switch msgType {
		case websocket.BinaryMessage:
			if len(payload) > 1 && payload[0] == streamFramePrefixStdout && strings.Contains(string(payload[1:]), "hello-stream") {
				seenStdout = true
			}
		case websocket.TextMessage:
			var ctrl execStreamControlOut
			if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" && ctrl.Code == 0 {
				seenExit = true
			}
		}
	}
	if !seenStdout {
		t.Fatalf("did not observe stdout frame")
	}
	if !seenExit {
		t.Fatalf("did not observe clean exit control message")
	}
}

func TestExecStream_InvalidStartMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	if err := conn.WriteMessage(websocket.TextMessage, []byte("{bad")); err != nil {
		t.Fatalf("write invalid start frame: %v", err)
	}
	msgType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read control message: %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Fatalf("message type = %d, want text", msgType)
	}
	var ctrl execStreamControlOut
	if err := json.Unmarshal(payload, &ctrl); err != nil {
		t.Fatalf("decode control payload: %v", err)
	}
	if ctrl.Type != "error" {
		t.Fatalf("control type = %q, want error", ctrl.Type)
	}
}

func TestExecStream_WebsocketRunWithPTY(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))

	if err := conn.WriteJSON(map[string]any{"command": "cat", "tty": true, "cols": 80, "rows": 24}); err != nil {
		t.Fatalf("write PTY start message: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("pty-input\n")); err != nil {
		t.Fatalf("write PTY stdin frame: %v", err)
	}
	// Exercise PTY control handling: resize and signal branches.
	_ = conn.WriteJSON(map[string]any{"type": "resize", "cols": 100, "rows": 40})
	_ = conn.WriteJSON(map[string]any{"type": "signal", "signal": "TERM"})

	seenStdout := false
	seenExit := false
	for i := 0; i < 12 && !seenExit; i++ {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		switch msgType {
		case websocket.BinaryMessage:
			if len(payload) > 1 && payload[0] == streamFramePrefixStdout && strings.Contains(string(payload[1:]), "pty-input") {
				seenStdout = true
			}
		case websocket.TextMessage:
			var ctrl execStreamControlOut
			if err := json.Unmarshal(payload, &ctrl); err == nil && ctrl.Type == "exit" {
				seenExit = true
			}
		}
	}
	if !seenStdout {
		t.Fatalf("did not observe PTY stdout frame")
	}
	if !seenExit {
		t.Fatalf("did not observe PTY exit control message")
	}
}

func TestExecStreamSignalAndEnvHelpers(t *testing.T) {
	if sig := mapStreamSignal("INT"); sig != syscall.SIGINT {
		t.Fatalf("mapStreamSignal(INT) = %v", sig)
	}
	if sig := mapStreamSignal("SIGTERM"); sig != syscall.SIGTERM {
		t.Fatalf("mapStreamSignal(SIGTERM) = %v", sig)
	}
	if sig := mapStreamSignal("UNKNOWN"); sig != nil {
		t.Fatalf("mapStreamSignal(UNKNOWN) = %v, want nil", sig)
	}

	env := mergeEnvForExec(map[string]string{"TEST_EXEC_STREAM": "1"})
	found := false
	for _, item := range env {
		if item == "TEST_EXEC_STREAM=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("mergeEnvForExec did not include TEST_EXEC_STREAM")
	}

	// sendSignalToCmd should be a no-op for nil process references.
	sendSignalToCmd(nil, "TERM")
	sendSignalToCmd(&exec.Cmd{}, "TERM")
}
