package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestExecStreamPipeControlMessages(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleExecStream(w, r)
	}))
	t.Cleanup(httpSrv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteJSON(map[string]any{"command": "cat", "tty": false}); err != nil {
		t.Fatalf("start: %v", err)
	}
	_ = conn.WriteMessage(websocket.TextMessage, []byte("{bad"))
	_ = conn.WriteJSON(map[string]any{"type": "signal", "signal": "TERM"})
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("x"))
	_ = conn.WriteJSON(map[string]any{"type": "close"})
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
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
