package toolhost

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// testDialWS opens a WebSocket connection to the given httptest server path.
func testDialWS(t *testing.T, srv *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + path
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial ws %s: %v", path, err)
	}
	return conn
}

// ─── writeStreamControl ──────────────────────────────────────────────────────

func TestWriteStreamControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		writeStreamControl(conn, execStreamControlOut{Type: "exit", Code: 0})
	}))
	defer srv.Close()

	conn := testDialWS(t, srv, "/")
	defer conn.Close()
	var msg execStreamControlOut
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if msg.Type != "exit" {
		t.Fatalf("type = %q", msg.Type)
	}
}

// ─── mergeExecEnv (also tested in whitebox_test.go, duplicate for stream file) ──

func TestMergeExecEnvEmpty(t *testing.T) {
	env := mergeExecEnv(map[string]string{})
	// Should still include at least one var from os.Environ()
	if len(env) == 0 {
		t.Fatal("expected non-empty env")
	}
}

// ─── handleExecStream via WebSocket ──────────────────────────────────────────

func TestHandleExecStreamNoCommand(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send empty command
	if err := conn.WriteJSON(map[string]string{"command": ""}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Should receive an error control message
	var msg execStreamControlOut
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if msg.Type != "error" {
		t.Fatalf("expected error type, got %q", msg.Type)
	}
}

func TestHandleExecStreamPipes(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a command that quickly exits
	if err := conn.WriteJSON(map[string]interface{}{
		"command": "echo hello-exec-stream",
		"tty":     false,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read until exit message
	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if jsonErr := parseJSON(data, &ctrl); jsonErr == nil && ctrl.Type == "exit" {
				return
			}
		}
	}
}

func TestHandleExecStreamPipesWithStdin(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Run a command that reads from stdin
	if err := conn.WriteJSON(map[string]interface{}{
		"command": "cat",
		"tty":     false,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Send some stdin data (binary message)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello\n")); err != nil {
		t.Logf("write stdin: %v (ok if cat already exited)", err)
	}

	// Send signal to close
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	_ = conn.WriteJSON(map[string]string{"type": "signal", "signal": "TERM"})

	// Wait for exit
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if jsonErr := parseJSON(data, &ctrl); jsonErr == nil && ctrl.Type == "exit" {
				return
			}
		}
	}
}

func TestHandleExecStreamInvalidStartMessage(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send garbage (not valid JSON for execStreamStartMsg)
	if err := conn.WriteMessage(websocket.TextMessage, []byte("not-valid-json")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Should get an error response or connection close
	conn.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	_, _, _ = conn.ReadMessage()                          // may be error control or close
}

func TestHandleExecStreamPTY(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a PTY command
	if err := conn.WriteJSON(map[string]interface{}{
		"command": "echo pty-hello",
		"tty":     true,
		"cols":    80,
		"rows":    24,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if jsonErr := parseJSON(data, &ctrl); jsonErr == nil && ctrl.Type == "exit" {
				return
			}
		}
	}
}

func TestHandleExecStreamPTYResizeAndSignal(t *testing.T) {
	h := &Host{workDir: t.TempDir()}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/process/exec/stream", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Start a long-running PTY process
	if err := conn.WriteJSON(map[string]interface{}{
		"command": "sleep 30",
		"tty":     true,
		"cols":    80,
		"rows":    24,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Send resize control message
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	_ = conn.WriteJSON(execStreamControlIn{Type: "resize", Cols: 120, Rows: 40})

	// Write binary data to stdin
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("ls\n"))

	// Send signal to kill it
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	_ = conn.WriteJSON(execStreamControlIn{Type: "signal", Signal: "TERM"})

	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType == websocket.TextMessage {
			var ctrl execStreamControlOut
			if jsonErr := parseJSON(data, &ctrl); jsonErr == nil && ctrl.Type == "exit" {
				return
			}
		}
	}
}

// parseJSON is a helper to avoid importing encoding/json in this file separately
// (it's used by websocket control messages).
func parseJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
