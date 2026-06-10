package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
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

// Helper to create a Host with a real sessions.Manager
func newHostWithRealSessions(t *testing.T) (*Host, *sessions.Manager) {
	t.Helper()
	recDir := t.TempDir()
	mgr, err := sessions.New(slog.Default(), sessions.Config{
		SandboxID:    "sb-test-ws",
		RecordingDir: recDir,
		BufferBytes:  64 * 1024,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	h := New(Config{
		SandboxID: "sb-test-ws",
		WorkDir:   t.TempDir(),
		Sessions:  mgr,
		StateKV:   nil,
	})
	return h, mgr
}

func TestSessionsWebSocketAttachAndControl(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// 1. Create a session that runs a command that waits (e.g. sleep) so we can attach to it.
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "sleep 10",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer func() { _ = mgr.Delete(sess.ID()) }()

	// 2. Connect to the WebSocket attach endpoint: /sessions/{id}/attach
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
	dialer := websocket.Dialer{
		Subprotocols: []string{"sandbox.bearer"},
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial attach ws failed: %v", err)
	}
	defer conn.Close()

	// 3. Send a binary message to write to the session's stdin
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("echo hello\n")); err != nil {
		t.Fatalf("write binary msg: %v", err)
	}

	// 4. Send a resize control message (text message with JSON)
	resizeMsg, _ := json.Marshal(sessionAttachControlIn{
		Type: "resize",
		Cols: 100,
		Rows: 30,
	})
	if err := conn.WriteMessage(websocket.TextMessage, resizeMsg); err != nil {
		t.Fatalf("write resize msg: %v", err)
	}

	// 5. Send a signal control message (text message with JSON)
	sigMsg, _ := json.Marshal(sessionAttachControlIn{
		Type:   "signal",
		Signal: "INT",
	})
	if err := conn.WriteMessage(websocket.TextMessage, sigMsg); err != nil {
		t.Fatalf("write signal msg: %v", err)
	}

	// 6. Send an invalid JSON text message to test JSON unmarshal failure
	if err := conn.WriteMessage(websocket.TextMessage, []byte("invalid-json")); err != nil {
		t.Fatalf("write invalid json: %v", err)
	}

	// 7. Send a close control message
	closeMsg, _ := json.Marshal(sessionAttachControlIn{
		Type: "close",
	})
	if err := conn.WriteMessage(websocket.TextMessage, closeMsg); err != nil {
		t.Fatalf("write close msg: %v", err)
	}

	// Give a bit of time for message loops to process
	time.Sleep(100 * time.Millisecond)
}

func TestSessionsWebSocketExitAndDrain(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	for i := 0; i < 15; i++ {
		sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
			Command: "echo hello",
			PTY:     true,
			Cols:    80,
			Rows:    24,
		})
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}

		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/sessions/" + sess.ID() + "/attach"
		dialer := websocket.Dialer{
			Subprotocols: []string{"sandbox.bearer"},
		}
		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial attach ws failed: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			msgType, p, err := conn.ReadMessage()
			if err != nil {
				break
			}
			if msgType == websocket.TextMessage {
				var out sessionAttachControlOut
				if err := json.Unmarshal(p, &out); err == nil && out.Type == "exit" {
					break
				}
			}
		}
		conn.Close()
		_ = mgr.Delete(sess.ID())
	}
}

func TestSessionsRecordingSuccess(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo hello",
		PTY:     true,
		Cols:    80,
		Rows:    24,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/recording", nil)
	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("recording download failed status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/x-asciicast+json-seq" {
		t.Fatalf("unexpected Content-Type: %s", rec.Header().Get("Content-Type"))
	}
}

func TestSessionsRecordingOpenError(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo hello",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Delete(sess.ID()) })

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for session")
	}

	path := sess.RecordingPath()
	if path != "" {
		_ = os.Remove(path)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/recording", nil)
	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d", rec.Code)
	}
}

func TestSessionsDisabled(t *testing.T) {
	h := New(Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		Sessions:  nil,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{}`))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 list when sessions nil, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/123", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/sessions/123", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/123/signal", strings.NewReader(`{}`))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/123/resize", strings.NewReader(`{}`))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/123/log", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/123/recording", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/123/attach", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDrainSessionFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Create a frames channel with some data
		ch := make(chan sessions.Frame, 3)
		ch <- sessions.Frame{Stream: sessions.StreamStdout, Data: []byte("stdout-data")}
		ch <- sessions.Frame{Stream: sessions.StreamStderr, Data: []byte("stderr-data")}
		close(ch)

		drainSessionFrames(conn, ch)
	}))
	defer srv.Close()

	// Dial the server
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read the two messages
	_, msg1, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if !bytes.Contains(msg1, []byte("stdout-data")) {
		t.Fatalf("unexpected msg1: %q", msg1)
	}

	_, msg2, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if !bytes.Contains(msg2, []byte("stderr-data")) {
		t.Fatalf("unexpected msg2: %q", msg2)
	}
}

func TestSessionsEdgeCases(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	// 1. Session ID empty -> 400
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions//attach", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	// 2. Session Create fails -> 400
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"argv":["/nonexistent-bin-12345"]}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	// Create a valid PTY session for signal/resize tests
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: "sleep 10",
		PTY:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = mgr.Delete(sess.ID()) }()

	// 3. Signal REST API success
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/signal", strings.NewReader(`{"signal":"INT"}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signal success got %d", rec.Code)
	}

	// Signal REST API error (invalid signal)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/signal", strings.NewReader(`{"signal":"SIGINVALID"}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("signal error got %d", rec.Code)
	}

	// 4. Resize REST API success
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/resize", strings.NewReader(`{"cols":120,"rows":40}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resize success got %d", rec.Code)
	}

	// Resize REST API error (invalid cols/rows)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID()+"/resize", strings.NewReader(`{"cols":-1,"rows":-1}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("resize error got %d", rec.Code)
	}

	// 5. Session recording empty when recorder fails to initialize (blocked by file)
	recDir := t.TempDir()
	mgrNoRec, err := sessions.New(slog.Default(), sessions.Config{
		SandboxID:    "sb-no-rec",
		RecordingDir: recDir,
		BufferBytes:  64 * 1024,
	})
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	defer mgrNoRec.Close()

	// Block the recording path by replacing the sandbox ID directory with a regular file
	sandboxDir := filepath.Join(recDir, "sb-no-rec")
	_ = os.RemoveAll(sandboxDir)
	if err := os.WriteFile(sandboxDir, []byte("blocker"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	sessNoRec, err := mgrNoRec.Create(context.Background(), models.CreateSessionRequest{
		Command: "echo hello",
	})
	if err != nil {
		t.Fatalf("create no-rec: %v", err)
	}

	hNoRec := New(Config{
		SandboxID: "sb-no-rec",
		WorkDir:   t.TempDir(),
		Sessions:  mgrNoRec,
	})

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/"+sessNoRec.ID()+"/recording", nil)
	hNoRec.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for no-rec recording, got %d", rec.Code)
	}

	// 6. Session attach fails to find session -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/nonexistent/attach", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 7. Session attach fails WebSocket upgrade (regular GET request) -> returns error/warning but no upgrade
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/attach", nil)
	h.Handler().ServeHTTP(rec, req)
	// Upgrader returns 400 Bad Request if not a WebSocket request
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on non-websocket attach, got %d", rec.Code)
	}
}
