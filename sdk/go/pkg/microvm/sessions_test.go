package microvm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestSessionClientAndSandboxWrappers(t *testing.T) {
	ctx := context.Background()
	var createBody models.CreateSessionRequest
	var signalBody models.SessionSignalRequest
	var resizeBody models.SessionResizeRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb-1/sessions":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(models.Session{ID: "ses-1", Name: createBody.Name, PTY: createBody.PTY, Status: models.SessionStatusRunning})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb-1/sessions":
			_ = json.NewEncoder(w).Encode(models.SessionList{Sessions: []models.Session{{ID: "ses-1", Name: "default"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1":
			_ = json.NewEncoder(w).Encode(models.Session{ID: "ses-1", Bytes: 7})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1/signal":
			if err := json.NewDecoder(r.Body).Decode(&signalBody); err != nil {
				t.Fatalf("decode signal body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1/resize":
			if err := json.NewDecoder(r.Body).Decode(&resizeBody); err != nil {
				t.Fatalf("decode resize body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1/log":
			_, _ = io.WriteString(w, "session-log")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb-1/sessions/ses-1/recording":
			_, _ = io.WriteString(w, "{\"version\":2}")
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-1"}, client: client}

	created, err := client.CreateSession(ctx, "sb-1", sdktypes.CreateSessionOptions{Name: "default", Command: "bash", PTY: true})
	if err != nil {
		t.Fatalf("client.CreateSession: %v", err)
	}
	if created.ID != "ses-1" || !created.PTY || createBody.Command != "bash" {
		t.Fatalf("create mismatch: created=%+v body=%+v", created, createBody)
	}
	if _, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{Name: "default", Command: "bash"}); err != nil {
		t.Fatalf("sandbox.CreateSession: %v", err)
	}

	if rows, err := client.ListSessions(ctx, "sb-1"); err != nil || len(rows) != 1 || rows[0].ID != "ses-1" {
		t.Fatalf("client.ListSessions = (%+v,%v)", rows, err)
	}
	if rows, err := sb.ListSessions(ctx); err != nil || len(rows) != 1 {
		t.Fatalf("sandbox.ListSessions = (%+v,%v)", rows, err)
	}

	if got, err := client.GetSession(ctx, "sb-1", "ses-1"); err != nil || got.Bytes != 7 {
		t.Fatalf("client.GetSession = (%+v,%v)", got, err)
	}
	if got, err := sb.GetSession(ctx, "ses-1"); err != nil || got.Bytes != 7 {
		t.Fatalf("sandbox.GetSession = (%+v,%v)", got, err)
	}

	if err := client.SignalSession(ctx, "sb-1", "ses-1", "TERM"); err != nil {
		t.Fatalf("client.SignalSession: %v", err)
	}
	if err := sb.SignalSession(ctx, "ses-1", "KILL"); err != nil {
		t.Fatalf("sandbox.SignalSession: %v", err)
	}
	if signalBody.Signal != "KILL" {
		t.Fatalf("last signal body = %+v, want KILL", signalBody)
	}

	if err := client.ResizeSession(ctx, "sb-1", "ses-1", 132, 40); err != nil {
		t.Fatalf("client.ResizeSession: %v", err)
	}
	if err := sb.ResizeSession(ctx, "ses-1", 100, 30); err != nil {
		t.Fatalf("sandbox.ResizeSession: %v", err)
	}
	if resizeBody.Cols != 100 || resizeBody.Rows != 30 {
		t.Fatalf("last resize body = %+v, want 100x30", resizeBody)
	}

	if logBytes, err := client.SessionLog(ctx, "sb-1", "ses-1"); err != nil || string(logBytes) != "session-log" {
		t.Fatalf("client.SessionLog = (%q,%v)", string(logBytes), err)
	}
	if logBytes, err := sb.SessionLog(ctx, "ses-1"); err != nil || string(logBytes) != "session-log" {
		t.Fatalf("sandbox.SessionLog = (%q,%v)", string(logBytes), err)
	}

	if cast, err := client.SessionRecording(ctx, "sb-1", "ses-1"); err != nil || string(cast) != "{\"version\":2}" {
		t.Fatalf("client.SessionRecording = (%q,%v)", string(cast), err)
	}
	if cast, err := sb.SessionRecording(ctx, "ses-1"); err != nil || string(cast) != "{\"version\":2}" {
		t.Fatalf("sandbox.SessionRecording = (%q,%v)", string(cast), err)
	}

	if err := client.DeleteSession(ctx, "sb-1", "ses-1"); err != nil {
		t.Fatalf("client.DeleteSession: %v", err)
	}
	if err := sb.DeleteSession(ctx, "ses-1"); err != nil {
		t.Fatalf("sandbox.DeleteSession: %v", err)
	}
}

func TestSessionAttachWrapperAndHandleMethods(t *testing.T) {
	var upgrader websocket.Upgrader
	var mu sync.Mutex
	var binaries []string
	var controls []map[string]any
	var stdout string
	var stderr string
	var onExitCode int
	var onExitSignal string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-1/attach" {
			t.Fatalf("path: %q", r.URL.Path)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()

		var initial map[string]any
		if err := conn.ReadJSON(&initial); err != nil {
			t.Fatalf("read initial resize: %v", err)
		}
		if initial["type"] != "resize" || int(initial["cols"].(float64)) != 80 || int(initial["rows"].(float64)) != 24 {
			t.Fatalf("unexpected initial resize: %+v", initial)
		}

		for i := 0; i < 4; i++ {
			mt, payload, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("ReadMessage(%d): %v", i, err)
			}
			mu.Lock()
			if mt == websocket.BinaryMessage {
				binaries = append(binaries, string(payload))
			} else {
				var item map[string]any
				if err := json.Unmarshal(payload, &item); err != nil {
					mu.Unlock()
					t.Fatalf("unmarshal control: %v", err)
				}
				controls = append(controls, item)
			}
			mu.Unlock()
		}

		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("out")...)); err != nil {
			t.Fatalf("write stdout frame: %v", err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{2}, []byte("err")...)); err != nil {
			t.Fatalf("write stderr frame: %v", err)
		}
		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 0, "signal": ""}); err != nil {
			t.Fatalf("write exit: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-1"}, client: client}

	h, err := sb.AttachSession(context.Background(), "ses-1", SessionAttachOptions{
		Cols: 80,
		Rows: 24,
		OnStdout: func(chunk []byte) {
			stdout += string(chunk)
		},
		OnStderr: func(chunk []byte) {
			stderr += string(chunk)
		},
		OnExit: func(code int, signal string) {
			onExitCode = code
			onExitSignal = signal
		},
	})
	if err != nil {
		t.Fatalf("AttachSession: %v", err)
	}
	if err := h.Write([]byte("pwd\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := h.WriteString("ls\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := h.Resize(120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := h.Signal("INT"); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	code, signal, err := h.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 0 || signal != "" {
		t.Fatalf("wait result = (%d,%q), want (0,empty)", code, signal)
	}
	if stdout != "out" || stderr != "err" {
		t.Fatalf("stdout/stderr = (%q,%q), want (out,err)", stdout, stderr)
	}
	if onExitCode != 0 || onExitSignal != "" {
		t.Fatalf("onExit = (%d,%q), want (0,empty)", onExitCode, onExitSignal)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(binaries) != 2 || binaries[0] != "pwd\n" || binaries[1] != "ls\n" {
		t.Fatalf("binary messages = %+v", binaries)
	}
	if len(controls) != 2 {
		t.Fatalf("control messages len = %d, want 2", len(controls))
	}
	if controls[0]["type"] != "resize" || int(controls[0]["cols"].(float64)) != 120 || int(controls[0]["rows"].(float64)) != 40 {
		t.Fatalf("resize control mismatch: %+v", controls[0])
	}
	if controls[1]["type"] != "signal" || controls[1]["signal"] != "INT" {
		t.Fatalf("signal control mismatch: %+v", controls[1])
	}
}

func TestSessionAttachHandleClose(t *testing.T) {
	var upgrader websocket.Upgrader

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()

		mt, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if mt != websocket.TextMessage {
			t.Fatalf("message type = %d, want text", mt)
		}
		var control map[string]any
		if err := json.Unmarshal(payload, &control); err != nil {
			t.Fatalf("unmarshal control: %v", err)
		}
		if control["type"] != "close" {
			t.Fatalf("control = %+v, want close", control)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	h, err := client.AttachSession(context.Background(), "sb-1", "ses-1", SessionAttachOptions{})
	if err != nil {
		t.Fatalf("AttachSession: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, waitErr := h.Wait()
	if waitErr == nil || !strings.Contains(waitErr.Error(), "session stream closed") {
		t.Fatalf("Wait err = %v, want session stream closed", waitErr)
	}
}
