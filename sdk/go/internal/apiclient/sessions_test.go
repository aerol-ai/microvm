package apiclient

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
)

func TestSessionsClientCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "create_session_round_trip",
			run: func(t *testing.T) {
				var receivedBody models.CreateSessionRequest
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						t.Fatalf("method: %q", r.Method)
					}
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					if got := r.Header.Get("Authorization"); got != "Bearer tok" {
						t.Fatalf("auth: %q", got)
					}
					if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
						t.Fatalf("decode: %v", err)
					}
					_ = json.NewEncoder(w).Encode(models.Session{
						ID:     "ses-aa",
						Name:   receivedBody.Name,
						Status: models.SessionStatusRunning,
						PTY:    receivedBody.PTY,
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				sess, err := client.CreateSession(ctx, "sb-1", CreateSessionRequest{
					Name:    "default",
					Command: "bash",
					PTY:     true,
				})
				if err != nil {
					t.Fatalf("CreateSession: %v", err)
				}
				if sess.ID != "ses-aa" || sess.Name != "default" || !sess.PTY {
					t.Fatalf("unexpected session: %+v", sess)
				}
				if receivedBody.Command != "bash" || !receivedBody.PTY {
					t.Fatalf("unexpected request body: %+v", receivedBody)
				}
			},
		},
		{
			name: "list_sessions_returns_array",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Fatalf("method: %q", r.Method)
					}
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(models.SessionList{
						Sessions: []models.Session{
							{ID: "ses-1", Name: "default", Status: models.SessionStatusRunning},
							{ID: "ses-2", Name: "build", Status: models.SessionStatusExited, ExitCode: 0},
						},
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				sessions, err := client.ListSessions(ctx, "sb-1")
				if err != nil {
					t.Fatalf("ListSessions: %v", err)
				}
				if len(sessions) != 2 {
					t.Fatalf("unexpected length: %d", len(sessions))
				}
				if sessions[0].ID != "ses-1" || sessions[1].Name != "build" {
					t.Fatalf("unexpected sessions: %+v", sessions)
				}
			},
		},
		{
			name: "get_session_round_trip",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(models.Session{ID: "ses-aa", Name: "default", Bytes: 42})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				sess, err := client.GetSession(ctx, "sb-1", "ses-aa")
				if err != nil {
					t.Fatalf("GetSession: %v", err)
				}
				if sess.Bytes != 42 {
					t.Fatalf("unexpected: %+v", sess)
				}
			},
		},
		{
			name: "delete_session_returns_no_content",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodDelete {
						t.Fatalf("method: %q", r.Method)
					}
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				if err := client.DeleteSession(ctx, "sb-1", "ses-aa"); err != nil {
					t.Fatalf("DeleteSession: %v", err)
				}
			},
		},
		{
			name: "signal_session_sends_body",
			run: func(t *testing.T) {
				var got models.SessionSignalRequest
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa/signal" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Fatalf("decode: %v", err)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				if err := client.SignalSession(ctx, "sb-1", "ses-aa", "TERM"); err != nil {
					t.Fatalf("SignalSession: %v", err)
				}
				if got.Signal != "TERM" {
					t.Fatalf("signal: %q", got.Signal)
				}
			},
		},
		{
			name: "resize_session_sends_dimensions",
			run: func(t *testing.T) {
				var got models.SessionResizeRequest
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa/resize" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Fatalf("decode: %v", err)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				if err := client.ResizeSession(ctx, "sb-1", "ses-aa", 132, 40); err != nil {
					t.Fatalf("ResizeSession: %v", err)
				}
				if got.Cols != 132 || got.Rows != 40 {
					t.Fatalf("dims: %+v", got)
				}
			},
		},
		{
			name: "session_log_returns_bytes",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa/log" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					_, _ = io.WriteString(w, "hello world")
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				body, err := client.SessionLog(ctx, "sb-1", "ses-aa")
				if err != nil {
					t.Fatalf("SessionLog: %v", err)
				}
				if string(body) != "hello world" {
					t.Fatalf("body: %q", string(body))
				}
			},
		},
		{
			name: "session_recording_returns_bytes",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-aa/recording" {
						t.Fatalf("path: %q", r.URL.Path)
					}
					_, _ = io.WriteString(w, "{\"version\":2}")
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				body, err := client.SessionRecording(ctx, "sb-1", "ses-aa")
				if err != nil {
					t.Fatalf("SessionRecording: %v", err)
				}
				if string(body) != "{\"version\":2}" {
					t.Fatalf("body: %q", string(body))
				}
			},
		},
		{
			name: "create_session_propagates_server_error",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "missing argv"})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
				_, err := client.CreateSession(ctx, "sb-1", CreateSessionRequest{})
				if err == nil || err.Error() != "missing argv" {
					t.Fatalf("expected missing argv error, got %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestAttachSession_ReceivesFramesAndExit(t *testing.T) {
	var upgrader websocket.Upgrader
	var stdout string
	var stderr string
	var onExitCode int
	var onExitSignal string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-1/sessions/ses-1/attach" {
			t.Fatalf("path: %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("auth: %q", got)
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
		if initial["type"] != "resize" || int(initial["cols"].(float64)) != 120 || int(initial["rows"].(float64)) != 40 {
			t.Fatalf("unexpected initial resize: %+v", initial)
		}

		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamPrefixStdout}, []byte("hello")...)); err != nil {
			t.Fatalf("write stdout: %v", err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamPrefixStderr}, []byte("warn")...)); err != nil {
			t.Fatalf("write stderr: %v", err)
		}
		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 7, "signal": "TERM"}); err != nil {
			t.Fatalf("write exit: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
	h, err := client.AttachSession(context.Background(), "sb-1", "ses-1", SessionAttachOptions{
		Cols: 120,
		Rows: 40,
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

	code, signal, err := h.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 7 || signal != "TERM" {
		t.Fatalf("wait result = (%d,%q), want (7,TERM)", code, signal)
	}
	if stdout != "hello" || stderr != "warn" {
		t.Fatalf("stdout/stderr = (%q,%q), want (hello,warn)", stdout, stderr)
	}
	if onExitCode != 7 || onExitSignal != "TERM" {
		t.Fatalf("onExit = (%d,%q), want (7,TERM)", onExitCode, onExitSignal)
	}
}

func TestAttachSession_ControlMessages(t *testing.T) {
	var upgrader websocket.Upgrader
	var mu sync.Mutex
	var binaries []string
	var controls []map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()

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
		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 0}); err != nil {
			t.Fatalf("WriteJSON(exit): %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
	h, err := client.AttachSession(context.Background(), "sb-1", "ses-1", SessionAttachOptions{})
	if err != nil {
		t.Fatalf("AttachSession: %v", err)
	}
	if err := h.Write([]byte("pwd\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := h.WriteString("ls\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := h.Resize(132, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := h.Signal("INT"); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	if code, signal, waitErr := h.Wait(); waitErr != nil || code != 0 || signal != "" {
		t.Fatalf("Wait = (%d,%q,%v), want (0,empty,nil)", code, signal, waitErr)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(binaries) != 2 || binaries[0] != "pwd\n" || binaries[1] != "ls\n" {
		t.Fatalf("binary messages = %+v", binaries)
	}
	if len(controls) != 2 {
		t.Fatalf("control messages len = %d, want 2", len(controls))
	}
	if controls[0]["type"] != "resize" || int(controls[0]["cols"].(float64)) != 132 || int(controls[0]["rows"].(float64)) != 40 {
		t.Fatalf("resize control mismatch: %+v", controls[0])
	}
	if controls[1]["type"] != "signal" || controls[1]["signal"] != "INT" {
		t.Fatalf("signal control mismatch: %+v", controls[1])
	}
}

func TestAttachSession_CloseSendsControl(t *testing.T) {
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

	client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
	h, err := client.AttachSession(context.Background(), "sb-1", "ses-1", SessionAttachOptions{})
	if err != nil {
		t.Fatalf("AttachSession: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, waitErr := h.Wait()
	if waitErr == nil || !strings.Contains(waitErr.Error(), "session stream closed") {
		t.Fatalf("Wait error = %v, want stream closed", waitErr)
	}
}

func TestAttachSession_RequiresIDs(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", ClientOptions{})
	if _, err := client.AttachSession(context.Background(), "", "ses", SessionAttachOptions{}); err == nil {
		t.Fatal("expected error for empty sandbox id")
	}
	if _, err := client.AttachSession(context.Background(), "sb", "", SessionAttachOptions{}); err == nil {
		t.Fatal("expected error for empty session id")
	}
}
