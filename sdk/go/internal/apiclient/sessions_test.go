package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
