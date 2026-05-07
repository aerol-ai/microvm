package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTransportClientCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "create_sends_bearer_auth",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer pat-token" {
						t.Fatalf("unexpected authorization: %q", r.Header.Get("Authorization"))
					}
					_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-create", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				sandbox, err := client.Create(ctx, CreateOptions{Image: "ubuntu:22.04"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if sandbox.ID != "sb-create" {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
			},
		},
		{
			name: "upload_file_sends_multipart",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
						t.Fatalf("unexpected content type: %q", r.Header.Get("Content-Type"))
					}
					if err := r.ParseMultipartForm(1 << 20); err != nil {
						t.Fatalf("ParseMultipartForm() error = %v", err)
					}
					if got := r.FormValue("path"); got != "/workspace/file.txt" {
						t.Fatalf("unexpected path: %q", got)
					}
					file, _, err := r.FormFile("file")
					if err != nil {
						t.Fatalf("FormFile() error = %v", err)
					}
					defer file.Close()
					payload, err := io.ReadAll(file)
					if err != nil {
						t.Fatalf("ReadAll() error = %v", err)
					}
					if string(payload) != "hello" {
						t.Fatalf("unexpected payload: %q", string(payload))
					}
					w.WriteHeader(http.StatusCreated)
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				if err := client.UploadFile(ctx, "sb-upload", "/workspace/file.txt", []byte("hello")); err != nil {
					t.Fatalf("UploadFile() error = %v", err)
				}
			},
		},
		{
			name: "health_maps_response",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(HealthStatus{Status: "ok", Sandboxes: 2, Docker: "ok", Caddy: "ok", Version: "dev"})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{HTTPClient: server.Client()})
				health, err := client.Health(ctx)
				if err != nil {
					t.Fatalf("Health() error = %v", err)
				}
				if health.Status != "ok" || health.Sandboxes != 2 {
					t.Fatalf("unexpected health: %+v", health)
				}
			},
		},
		{
			name: "json_error_payload_is_decoded",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "bad request"})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{HTTPClient: server.Client()})
				_, err := client.Create(ctx, CreateOptions{Image: "ubuntu:22.04"})
				if err == nil || err.Error() != "bad request" {
					t.Fatalf("unexpected error: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
