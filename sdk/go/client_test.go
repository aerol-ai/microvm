package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGoSDKCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new_client_trims_base_url",
			run: func(t *testing.T) {
				client := NewClient("http://localhost:8080/", "token")
				if client.baseURL != "http://localhost:8080" || client.token != "token" {
					t.Fatalf("unexpected client: %+v", client)
				}
			},
		},
		{
			name: "create_sends_json_and_wraps_response",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assertAuthHeader(t, r, "token")
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if body["image"] != "ubuntu:22.04" {
						t.Fatalf("unexpected request body: %+v", body)
					}
					writeJSON(t, w, http.StatusCreated, sampleSandboxModel("sb-create", models.SandboxStatusStarted))
				}))
				defer server.Close()

				client := NewClient(server.URL+"/", "token")
				client.httpClient = server.Client()
				sandbox, err := client.Create(ctx, CreateOptions{Image: "ubuntu:22.04"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if sandbox.ID != "sb-create" || sandbox.client != client {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
			},
		},
		{
			name: "list_returns_wrapped_handles",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/v1/sandboxes" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					writeJSON(t, w, http.StatusOK, []models.Sandbox{
						sampleSandboxModel("sb-a", models.SandboxStatusStarted),
						sampleSandboxModel("sb-b", models.SandboxStatusStopped),
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				items, err := client.List(ctx)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}
				if len(items) != 2 || items[0].client != client || items[1].Status != models.SandboxStatusStopped {
					t.Fatalf("unexpected items: %+v", items)
				}
			},
		},
		{
			name: "get_uses_sandbox_path",
			run: func(t *testing.T) {
				assertSimpleSandboxRequest(t, clientRequestCase{
					method: http.MethodGet,
					path:   "/v1/sandboxes/sb-get",
					run: func(client *Client) error {
						_, err := client.Get(ctx, "sb-get")
						return err
					},
				})
			},
		},
		{
			name: "start_uses_start_path",
			run: func(t *testing.T) {
				assertSimpleSandboxRequest(t, clientRequestCase{
					method: http.MethodPost,
					path:   "/v1/sandboxes/sb-start/start",
					run: func(client *Client) error {
						_, err := client.Start(ctx, "sb-start")
						return err
					},
				})
			},
		},
		{
			name: "stop_uses_stop_path",
			run: func(t *testing.T) {
				assertSimpleSandboxRequest(t, clientRequestCase{
					method: http.MethodPost,
					path:   "/v1/sandboxes/sb-stop/stop",
					run: func(client *Client) error {
						_, err := client.Stop(ctx, "sb-stop")
						return err
					},
				})
			},
		},
		{
			name: "destroy_uses_delete_and_no_content",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodDelete || r.URL.Path != "/v1/sandboxes/sb-destroy" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				if err := client.Destroy(ctx, "sb-destroy"); err != nil {
					t.Fatalf("Destroy() error = %v", err)
				}
			},
		},
		{
			name: "resize_sends_json_payload",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-resize/resize" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if body["cpu"] != float64(4) || body["memory_mb"] != float64(4096) {
						t.Fatalf("unexpected resize body: %+v", body)
					}
					updated := sampleSandboxModel("sb-resize", models.SandboxStatusStarted)
					updated.CPU = 4
					updated.MemoryMB = 4096
					writeJSON(t, w, http.StatusOK, updated)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				updated, err := client.Resize(ctx, "sb-resize", ResizeOptions{CPU: 4, MemoryMB: 4096})
				if err != nil {
					t.Fatalf("Resize() error = %v", err)
				}
				if updated.CPU != 4 || updated.MemoryMB != 4096 {
					t.Fatalf("unexpected updated sandbox: %+v", updated)
				}
			},
		},
		{
			name: "exec_sends_request_and_returns_result",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-exec/toolbox/process/execute" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if body["command"] != "echo hello" {
						t.Fatalf("unexpected exec body: %+v", body)
					}
					writeJSON(t, w, http.StatusOK, ExecResult{Stdout: "hello\n", ExitCode: 0, DurationMS: 5})
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				result, err := client.Exec(ctx, "sb-exec", ExecRequest{Command: "echo hello"})
				if err != nil {
					t.Fatalf("Exec() error = %v", err)
				}
				if result.Stdout != "hello\n" || result.ExitCode != 0 {
					t.Fatalf("unexpected exec result: %+v", result)
				}
			},
		},
		{
			name: "upload_file_sends_multipart_form",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assertAuthHeader(t, r, "token")
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-upload/toolbox/files/upload" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
						t.Fatalf("expected multipart content type, got %q", r.Header.Get("Content-Type"))
					}
					if err := r.ParseMultipartForm(1 << 20); err != nil {
						t.Fatalf("ParseMultipartForm() error = %v", err)
					}
					if got := r.FormValue("path"); got != "/workspace/file.txt" {
						t.Fatalf("unexpected path field: %q", got)
					}
					file, header, err := r.FormFile("file")
					if err != nil {
						t.Fatalf("FormFile() error = %v", err)
					}
					defer file.Close()
					data, err := io.ReadAll(file)
					if err != nil {
						t.Fatalf("ReadAll() error = %v", err)
					}
					if header.Filename != "file.txt" || string(data) != "hello" {
						t.Fatalf("unexpected multipart file: %s %q", header.Filename, string(data))
					}
					w.WriteHeader(http.StatusCreated)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				if err := client.UploadFile(ctx, "sb-upload", "/workspace/file.txt", []byte("hello")); err != nil {
					t.Fatalf("UploadFile() error = %v", err)
				}
			},
		},
		{
			name: "download_file_encodes_query_and_returns_bytes",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/v1/sandboxes/sb-download/toolbox/files/download" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if got := r.URL.Query().Get("path"); got != "/workspace/file name.txt" {
						t.Fatalf("unexpected query path: %q", got)
					}
					_, _ = w.Write([]byte("payload"))
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				data, err := client.DownloadFile(ctx, "sb-download", "/workspace/file name.txt")
				if err != nil {
					t.Fatalf("DownloadFile() error = %v", err)
				}
				if string(data) != "payload" {
					t.Fatalf("unexpected payload: %q", string(data))
				}
			},
		},
		{
			name: "expose_port_returns_public_url",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-port/ports/3000" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					writeJSON(t, w, http.StatusOK, map[string]string{"public_url": "https://sb-port-3000.example.com"})
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				publicURL, err := client.ExposePort(ctx, "sb-port", 3000)
				if err != nil {
					t.Fatalf("ExposePort() error = %v", err)
				}
				if publicURL != "https://sb-port-3000.example.com" {
					t.Fatalf("unexpected public URL: %q", publicURL)
				}
			},
		},
		{
			name: "unexpose_port_uses_delete",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodDelete || r.URL.Path != "/v1/sandboxes/sb-port/ports/3000" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				if err := client.UnexposePort(ctx, "sb-port", 3000); err != nil {
					t.Fatalf("UnexposePort() error = %v", err)
				}
			},
		},
		{
			name: "health_reads_status",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/health" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					writeJSON(t, w, http.StatusOK, HealthStatus{Status: "ok", Sandboxes: 2, Docker: "ok", Caddy: "ok", Version: "dev"})
				}))
				defer server.Close()

				client := NewClient(server.URL, "")
				client.httpClient = server.Client()
				status, err := client.Health(ctx)
				if err != nil {
					t.Fatalf("Health() error = %v", err)
				}
				if status.Status != "ok" || status.Sandboxes != 2 {
					t.Fatalf("unexpected health: %+v", status)
				}
			},
		},
		{
			name: "sandbox_refresh_updates_fields",
			run: func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					response := sampleSandboxModel("sb-refresh", models.SandboxStatusStarted)
					if calls == 1 {
						response.PublicURL = "https://old.example.com"
					} else {
						response.PublicURL = "https://new.example.com"
					}
					writeJSON(t, w, http.StatusOK, response)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				sandbox, err := client.Get(ctx, "sb-refresh")
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if err := sandbox.Refresh(ctx); err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}
				if sandbox.PublicURL != "https://new.example.com" {
					t.Fatalf("unexpected refreshed sandbox: %+v", sandbox)
				}
			},
		},
		{
			name: "sandbox_exec_delegates_to_client",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					writeJSON(t, w, http.StatusOK, ExecResult{Stdout: "42", ExitCode: 0})
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				sandbox := &Sandbox{Sandbox: sampleSandboxModel("sb-exec-delegate", models.SandboxStatusStarted), client: client}
				result, err := sandbox.Exec(ctx, "echo 42")
				if err != nil {
					t.Fatalf("Sandbox.Exec() error = %v", err)
				}
				if result.Stdout != "42" {
					t.Fatalf("unexpected exec result: %+v", result)
				}
			},
		},
		{
			name: "sandbox_start_updates_fields",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := sampleSandboxModel("sb-start-handle", models.SandboxStatusStarted)
					response.PublicURL = "https://started.example.com"
					writeJSON(t, w, http.StatusOK, response)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				sandbox := &Sandbox{Sandbox: sampleSandboxModel("sb-start-handle", models.SandboxStatusStopped), client: client}
				if err := sandbox.Start(ctx); err != nil {
					t.Fatalf("Sandbox.Start() error = %v", err)
				}
				if sandbox.Status != models.SandboxStatusStarted || sandbox.PublicURL != "https://started.example.com" {
					t.Fatalf("unexpected sandbox after start: %+v", sandbox)
				}
			},
		},
		{
			name: "sandbox_stop_updates_fields",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := sampleSandboxModel("sb-stop-handle", models.SandboxStatusStopped)
					writeJSON(t, w, http.StatusOK, response)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				sandbox := &Sandbox{Sandbox: sampleSandboxModel("sb-stop-handle", models.SandboxStatusStarted), client: client}
				if err := sandbox.Stop(ctx); err != nil {
					t.Fatalf("Sandbox.Stop() error = %v", err)
				}
				if sandbox.Status != models.SandboxStatusStopped {
					t.Fatalf("unexpected sandbox after stop: %+v", sandbox)
				}
			},
		},
		{
			name: "sandbox_resize_updates_fields",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := sampleSandboxModel("sb-resize-handle", models.SandboxStatusStarted)
					response.CPU = 8
					response.MemoryMB = 8192
					writeJSON(t, w, http.StatusOK, response)
				}))
				defer server.Close()

				client := NewClient(server.URL, "token")
				client.httpClient = server.Client()
				sandbox := &Sandbox{Sandbox: sampleSandboxModel("sb-resize-handle", models.SandboxStatusStarted), client: client}
				if err := sandbox.Resize(ctx, ResizeOptions{CPU: 8, MemoryMB: 8192}); err != nil {
					t.Fatalf("Sandbox.Resize() error = %v", err)
				}
				if sandbox.CPU != 8 || sandbox.MemoryMB != 8192 {
					t.Fatalf("unexpected sandbox after resize: %+v", sandbox)
				}
			},
		},
		{
			name: "decode_error_reads_json_message",
			run: func(t *testing.T) {
				response := &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"error":"bad request"}`)),
				}
				if err := decodeError(response); err == nil || err.Error() != "bad request" {
					t.Fatalf("unexpected decodeError() result: %v", err)
				}
			},
		},
		{
			name: "decode_error_uses_status_fallback",
			run: func(t *testing.T) {
				response := &http.Response{
					StatusCode: http.StatusBadGateway,
					Body:       io.NopCloser(strings.NewReader(`not-json`)),
				}
				if err := decodeError(response); err == nil || err.Error() != "request failed with status 502" {
					t.Fatalf("unexpected decodeError() result: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

type clientRequestCase struct {
	method string
	path   string
	run    func(*Client) error
}

func assertSimpleSandboxRequest(t *testing.T, tc clientRequestCase) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != tc.method || r.URL.Path != tc.path {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, sampleSandboxModel("test", models.SandboxStatusStarted))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	client.httpClient = server.Client()
	if err := tc.run(client); err != nil {
		t.Fatalf("client request error = %v", err)
	}
}

func assertAuthHeader(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+token {
		t.Fatalf("unexpected Authorization header: %q", got)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}

func sampleSandboxModel(id string, status models.SandboxStatus) models.Sandbox {
	now := time.Now().UTC().Round(0)
	return models.Sandbox{
		ID:              id,
		Image:           "ubuntu:22.04",
		Status:          status,
		PublicURL:       fmt.Sprintf("https://%s.example.com", id),
		ContainerID:     "container-" + id,
		ContainerIP:     "10.0.0.10",
		CPU:             2,
		MemoryMB:        2048,
		DiskGB:          20,
		OSUser:          "root",
		Env:             map[string]string{"KEY": "VALUE"},
		NetworkBlockAll: false,
		ToolboxEnabled:  true,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}
}
