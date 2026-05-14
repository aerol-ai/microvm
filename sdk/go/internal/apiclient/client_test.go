package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
					_ = json.NewEncoder(w).Encode(models.CreateSandboxResponse{
						Sandbox:       models.Sandbox{ID: "sb-create", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted},
						SSHPrivateKey: "PRIVATE",
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				sandbox, sshKey, err := client.Create(ctx, CreateOptions{Image: "ubuntu:22.04"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if sandbox.ID != "sb-create" {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
				if sshKey != "PRIVATE" {
					t.Fatalf("unexpected ssh key: %q", sshKey)
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
			name: "create_snapshot_sends_name_and_maps_response",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-snap/snapshot" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if r.Header.Get("Authorization") != "Bearer pat-token" {
						t.Fatalf("unexpected authorization: %q", r.Header.Get("Authorization"))
					}
					var payload models.CreateSandboxSnapshotRequest
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if payload.Name != "snapshots/demo:v1" {
						t.Fatalf("payload.Name = %q, want snapshots/demo:v1", payload.Name)
					}
					_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
						Name:            "snapshots/demo:v1",
						Image:           "snapshots/demo:v1",
						ImageID:         "sha256:snap-1",
						SourceSandboxID: "sb-snap",
						CreatedAt:       time.Now().UTC(),
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				snapshot, err := client.CreateSnapshot(ctx, "sb-snap", "snapshots/demo:v1")
				if err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if snapshot.Name != "snapshots/demo:v1" || snapshot.SourceSandboxID != "sb-snap" {
					t.Fatalf("unexpected snapshot: %+v", snapshot)
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
			name: "get_network_usage_returns_counters_and_limits",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/v1/sandboxes/sb-net/network/usage" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(models.NetworkUsage{
						SandboxID:     "sb-net",
						BytesIn:       1024,
						BytesOut:      2048,
						BytesInLimit:  1 << 20,
						BytesOutLimit: 0,
						QuotaExceeded: false,
						LastSampledAt: time.Now().UTC(),
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				usage, err := client.GetNetworkUsage(ctx, "sb-net")
				if err != nil {
					t.Fatalf("GetNetworkUsage() error = %v", err)
				}
				if usage.BytesIn != 1024 || usage.BytesOutLimit != 0 || usage.QuotaExceeded {
					t.Fatalf("unexpected usage: %+v", usage)
				}
			},
		},
		{
			name: "set_network_limits_sends_patch_with_pointer_fields",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPatch || r.URL.Path != "/v1/sandboxes/sb-net/network/limits" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					var payload models.UpdateNetworkLimitsRequest
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if payload.NetworkBytesInLimit == nil || *payload.NetworkBytesInLimit != 4096 {
						t.Fatalf("unexpected NetworkBytesInLimit: %+v", payload.NetworkBytesInLimit)
					}
					if payload.NetworkBytesOutLimit != nil {
						t.Fatalf("expected NetworkBytesOutLimit nil; got %+v", payload.NetworkBytesOutLimit)
					}
					_ = json.NewEncoder(w).Encode(models.NetworkUsage{
						SandboxID:    "sb-net",
						BytesInLimit: 4096,
					})
				}))
				defer server.Close()

				client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
				inLimit := int64(4096)
				usage, err := client.SetNetworkLimits(ctx, "sb-net", models.UpdateNetworkLimitsRequest{NetworkBytesInLimit: &inLimit})
				if err != nil {
					t.Fatalf("SetNetworkLimits() error = %v", err)
				}
				if usage.BytesInLimit != 4096 {
					t.Fatalf("unexpected usage: %+v", usage)
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
				_, _, err := client.Create(ctx, CreateOptions{Image: "ubuntu:22.04"})
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
