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
					sampled := time.Now().UTC()
					_ = json.NewEncoder(w).Encode(models.NetworkUsage{
						SandboxID:     "sb-net",
						BytesIn:       1024,
						BytesOut:      2048,
						BytesInLimit:  1 << 20,
						BytesOutLimit: 0,
						QuotaExceeded: false,
						LastSampledAt: &sampled,
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

// TestRegisterSnapshotSendsImagePath verifies the image-only happy path:
// fields land on the wire under their snake_case names, the URL targets
// /v1/snapshots, and the daemon's response is round-tripped back to the
// caller. Splitting this off the big TestTransportClientCases table keeps
// the per-field assertions readable.
func TestRegisterSnapshotSendsImagePath(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/snapshots" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer pat" {
			t.Fatalf("unexpected authorization: %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
			Name:     "py-base",
			Image:    "python:3.12-slim",
			RegionID: "us",
			CPU:      2,
			MemoryMB: 4096,
			DiskGB:   10,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	snap, err := client.RegisterSnapshot(ctx, RegisterSnapshotOptions{
		Name:     "py-base",
		Image:    "python:3.12-slim",
		RegionID: "us",
		CPU:      2,
		MemoryMB: 4096,
		DiskGB:   10,
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if snap.Name != "py-base" || snap.Image != "python:3.12-slim" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if seen["image"] != "python:3.12-slim" || seen["region_id"] != "us" {
		t.Fatalf("payload missing fields: %+v", seen)
	}
	// dockerfile_content omitempty — must NOT be in the payload when Image is set.
	if _, present := seen["dockerfile_content"]; present {
		t.Errorf("dockerfile_content should not be sent when Image is set: %+v", seen)
	}
}

// TestRegisterSnapshotSendsDockerfilePath verifies the build-info wire
// shape — the payload uses dockerfile_content, image is omitted, and the
// daemon's resolved tag flows back to the caller.
func TestRegisterSnapshotSendsDockerfilePath(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
			Name:  "built",
			Image: "snapshots/built:abcd1234",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	snap, err := client.RegisterSnapshot(ctx, RegisterSnapshotOptions{
		Name:              "built",
		DockerfileContent: "FROM debian:bookworm-slim\nRUN apt-get update",
		Entrypoint:        []string{"/bin/sh", "-c", "echo hi"},
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if snap.Image != "snapshots/built:abcd1234" {
		t.Fatalf("Image = %q, want resolved build tag", snap.Image)
	}
	if seen["dockerfile_content"] == nil || seen["dockerfile_content"] == "" {
		t.Errorf("dockerfile_content missing: %+v", seen)
	}
	if _, present := seen["image"]; present {
		t.Errorf("image must be omitted on dockerfile path: %+v", seen)
	}
	ep, _ := seen["entrypoint"].([]any)
	if len(ep) != 3 {
		t.Errorf("entrypoint = %+v, want 3 elements", seen["entrypoint"])
	}
}

// TestRegisterSnapshotClientValidation pins the validation we do client-
// side before issuing the request. Catching these locally avoids a network
// round-trip and gives a more direct error message.
func TestRegisterSnapshotClientValidation(t *testing.T) {
	ctx := context.Background()
	// Server intentionally panics — these calls must never reach it.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("validation should fail before the request fires; got %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{HTTPClient: server.Client()})

	cases := []struct {
		name string
		opts RegisterSnapshotOptions
		want string
	}{
		{"missing name", RegisterSnapshotOptions{Image: "alpine"}, "name is required"},
		{"missing both", RegisterSnapshotOptions{Name: "x"}, "image or dockerfile_content"},
		{"both set", RegisterSnapshotOptions{Name: "x", Image: "alpine", DockerfileContent: "FROM busybox"}, "mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.RegisterSnapshot(ctx, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestListRendersTagFilterAsTagDotPrefix mirrors
// pkg/api/v1/list_filter_test.go: every supplied tag must reach the wire
// under the `tag.` prefix, which is what the server's parseTagFilter keys
// on. If this drifts (e.g. someone switches to `tags[user_id]`), the server
// silently returns the full list and breaks multi-tenant scoping.
func TestListRendersTagFilterAsTagDotPrefix(t *testing.T) {
	ctx := context.Background()
	var seen *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if _, err := client.List(ctx, map[string]string{"user_id": "alice", "project_id": "p1"}); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if seen == nil {
		t.Fatalf("server received no request")
	}
	if seen.URL.Path != "/v1/sandboxes" {
		t.Fatalf("path = %q, want /v1/sandboxes", seen.URL.Path)
	}
	q := seen.URL.Query()
	if got := q.Get("tag.user_id"); got != "alice" {
		t.Fatalf("tag.user_id = %q, want alice", got)
	}
	if got := q.Get("tag.project_id"); got != "p1" {
		t.Fatalf("tag.project_id = %q, want p1", got)
	}
}

// TestListWithoutTagsOmitsQueryString pins the byte-identical-to-pre-filter
// guarantee: a bare List call must not introduce a stray "?". Without this,
// HTTP fixtures and request matchers in downstream code break the moment the
// SDK gains a filter arg.
func TestListWithoutTagsOmitsQueryString(t *testing.T) {
	ctx := context.Background()
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	for _, tags := range []map[string]string{nil, {}} {
		if _, err := client.List(ctx, tags); err != nil {
			t.Fatalf("List(%v) error = %v", tags, err)
		}
		if seenURL != "/v1/sandboxes" {
			t.Fatalf("URL = %q, want /v1/sandboxes (tags=%v)", seenURL, tags)
		}
	}
}
