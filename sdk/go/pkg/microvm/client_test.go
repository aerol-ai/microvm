package microvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestNewClientCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new_client_uses_environment_config",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer env-pat" {
						t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
					}
					_ = json.NewEncoder(w).Encode([]models.Sandbox{})
				}))
				defer server.Close()

				t.Setenv("SB_PAT_TOKEN", "env-pat")
				t.Setenv("SB_API_URL", server.URL)

				client, err := NewClient()
				if err != nil {
					t.Fatalf("NewClient() error = %v", err)
				}
				if _, err := client.List(ctx); err != nil {
					t.Fatalf("List() error = %v", err)
				}
			},
		},
		{
			name: "new_client_with_config_wraps_sandbox_resource",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer config-pat" {
						t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
					}
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(models.CreateSandboxResponse{
						Sandbox:       models.Sandbox{ID: "sb-structured", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted},
						SSHPrivateKey: "PRIVATE",
					})
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				sandbox, err := client.Create(ctx, sdktypes.CreateSandboxOptions{Image: "ubuntu:22.04"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if sandbox.ID != "sb-structured" {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
				if sandbox.SSHPrivateKey != "PRIVATE" {
					t.Fatalf("unexpected ssh private key: %q", sandbox.SSHPrivateKey)
				}
			},
		},
		{
			name: "create_with_image_builds_then_creates",
			run: func(t *testing.T) {
				var buildPayload struct {
					DockerfileContent string `json:"dockerfile_content"`
				}
				var createPayload models.CreateSandboxRequest
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/v1/images/build":
						if r.Method != http.MethodPost {
							t.Fatalf("unexpected build request: %s %s", r.Method, r.URL.Path)
						}
						if err := json.NewDecoder(r.Body).Decode(&buildPayload); err != nil {
							t.Fatalf("Decode(build) error = %v", err)
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"image": "aerolvm-build/abc123:latest"})
					case "/v1/sandboxes":
						if r.Method != http.MethodPost {
							t.Fatalf("unexpected create request: %s %s", r.Method, r.URL.Path)
						}
						if err := json.NewDecoder(r.Body).Decode(&createPayload); err != nil {
							t.Fatalf("Decode(create) error = %v", err)
						}
						_ = json.NewEncoder(w).Encode(models.CreateSandboxResponse{
							Sandbox: models.Sandbox{ID: "sb-from-image", Image: createPayload.Image, Status: models.SandboxStatusStarted},
						})
					default:
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				image := BaseImage("ubuntu:22.04").RunCommands("apt-get update", "apt-get install -y curl")
				sandbox, err := client.CreateWithImage(ctx, image, sdktypes.CreateSandboxOptions{})
				if err != nil {
					t.Fatalf("CreateWithImage() error = %v", err)
				}

				if sandbox.ID != "sb-from-image" {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
				if buildPayload.DockerfileContent != "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n" {
					t.Fatalf("unexpected build payload: %+v", buildPayload)
				}
				if createPayload.Image != "aerolvm-build/abc123:latest" {
					t.Fatalf("unexpected create payload image: %+v", createPayload)
				}
			},
		},
		{
			name: "build_image_maps_404_to_actionable_error",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte("404 page not found\n"))
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				_, err = client.BuildImage(ctx, BaseImage("alpine"))
				if err == nil || !strings.Contains(err.Error(), "does not support Image builds") || !strings.Contains(err.Error(), "string image reference") {
					t.Fatalf("unexpected error: %v", err)
				}
			},
		},
		{
			name: "new_client_requires_pat_token",
			run: func(t *testing.T) {
				t.Setenv("SB_PAT_TOKEN", "")
				_, err := NewClientWithConfig(&sdktypes.MicroVMConfig{})
				if err == nil {
					t.Fatal("expected auth error")
				}
			},
		},
		{
			name: "sandbox_exec_stream_requires_command",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				sandbox := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-stream"}, client: client}
				_, err = sandbox.ExecStream(ctx, sdktypes.ExecStreamOptions{})
				if err == nil || !strings.Contains(err.Error(), "command is required") {
					t.Fatalf("unexpected error: %v", err)
				}
			},
		},
		{
			name: "client_create_snapshot_maps_response",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-structured/snapshot" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					var payload models.CreateSandboxSnapshotRequest
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatalf("Decode() error = %v", err)
					}
					if payload.Name != "snapshots/demo:v1" {
						t.Fatalf("payload.Name = %q, want snapshots/demo:v1", payload.Name)
					}
					_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
						Name:            payload.Name,
						Image:           payload.Name,
						ImageID:         "sha256:snap-1",
						SourceSandboxID: "sb-structured",
						CreatedAt:       time.Now().UTC(),
					})
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "config-pat", APIUrl: server.URL})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				snapshot, err := client.CreateSnapshot(ctx, "sb-structured", "snapshots/demo:v1")
				if err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if snapshot.Name != "snapshots/demo:v1" || snapshot.ImageID != "sha256:snap-1" {
					t.Fatalf("unexpected snapshot: %+v", snapshot)
				}
			},
		},
		{
			name: "build_image_with_options_forwards_push_directive",
			run: func(t *testing.T) {
				var seenBody struct {
					DockerfileContent string `json:"dockerfile_content"`
					Push              *struct {
						Registry string `json:"registry"`
						Tag      string `json:"tag"`
						Server   string `json:"server"`
						Username string `json:"username"`
						Password string `json:"password"`
					} `json:"push"`
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.URL.Path != "/v1/images/build" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
						t.Fatalf("decode: %v", err)
					}
					_ = json.NewEncoder(w).Encode(map[string]string{
						"image":  "aerolvm-build/abc123:latest",
						"pushed": "ghcr.io/x/y:v1",
					})
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig: %v", err)
				}

				result, err := client.BuildImageWithOptions(ctx, BaseImage("alpine"), sdktypes.BuildImageOptions{
					Push: &sdktypes.BuildImagePushOptions{
						Registry: "ghcr.io/x/y",
						Tag:      "v1",
						Server:   "ghcr.io",
						Username: "u",
						Password: "p",
					},
				})
				if err != nil {
					t.Fatalf("BuildImageWithOptions: %v", err)
				}
				if result.Image != "aerolvm-build/abc123:latest" || result.Pushed != "ghcr.io/x/y:v1" {
					t.Fatalf("unexpected result: %+v", result)
				}
				if seenBody.Push == nil ||
					seenBody.Push.Registry != "ghcr.io/x/y" ||
					seenBody.Push.Tag != "v1" ||
					seenBody.Push.Server != "ghcr.io" ||
					seenBody.Push.Username != "u" ||
					seenBody.Push.Password != "p" {
					t.Fatalf("unexpected push body: %+v", seenBody.Push)
				}
			},
		},
		{
			name: "build_image_with_options_rejects_missing_credentials",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Fatalf("must not call daemon: %s %s", r.Method, r.URL.Path)
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig: %v", err)
				}
				cases := []struct {
					name string
					push sdktypes.BuildImagePushOptions
					want string
				}{
					{name: "missing_registry", push: sdktypes.BuildImagePushOptions{Username: "u", Password: "p"}, want: "registry"},
					{name: "missing_username", push: sdktypes.BuildImagePushOptions{Registry: "ghcr.io/x/y", Password: "p"}, want: "username"},
					{name: "missing_password", push: sdktypes.BuildImagePushOptions{Registry: "ghcr.io/x/y", Username: "u"}, want: "password"},
				}
				for _, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						_, err := client.BuildImageWithOptions(ctx, BaseImage("alpine"), sdktypes.BuildImageOptions{Push: &tc.push})
						if err == nil || !strings.Contains(err.Error(), tc.want) {
							t.Fatalf("expected error containing %q, got %v", tc.want, err)
						}
					})
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

// TestRegisterSnapshotForwardsToWire verifies the public wrapper threads
// through to /v1/snapshots with the right field names and surfaces the
// daemon's stored row back to the caller.
func TestRegisterSnapshotForwardsToWire(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/snapshots" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
			Name:      "py-base",
			Image:     "python:3.12-slim",
			RegionID:  "us",
			MemoryMB:  4096,
			DiskGB:    10,
			CreatedAt: time.Now().UTC(),
		})
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:     server.URL,
		PATToken:   "pat",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	snap, err := client.RegisterSnapshot(ctx, sdktypes.RegisterSnapshotOptions{
		Name:     "py-base",
		Image:    "python:3.12-slim",
		RegionID: "us",
		MemoryMB: 4096,
		DiskGB:   10,
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if snap.Name != "py-base" || snap.Image != "python:3.12-slim" {
		t.Fatalf("unexpected snap: %+v", snap)
	}
	if seen["name"] != "py-base" || seen["image"] != "python:3.12-slim" {
		t.Fatalf("payload missing fields: %+v", seen)
	}
}

func TestExecStreamWrappersAndHandleMethods(t *testing.T) {
	var upgrader websocket.Upgrader
	var mu sync.Mutex
	var binaries []string
	var controls []map[string]any
	var stdout string
	var stderr string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-stream/toolbox/process/exec/stream" {
			t.Fatalf("path: %q", r.URL.Path)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()

		var start map[string]any
		if err := conn.ReadJSON(&start); err != nil {
			t.Fatalf("read start payload: %v", err)
		}
		if start["command"] != "bash" {
			t.Fatalf("start payload = %+v, want command bash", start)
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
		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 0}); err != nil {
			t.Fatalf("write exit: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-stream"}, client: client}

	handle, err := sb.ExecStream(context.Background(), sdktypes.ExecStreamOptions{
		Command: "bash",
		OnStdout: func(chunk []byte) {
			stdout += string(chunk)
		},
		OnStderr: func(chunk []byte) {
			stderr += string(chunk)
		},
	})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	if err := handle.Write([]byte("pwd\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := handle.WriteString("ls\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := handle.Resize(120, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := handle.Signal("INT"); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	info, err := handle.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if info.Code != 0 || info.Signal != "" {
		t.Fatalf("wait result = %+v, want zero exit", info)
	}
	if stdout != "out" || stderr != "err" {
		t.Fatalf("stdout/stderr = (%q,%q), want (out,err)", stdout, stderr)
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

func TestExecStreamHandleClose(t *testing.T) {
	var upgrader websocket.Upgrader

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer conn.Close()

		var start map[string]any
		if err := conn.ReadJSON(&start); err != nil {
			t.Fatalf("read start payload: %v", err)
		}
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
	handle, err := client.ExecStream(context.Background(), "sb-stream", sdktypes.ExecStreamOptions{Command: "bash"})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, waitErr := handle.Wait(); waitErr == nil || !strings.Contains(waitErr.Error(), "stream closed before exit") {
		t.Fatalf("Wait err = %v, want stream closed before exit", waitErr)
	}
}

func TestWrapperErrorPaths(t *testing.T) {
	ctx := context.Background()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		PATToken: "pat",
		APIUrl:   "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	if _, err := client.BuildImage(ctx, nil); err == nil || !strings.Contains(err.Error(), "image is nil") {
		t.Fatalf("BuildImage(nil) err = %v", err)
	}
	if _, err := client.BuildImageWithOptions(ctx, nil, sdktypes.BuildImageOptions{}); err == nil || !strings.Contains(err.Error(), "image is nil") {
		t.Fatalf("BuildImageWithOptions(nil) err = %v", err)
	}
	if _, err := client.CreateWithImage(ctx, nil, sdktypes.CreateSandboxOptions{}); err == nil || !strings.Contains(err.Error(), "image is nil") {
		t.Fatalf("CreateWithImage(nil) err = %v", err)
	}
	if _, err := client.RegisterSnapshotFromImage(ctx, "snap", nil, sdktypes.RegisterSnapshotOptions{}); err == nil || !strings.Contains(err.Error(), "image is nil") {
		t.Fatalf("RegisterSnapshotFromImage(nil) err = %v", err)
	}
	if wrapSandbox(client, nil) != nil {
		t.Fatal("wrapSandbox(nil) != nil")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err = NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-err"}, client: client}

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{name: "create", run: func() error { _, err := client.Create(ctx, sdktypes.CreateSandboxOptions{Image: "alpine"}); return err }},
		{name: "get", run: func() error { _, err := client.Get(ctx, "sb-err"); return err }},
		{name: "start", run: func() error { _, err := client.Start(ctx, "sb-err"); return err }},
		{name: "stop", run: func() error { _, err := client.Stop(ctx, "sb-err"); return err }},
		{name: "resize", run: func() error {
			_, err := client.Resize(ctx, "sb-err", sdktypes.ResizeSandboxOptions{CPU: 2})
			return err
		}},
		{name: "update_lifecycle", run: func() error { _, err := client.UpdateLifecycle(ctx, "sb-err", sdktypes.Lifecycle{}); return err }},
		{name: "refresh", run: func() error { return sb.Refresh(ctx) }},
		{name: "sandbox_start", run: func() error { return sb.Start(ctx) }},
		{name: "sandbox_stop", run: func() error { return sb.Stop(ctx) }},
		{name: "sandbox_resize", run: func() error { return sb.Resize(ctx, sdktypes.ResizeSandboxOptions{CPU: 2}) }},
		{name: "sandbox_update_lifecycle", run: func() error { return sb.UpdateLifecycle(ctx, sdktypes.Lifecycle{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatalf("%s err = nil, want error", tc.name)
			}
		})
	}
}

// TestRegisterSnapshotFromImageBuildsDockerfile verifies the convenience
// wrapper that takes an *Image: it serializes to dockerfile_content under
// the hood and forwards everything else from the options.
func TestRegisterSnapshotFromImageBuildsDockerfile(t *testing.T) {
	ctx := context.Background()
	var seen map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
			Name:  "built",
			Image: "snapshots/built:resolved",
		})
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl: server.URL, PATToken: "pat", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	img := BaseImage("debian:bookworm-slim").RunCommands("apt-get update")
	snap, err := client.RegisterSnapshotFromImage(ctx, "built", img, sdktypes.RegisterSnapshotOptions{
		Entrypoint: []string{"/bin/sh", "-c", "echo hi"},
	})
	if err != nil {
		t.Fatalf("RegisterSnapshotFromImage: %v", err)
	}
	if snap.Image != "snapshots/built:resolved" {
		t.Fatalf("Image = %q, want resolved tag", snap.Image)
	}
	got, _ := seen["dockerfile_content"].(string)
	if got == "" || !strings.Contains(got, "FROM debian:bookworm-slim") {
		t.Errorf("dockerfile_content missing FROM: %q", got)
	}
	if !strings.Contains(got, "apt-get update") {
		t.Errorf("dockerfile_content missing RUN body: %q", got)
	}
	if _, present := seen["image"]; present {
		t.Errorf("image must be omitted on dockerfile path: %+v", seen)
	}
	if seen["name"] != "built" {
		t.Errorf("name = %v, want built", seen["name"])
	}
}

// TestListWithTagsOptionRendersWireFormat covers the public ListOption →
// wire path: callers use microvm.WithTags(map[...]string{...}) and the
// resulting request must carry `?tag.<k>=<v>` for each pair. Pairs with the
// inner-transport test in apiclient/client_test.go; this one specifically
// pins that the variadic option wiring doesn't silently drop the map.
func TestListWithTagsOptionRendersWireFormat(t *testing.T) {
	ctx := context.Background()
	var seenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}
	if _, err := client.List(ctx, WithTags(map[string]string{"user_id": "alice"})); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !strings.HasPrefix(seenURL, "/v1/sandboxes?") {
		t.Fatalf("URL = %q, want /v1/sandboxes?... prefix", seenURL)
	}
	if !strings.Contains(seenURL, "tag.user_id=alice") {
		t.Fatalf("URL = %q, missing tag.user_id=alice", seenURL)
	}
}

// TestTemplateLifecycle covers the public CreateTemplate / GetTemplate /
// ListTemplates / DeleteTemplate / RebuildTemplate methods. The server
// shape is stubbed via httptest so we can assert method+path+JSON shape
// in one round trip per call. Daemon-side concurrency / state-machine
// behaviour is covered by the internal/service tests on the server side.
func TestTemplateLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	type seenReq struct {
		method string
		path   string
		body   map[string]any
	}
	var seen seenReq

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.body = nil
		if r.ContentLength > 0 {
			_ = json.NewDecoder(r.Body).Decode(&seen.body)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/templates":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "tpl-go", "image": "docker://alpine:3.19",
				"status": "pending", "min_size_mib": 256,
				"created_at": now, "updated_at": now,
				"has_snapshot": false, "has_overlay": false,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/templates":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": "tpl-go", "image": "docker://alpine:3.19",
				"status": "ready", "created_at": now, "updated_at": now,
				"has_snapshot": true, "has_overlay": false, "push_state": "active",
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/templates/tpl-go":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "tpl-go", "image": "docker://alpine:3.19",
				"status": "ready", "created_at": now, "updated_at": now,
				"has_snapshot": true, "has_overlay": false,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/templates/tpl-go/rebuild":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "tpl-go", "image": "docker://alpine:3.19",
				"status": "unhealthy", "created_at": now, "updated_at": now,
				"has_snapshot": true, "has_overlay": false,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/templates/tpl-go":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	tpl, err := client.CreateTemplate(ctx, sdktypes.CreateTemplateOptions{
		ID: "tpl-go", Image: "docker://alpine:3.19", MinSizeMiB: 256,
	})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	if tpl.ID != "tpl-go" || tpl.Status != sdktypes.TemplateStatusPending {
		t.Fatalf("CreateTemplate response = %+v", tpl)
	}
	if seen.body["image"] != "docker://alpine:3.19" || int(seen.body["min_size_mib"].(float64)) != 256 {
		t.Fatalf("CreateTemplate body = %+v, missing fields", seen.body)
	}

	rows, err := client.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != sdktypes.TemplateStatusReady || !rows[0].HasSnapshot {
		t.Fatalf("ListTemplates = %+v", rows)
	}

	got, err := client.GetTemplate(ctx, "tpl-go")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.ID != "tpl-go" {
		t.Fatalf("GetTemplate = %+v", got)
	}

	reb, err := client.RebuildTemplate(ctx, "tpl-go")
	if err != nil {
		t.Fatalf("RebuildTemplate: %v", err)
	}
	if reb.Status != sdktypes.TemplateStatusUnhealthy {
		t.Fatalf("RebuildTemplate status = %s, want unhealthy", reb.Status)
	}

	if err := client.DeleteTemplate(ctx, "tpl-go"); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	if seen.method != http.MethodDelete || seen.path != "/v1/templates/tpl-go" {
		t.Fatalf("last call = %+v, want DELETE /v1/templates/tpl-go", seen)
	}
}

// TestRebuildTemplate_412SurfacedAsError pins the operator-rebuild contract:
// the daemon's 412 (template not in a rebuildable state) must surface as an
// error from the SDK call, not as a silent zero-value response. Operator
// tooling treating this as success would forever miss the underlying state.
func TestRebuildTemplate_412SurfacedAsError(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"error":"template not eligible for rebuild: current status=pending"}`))
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
		PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	_, err = client.RebuildTemplate(ctx, "tpl-pending")
	if err == nil {
		t.Fatal("RebuildTemplate returned nil error on 412 response")
	}
	if !strings.Contains(err.Error(), "not eligible for rebuild") {
		t.Errorf("err = %v, want it to mention 'not eligible for rebuild'", err)
	}
}
