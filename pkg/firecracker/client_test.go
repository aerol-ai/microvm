package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// startUDSServer starts an httptest.Server bound to a Unix-domain socket
// inside t.TempDir() and returns the socket path. The server is closed
// automatically on test cleanup. Mirrors the shape Firecracker presents:
// HTTP/1.1 over a single UDS, no host header authority.
func startUDSServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	baseDir, err := os.MkdirTemp("", "fc-uds-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	sockPath := filepath.Join(baseDir, "fc.sock")
	srv := &http.Server{Handler: handler}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(sockPath)
		_ = os.RemoveAll(baseDir)
	})
	return sockPath
}

func TestPing_SuccessAndAPIError(t *testing.T) {
	calls := 0
	sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		// First call: 200 with a small body. Second call: 400 with a
		// fault_message — both reachable through the same handler so we
		// don't need to wire two servers.
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(InstanceInfo{ID: "fc-1", State: "Running", VmmVersion: "1.7.0"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"fault_message":"already started"}`))
	}))
	c := New(sock)

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: unexpected error: %v", err)
	}

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatalf("expected APIError on second call")
	}
	var apiErr *APIError
	if !errorsAs(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", apiErr.Status)
	}
	if !strings.Contains(apiErr.Body, "already started") {
		t.Fatalf("body did not surface fault_message: %q", apiErr.Body)
	}
}

// TestPutMachineConfig_RoundTrip confirms the JSON shape we send matches
// Firecracker's swagger names. A typo in a json tag would break VMM bring-up
// silently (Firecracker rejects unknown fields with a 400, which we'd see at
// boot, but the test catches it pre-merge).
func TestPutMachineConfig_RoundTrip(t *testing.T) {
	var seen MachineConfig
	sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/machine-config" || r.Method != http.MethodPut {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	c := New(sock)

	want := MachineConfig{VcpuCount: 2, MemSizeMib: 512, TrackDirtyPages: true}
	if err := c.PutMachineConfig(context.Background(), want); err != nil {
		t.Fatalf("PutMachineConfig: %v", err)
	}
	if seen != want {
		t.Fatalf("server saw %+v, want %+v", seen, want)
	}
}

func TestNewAndSocketPath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "fc.sock")
	c := New(sock)

	if c.SocketPath() != sock {
		t.Fatalf("SocketPath = %q, want %q", c.SocketPath(), sock)
	}
	if c.httpClient == nil {
		t.Fatalf("httpClient should be initialized")
	}
	if c.httpClient.Timeout != DefaultRequestTimeout {
		t.Fatalf("timeout = %v, want %v", c.httpClient.Timeout, DefaultRequestTimeout)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.httpClient.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatalf("DisableKeepAlives should be true")
	}
}

func TestInstanceInfoAndEmptyBody(t *testing.T) {
	t.Run("instance-info-success", func(t *testing.T) {
		sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" || r.Method != http.MethodGet {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(InstanceInfo{ID: "fc-2", State: "Paused", VmmVersion: "1.8.0"})
		}))
		c := New(sock)

		info, err := c.InstanceInfo(context.Background())
		if err != nil {
			t.Fatalf("InstanceInfo: %v", err)
		}
		if info.ID != "fc-2" || info.State != "Paused" || info.VmmVersion != "1.8.0" {
			t.Fatalf("unexpected info: %+v", info)
		}
	})

	t.Run("ping-allows-empty-200-body", func(t *testing.T) {
		sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" || r.Method != http.MethodGet {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		c := New(sock)
		if err := c.Ping(context.Background()); err != nil {
			t.Fatalf("Ping with empty body: %v", err)
		}
	})
}

func TestWrapperMethods_RequestShape(t *testing.T) {
	type reqCase struct {
		name   string
		method string
		path   string
		body   any
		invoke func(context.Context, *Client) error
	}

	cases := []reqCase{
		{
			name:   "put-boot-source",
			method: http.MethodPut,
			path:   "/boot-source",
			body:   BootSource{KernelImagePath: "/vmlinux", BootArgs: "console=ttyS0"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PutBootSource(ctx, BootSource{KernelImagePath: "/vmlinux", BootArgs: "console=ttyS0"})
			},
		},
		{
			name:   "put-drive",
			method: http.MethodPut,
			path:   "/drives/root",
			body:   Drive{DriveID: "root", PathOnHost: "/tmp/root.ext4", IsRootDevice: true, IsReadOnly: false},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PutDrive(ctx, "root", Drive{DriveID: "root", PathOnHost: "/tmp/root.ext4", IsRootDevice: true, IsReadOnly: false})
			},
		},
		{
			name:   "patch-drive",
			method: http.MethodPatch,
			path:   "/drives/root",
			body:   DrivePatch{DriveID: "root", PathOnHost: "/tmp/new-root.ext4"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PatchDrive(ctx, "root", DrivePatch{DriveID: "root", PathOnHost: "/tmp/new-root.ext4"})
			},
		},
		{
			name:   "put-network-interface",
			method: http.MethodPut,
			path:   "/network-interfaces/eth0",
			body:   NetworkInterface{IfaceID: "eth0", HostDevName: "tap0", GuestMAC: "06:00:ac:10:00:02"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PutNetworkInterface(ctx, "eth0", NetworkInterface{IfaceID: "eth0", HostDevName: "tap0", GuestMAC: "06:00:ac:10:00:02"})
			},
		},
		{
			name:   "patch-network-interface",
			method: http.MethodPatch,
			path:   "/network-interfaces/eth0",
			body:   NetworkInterfacePatch{IfaceID: "eth0", HostDevName: "tap1"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PatchNetworkInterface(ctx, "eth0", NetworkInterfacePatch{IfaceID: "eth0", HostDevName: "tap1"})
			},
		},
		{
			name:   "put-vsock",
			method: http.MethodPut,
			path:   "/vsock",
			body:   Vsock{GuestCID: 3, UDSPath: "/tmp/vsock.sock"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PutVsock(ctx, Vsock{GuestCID: 3, UDSPath: "/tmp/vsock.sock"})
			},
		},
		{
			name:   "put-logger",
			method: http.MethodPut,
			path:   "/logger",
			body:   Logger{LogPath: "/tmp/fc.log", Level: "Info"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.PutLogger(ctx, Logger{LogPath: "/tmp/fc.log", Level: "Info"})
			},
		},
		{
			name:   "action",
			method: http.MethodPut,
			path:   "/actions",
			body:   Action{ActionType: ActionPause},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Action(ctx, Action{ActionType: ActionPause})
			},
		},
		{
			name:   "create-snapshot",
			method: http.MethodPut,
			path:   "/snapshot/create",
			body:   SnapshotCreate{SnapshotType: "Full", SnapshotPath: "/tmp/vm.snap", MemFilePath: "/tmp/vm.mem"},
			invoke: func(ctx context.Context, c *Client) error {
				return c.CreateSnapshot(ctx, SnapshotCreate{SnapshotType: "Full", SnapshotPath: "/tmp/vm.snap", MemFilePath: "/tmp/vm.mem"})
			},
		},
		{
			name:   "load-snapshot",
			method: http.MethodPut,
			path:   "/snapshot/load",
			body: SnapshotLoad{
				SnapshotPath:        "/tmp/vm.snap",
				MemBackend:          &MemoryBackend{BackendType: "File", BackendPath: "/tmp/vm.mem"},
				EnableDiffSnapshots: true,
				ResumeVM:            false,
			},
			invoke: func(ctx context.Context, c *Client) error {
				return c.LoadSnapshot(ctx, SnapshotLoad{
					SnapshotPath:        "/tmp/vm.snap",
					MemBackend:          &MemoryBackend{BackendType: "File", BackendPath: "/tmp/vm.mem"},
					EnableDiffSnapshots: true,
					ResumeVM:            false,
				})
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Fatalf("unexpected request: %s %s, want %s %s", r.Method, r.URL.Path, tc.method, tc.path)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Fatalf("content-type = %q, want application/json", ct)
				}
				if accept := r.Header.Get("Accept"); accept != "application/json" {
					t.Fatalf("accept = %q, want application/json", accept)
				}

				seen := reflect.New(reflect.TypeOf(tc.body)).Interface()
				if err := json.NewDecoder(r.Body).Decode(seen); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				if !reflect.DeepEqual(reflect.ValueOf(seen).Elem().Interface(), tc.body) {
					t.Fatalf("decoded body = %+v, want %+v", reflect.ValueOf(seen).Elem().Interface(), tc.body)
				}

				w.WriteHeader(http.StatusNoContent)
			}))

			c := New(sock)
			if err := tc.invoke(context.Background(), c); err != nil {
				t.Fatalf("invoke %s: %v", tc.name, err)
			}
		})
	}
}

func TestDo_ErrorPaths(t *testing.T) {
	t.Run("marshal-error", func(t *testing.T) {
		c := New(filepath.Join(t.TempDir(), "never-used.sock"))
		err := c.do(context.Background(), http.MethodPut, "/x", map[string]any{"bad": make(chan int)}, nil)
		if err == nil || !strings.Contains(err.Error(), "marshal") {
			t.Fatalf("expected marshal error, got: %v", err)
		}
	})

	t.Run("build-request-error", func(t *testing.T) {
		c := New(filepath.Join(t.TempDir(), "never-used.sock"))
		err := c.do(context.Background(), http.MethodGet, "/bad\npath", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("expected build request error, got: %v", err)
		}
	})

	t.Run("transport-error", func(t *testing.T) {
		missingSock := filepath.Join(t.TempDir(), "missing.sock")
		c := New(missingSock)
		err := c.Ping(context.Background())
		if err == nil || !strings.Contains(err.Error(), "firecracker: GET /") {
			t.Fatalf("expected transport error, got: %v", err)
		}
	})

	t.Run("decode-error", func(t *testing.T) {
		sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{not-json"))
		}))
		c := New(sock)
		_, err := c.InstanceInfo(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decode GET /") {
			t.Fatalf("expected decode error, got: %v", err)
		}
	})

	t.Run("context-timeout", func(t *testing.T) {
		sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(60 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"fc-timeout","state":"Running"}`))
		}))
		c := New(sock)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		err := c.Ping(ctx)
		if err == nil {
			t.Fatalf("expected timeout error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline exceeded, got: %v", err)
		}
	})
}

func TestAPIError_ErrorFormatting(t *testing.T) {
	errWithBody := (&APIError{Method: http.MethodPut, Path: "/actions", Status: 400, Body: `{"fault_message":"bad action"}`}).Error()
	if !strings.Contains(errWithBody, "firecracker: PUT /actions -> 400:") {
		t.Fatalf("unexpected format with body: %q", errWithBody)
	}

	errNoBody := (&APIError{Method: http.MethodGet, Path: "/", Status: 503}).Error()
	if errNoBody != "firecracker: GET / -> 503" {
		t.Fatalf("unexpected format without body: %q", errNoBody)
	}
}

// errorsAs is a tiny local alias to keep the test free of the errors
// import dance for an as-conversion in a single spot.
func errorsAs(err error, target **APIError) bool {
	for err != nil {
		if v, ok := err.(*APIError); ok {
			*target = v
			return true
		}
		type unwrap interface{ Unwrap() error }
		u, ok := err.(unwrap)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
