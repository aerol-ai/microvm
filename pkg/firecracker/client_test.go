package firecracker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startUDSServer starts an httptest.Server bound to a Unix-domain socket
// inside t.TempDir() and returns the socket path. The server is closed
// automatically on test cleanup. Mirrors the shape Firecracker presents:
// HTTP/1.1 over a single UDS, no host header authority.
func startUDSServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "fc.sock")
	srv := &http.Server{Handler: handler}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(sockPath)
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
