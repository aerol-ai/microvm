package isolate

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeWorkerdPath() string {
	return os.Args[0]
}

func TestBundleServerIncludesEgressSlot(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t), EgressPoolSize: 2})
	if err := h.startBundleServer(); err != nil {
		t.Fatal(err)
	}
	defer h.stopServers()
	_ = h.Load("sb-1", testBundle(t))
	h.SetEgressPolicy("sb-1", EgressPolicy{})
	client := unixHTTPClient(h.hostSock)
	resp, err := client.Get("http://host/bundle/sb-1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"egress_slot"`) {
		t.Fatalf("wire missing egress_slot: %s", body)
	}
}

func TestStartErrorPaths(t *testing.T) {
	t.Run("mkdir", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: filepath.Join(parent, "run")})
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("err = %v, want mkdir", err)
		}
	})

	t.Run("bundle listen", func(t *testing.T) {
		dir := shortRunDir(t)
		h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: dir})
		if err := os.MkdirAll(h.hostSock, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.hostSock, "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "bundle socket") {
			t.Fatalf("err = %v, want bundle socket", err)
		}
	})

	t.Run("egress deny listen", func(t *testing.T) {
		dir := shortRunDir(t)
		h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: dir})
		if err := os.MkdirAll(h.egressDenySock, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.egressDenySock, "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "egress-deny") {
			t.Fatalf("err = %v, want egress-deny", err)
		}
	})

	t.Run("writeConfig controller", func(t *testing.T) {
		dir := shortRunDir(t)
		h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: dir})
		// Directory where the controller module should be written → WriteFile fails.
		if err := os.MkdirAll(filepath.Join(dir, controllerModuleName), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "controller") {
			t.Fatalf("err = %v, want controller write", err)
		}
	})

	t.Run("writeConfig capnp", func(t *testing.T) {
		dir := shortRunDir(t)
		h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: dir})
		if err := os.MkdirAll(filepath.Join(dir, "config.capnp"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "config") {
			t.Fatalf("err = %v, want config write", err)
		}
	})

	t.Run("workerd missing", func(t *testing.T) {
		dir := shortRunDir(t)
		h, _ := NewHost(HostConfig{WorkerdPath: filepath.Join(dir, "no-such-workerd"), GroupKey: "acme", RunDir: dir})
		if err := h.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "start workerd") {
			t.Fatalf("err = %v, want start workerd", err)
		}
	})

	t.Run("waitReady timeout", func(t *testing.T) {
		dir := shortRunDir(t)
		// Binary that exits 0 immediately — control socket never appears.
		bin := filepath.Join(dir, "quiet-exit")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		h, _ := NewHost(HostConfig{
			WorkerdPath: bin, GroupKey: "acme", RunDir: dir,
			StartTimeout: 40 * time.Millisecond,
		})
		err := h.Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not ready") && !strings.Contains(err.Error(), "exited") {
			t.Fatalf("err = %v, want not-ready or exited", err)
		}
	})

	t.Run("waitReady ctx cancel", func(t *testing.T) {
		dir := shortRunDir(t)
		bin := filepath.Join(dir, "sleep-long")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		h, _ := NewHost(HostConfig{
			WorkerdPath: bin, GroupKey: "acme", RunDir: dir,
			StartTimeout: 5 * time.Second,
		})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		err := h.Start(ctx)
		if err == nil {
			_ = h.Stop()
			t.Fatal("want ctx cancel error")
		}
	})
}

func TestStartInvokeStopWithFakeWorkerd(t *testing.T) {
	dir := shortRunDir(t)
	h, err := NewHost(HostConfig{
		WorkerdPath:    fakeWorkerdPath(),
		GroupKey:       "acme",
		RunDir:         dir,
		StartTimeout:   5 * time.Second,
		EgressPoolSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the re-exec child sees the latch. Clear in parent so nested tests
	// don't accidentally re-enter fake mode (init already ran in parent).
	t.Setenv("ISOLATE_FAKE_WORKERD", "1")

	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer h.Stop()

	if !h.started.Load() {
		t.Fatal("started flag not set")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ctrl/hello", nil)
	resp, err := h.Invoke(ctx, "sb-1", req)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "fake-ok" {
		t.Fatalf("invoke = %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("x-echo-sb-id") != "sb-1" {
		t.Fatalf("x-sb-id not forwarded: %q", resp.Header.Get("x-echo-sb-id"))
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestInvokeNilClient(t *testing.T) {
	h, _ := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: shortRunDir(t)})
	h.started.Store(true) // started but ctrlClient never set
	req, _ := http.NewRequest(http.MethodGet, "http://ctrl/", nil)
	if _, err := h.Invoke(context.Background(), "sb-1", req); err == nil {
		t.Fatal("want error when ctrlClient is nil")
	}
}

func TestWaitReadyDirect(t *testing.T) {
	dir := shortRunDir(t)
	sock := filepath.Join(dir, "ctrl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // 502 still proves the controller is up
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	h := &Host{cfg: HostConfig{StartTimeout: time.Second}}
	client := unixHTTPClient(sock)
	// Unstarted cmd: ProcessState stays nil; readiness succeeds on HTTP.
	cmd := exec.Command("true")
	if err := h.waitReady(context.Background(), cmd, client); err != nil {
		t.Fatalf("waitReady: %v", err)
	}
}

func TestNewHostDefaults(t *testing.T) {
	h, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: "/x", EgressPoolSize: 0})
	if err != nil {
		t.Fatal(err)
	}
	if h.cfg.EgressPoolSize != defaultEgressPoolSize || h.cfg.StartTimeout != 10*time.Second {
		t.Fatalf("defaults = pool=%d timeout=%s", h.cfg.EgressPoolSize, h.cfg.StartTimeout)
	}
	if h.logger == nil {
		t.Fatal("nil logger should default")
	}
}
