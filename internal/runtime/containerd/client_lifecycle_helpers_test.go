package containerd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClientNilSafe(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(t.Context()); err == nil {
		t.Fatal("want error for nil client ping")
	}
	if c.Raw() != nil || c.Namespace() != "" {
		t.Fatal("nil client accessors should be empty")
	}
}

func TestClientWithNS(t *testing.T) {
	c := &Client{namespace: "aerolvm"}
	ctx := c.withNS(t.Context())
	if got := c.Namespace(); got != "aerolvm" {
		t.Fatalf("namespace=%q", got)
	}
	_ = ctx
}

func TestEnsureToolboxBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "toolboxd")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{ToolboxBinaryPath: bin}, nil, nil)
	if err := d.ensureToolboxBinary(); err != nil {
		t.Fatal(err)
	}
	d2 := New(Config{}, nil, nil)
	if err := d2.ensureToolboxBinary(); err == nil {
		t.Fatal("want missing toolbox error")
	}
}

func TestTaskLogPathAndRemove(t *testing.T) {
	dir := t.TempDir()
	d := New(Config{LogDir: dir}, nil, nil)
	path, err := d.taskLogPath("sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.removeTaskLog("sb-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("log should be removed")
	}
}

func TestRemoveHostFiles(t *testing.T) {
	runDir := t.TempDir()
	d := New(Config{RunDir: runDir}, nil, nil)
	files, err := prepareSandboxHostFiles(runDir, "sb-h")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.removeHostFiles("sb-h"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files.Dir); !os.IsNotExist(err) {
		t.Fatal("host files dir should be removed")
	}
}

func TestFromDaemonConfigNativeNetnsFlag(t *testing.T) {
	got := FromDaemonConfig(config.Config{ContainerdNativeNetnsPoolEnabled: true})
	if !got.NativeNetnsPool {
		t.Fatal("flag not projected")
	}
}

func TestRegistryHostEdgeCases(t *testing.T) {
	if got := registryHost(""); got != "" {
		t.Fatalf("empty ref => %q", got)
	}
}

func TestConnectRejectsEmptyPaths(t *testing.T) {
	if _, err := Connect("", "aerolvm"); err == nil {
		t.Fatal("want error for empty socket")
	}
	if _, err := Connect("/run/containerd.sock", ""); err == nil {
		t.Fatal("want error for empty namespace")
	}
}

func TestClientTransportDelegation(t *testing.T) {
	tr := newFakeTransport()
	tr.emitEvents = true
	c := NewTestClient("aerolvm", tr)
	ctx := context.Background()
	if _, err := c.PullImage(ctx, "alpine:3.20"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListContainers(ctx); err != nil {
		t.Fatal(err)
	}
	if c.ContentStore() != nil {
		t.Fatal("fake content store should be nil")
	}
	ch, errCh := c.SubscribeEvents(ctx)
	select {
	case <-ch:
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSetupReadySocket(t *testing.T) {
	dir := "/tmp/avmrdy"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := New(Config{ReadyDir: dir, ReadyEnabled: true}, nil, nil)
	env := []string{"BASE=1"}
	mounts := []specs.Mount{{Destination: "/data"}}
	ln, err := d.setupReadySocket(&env, &mounts, "sb", "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if len(env) < 2 {
		t.Fatalf("env not extended: %v", env)
	}
	if len(mounts) < 2 {
		t.Fatalf("mounts not extended: %v", mounts)
	}
}

func TestEnsureImageBackoff(t *testing.T) {
	tr := newFakeTransport()
	miss := errors.New("missing")
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, miss }
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) { return nil, miss }
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	_, err := d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), "missing:ref", nil)
	if err == nil {
		t.Fatal("want pull error")
	}
	_, err = d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), "missing:ref", nil)
	if err == nil || !strings.Contains(err.Error(), "backing off") {
		t.Fatalf("want backoff, got %v", err)
	}
}

func TestImageDefaultCommandNilClient(t *testing.T) {
	_, err := imageDefaultCommand(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestPollToolboxHealthOK(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err := pollToolboxHealth(context.Background(), "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
}

func TestPollToolboxHealthBadStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	if err := pollToolboxHealth(context.Background(), "127.0.0.1", port); err == nil {
		t.Fatal("want status error")
	}
}

func TestTaskLogPathMissingDir(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.taskLogPath("sb"); err == nil {
		t.Fatal("want error for missing log dir")
	}
}

func TestClientRawNilOnTestClient(t *testing.T) {
	c := NewTestClient("aerolvm", newFakeTransport())
	if c.Raw() != nil {
		t.Fatal("test client Raw should be nil")
	}
	if c.ContentStore() != nil {
		t.Fatal("fake content store should be nil")
	}
}

func TestInspectStoppedContainerFake(t *testing.T) {
	d := newTestDriver(t)
	c := NewTestClient("aerolvm", newFakeTransport())
	d.SetClient(c)
	ctx := context.Background()
	if _, err := c.NewContainer(ctx, "sb-stopped"); err != nil {
		t.Fatal(err)
	}
	state, err := d.Inspect(ctx, "sb-stopped")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != models.SandboxStatusStopped {
		t.Fatalf("status=%s", state.Status)
	}
}

func TestNamespacedHelper(t *testing.T) {
	ctx := namespaced(context.Background(), "aerolvm")
	if ctx == nil {
		t.Fatal("nil context")
	}
}

func TestEnsureClientLazyConnectFails(t *testing.T) {
	d := New(Config{Socket: "/nonexistent/containerd.sock", Namespace: "aerolvm"}, nil, nil)
	if err := d.Ping(context.Background()); err == nil {
		t.Fatal("want connect error")
	}
}

func TestIsLoopbackResolver(t *testing.T) {
	if !isLoopbackResolver("127.0.0.1") {
		t.Fatal("127.0.0.1 should be loopback")
	}
	if isLoopbackResolver("8.8.8.8") {
		t.Fatal("8.8.8.8 should not be loopback")
	}
	if isLoopbackResolver("not-an-ip") {
		t.Fatal("invalid ip should not be loopback")
	}
}

func TestCappedWriterWriteErrorPath(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "closed.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	w := &cappedWriter{f: f, cap: 100}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("want write error")
	}
}
