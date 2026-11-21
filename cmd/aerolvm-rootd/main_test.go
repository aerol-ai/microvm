package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fakeContainerd answers the two calls the helper and these tests make:
// the namespace check at start and containerd's Version.
type fakeContainerd struct {
	namespacesapi.UnimplementedNamespacesServer
	versionapi.UnimplementedVersionServer
	labels map[string]string // the namespace's labels; nil: no namespace yet
}

func (f *fakeContainerd) Get(_ context.Context, r *namespacesapi.GetNamespaceRequest) (*namespacesapi.GetNamespaceResponse, error) {
	if f.labels == nil {
		return nil, status.Error(codes.NotFound, "no namespace")
	}
	return &namespacesapi.GetNamespaceResponse{Namespace: &namespacesapi.Namespace{Name: r.GetName(), Labels: f.labels}}, nil
}

func (f *fakeContainerd) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "2.1.4", Revision: "fake"}, nil
}

func serveContainerd(t *testing.T, sock string, f *fakeContainerd) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	namespacesapi.RegisterNamespacesServer(srv, f)
	versionapi.RegisterVersionServer(srv, f)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rm") // short enough for sun_path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// The helper follows no link to its socket (macOS: /var is one).
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// helperEnv is the helper's own environment for a test: its socket and
// containerd's in dir, the namespace given.
func helperEnv(dir, namespace string) func(string) string {
	e := map[string]string{
		"SB_ROOTD_SOCKET":         filepath.Join(dir, "root.sock"),
		"SB_ROOTD_SOCKET_GROUP":   strconv.Itoa(os.Getgid()),
		"SB_ROOTD_AGENT_UID":      "54321",
		"SB_CONTAINERD_SOCKET":    filepath.Join(dir, "containerd.sock"),
		"SB_CONTAINERD_NAMESPACE": namespace,
		"SB_HOST_MEMORY_MB":       "1024",
	}
	return func(k string) string { return e[k] }
}

// syncBuffer is a log sink the server goroutines and the test share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// serving runs serve in the background and stops it at cleanup, checking
// it returned nil.
func serving(t *testing.T, cfg rootd.Config, logs *syncBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// The test process is the agent here; on Linux this is the real
	// SO_PEERCRED check for its uid.
	opts := rootd.Options{Peer: egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, "")}
	go func() { done <- serve(ctx, cfg, opts, slog.New(slog.NewTextHandler(logs, nil))) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve = %v", err)
		}
		if _, err := os.Lstat(cfg.Socket); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket left behind: %v", err)
		}
	})
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestPolicyComesFromTheHelpersEnv: the gate the helper serves checks
// against the policy its own environment set, here a namespace that is
// not sandboxd's default, and the agent cannot argue: a containerd call in
// any other namespace is refused, and the refusal is logged.
func TestPolicyComesFromTheHelpersEnv(t *testing.T) {
	dir := shortDir(t)
	cfg, err := rootd.ConfigFromEnv(helperEnv(dir, "tenant-x"))
	if err != nil {
		t.Fatal(err)
	}
	serveContainerd(t, cfg.ContainerdSocket, &fakeContainerd{})
	var logs syncBuffer
	serving(t, cfg, &logs)

	agent := rootclient.New(rootclient.Config{Socket: cfg.Socket, HelperUID: uint32(os.Getuid())})
	defer agent.Close()
	for _, tc := range []struct {
		namespace string
		refused   bool
	}{
		{"tenant-x", false},
		{"aerolvm", true},
	} {
		ctr, err := cntr.New(agent.Socket(), append(agent.ContainerdOptions(), cntr.WithDefaultNamespace(tc.namespace))...)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ctr.Version(ctxT(t))
		_ = ctr.Close()
		if tc.refused != (status.Code(err) == codes.PermissionDenied) || (!tc.refused && v.Version != "2.1.4") {
			t.Fatalf("Version in %s = %v, %v; refused want %v", tc.namespace, v, err, tc.refused)
		}
	}
	if !strings.Contains(logs.String(), "root helper refused") || !strings.Contains(logs.String(), string(rootpolicy.RuleNamespace)) {
		t.Fatalf("the refusal was not logged:\n%s", logs.String())
	}
}

// TestServeRefusesADefaultingNamespace: a namespace whose labels set a
// default runtime would change every create, so the helper does not
// serve over it.
func TestServeRefusesADefaultingNamespace(t *testing.T) {
	dir := shortDir(t)
	cfg, err := rootd.ConfigFromEnv(helperEnv(dir, "aerolvm"))
	if err != nil {
		t.Fatal(err)
	}
	serveContainerd(t, cfg.ContainerdSocket, &fakeContainerd{labels: map[string]string{"containerd.io/defaults/runtime": "io.containerd.runc.v2"}})
	err = serve(ctxT(t), cfg, rootd.Options{Peer: func(net.Conn) error { return nil }}, slog.New(slog.DiscardHandler))
	if rootpolicy.RuleOf(err) != rootpolicy.RuleNamespace {
		t.Fatalf("serve = %v, want the namespace rule", err)
	}
	if _, err := os.Lstat(cfg.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}

// TestServeWaitsForContainerd: the helper and containerd start together,
// so the helper waits for containerd's answer before it serves, and a stop
// while it waits is a clean exit.
func TestServeWaitsForContainerd(t *testing.T) {
	old := containerdRetry
	containerdRetry = 20 * time.Millisecond
	t.Cleanup(func() { containerdRetry = old })

	t.Run("containerd comes up", func(t *testing.T) {
		dir := shortDir(t)
		cfg, err := rootd.ConfigFromEnv(helperEnv(dir, "aerolvm"))
		if err != nil {
			t.Fatal(err)
		}
		var logs syncBuffer
		serving(t, cfg, &logs)
		time.Sleep(50 * time.Millisecond)
		serveContainerd(t, cfg.ContainerdSocket, &fakeContainerd{})
		agent := rootclient.New(rootclient.Config{Socket: cfg.Socket, Timeout: 200 * time.Millisecond, HelperUID: uint32(os.Getuid())})
		defer agent.Close()
		deadline := time.Now().Add(5 * time.Second)
		for agent.Ensure(ctxT(t)) != nil {
			if time.Now().After(deadline) {
				t.Fatal("the helper never served")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !strings.Contains(logs.String(), "waiting for containerd") {
			t.Fatalf("no wait was logged:\n%s", logs.String())
		}
	})
	t.Run("stopped while waiting", func(t *testing.T) {
		dir := shortDir(t)
		cfg, err := rootd.ConfigFromEnv(helperEnv(dir, "aerolvm"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := serve(ctx, cfg, rootd.Options{Peer: func(net.Conn) error { return nil }}, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("serve = %v, want a clean stop", err)
		}
	})
}

// TestRun: run reads the helper's environment; a bad one stops it, and
// off Linux, where there is no SO_PEERCRED, so does the platform.
func TestRun(t *testing.T) {
	bad := func(k string) string {
		switch k {
		case "SB_ROOTD_AGENT_UID":
			return "0"
		case "SB_ROOTD_SOCKET_GROUP":
			return strconv.Itoa(os.Getgid())
		}
		return ""
	}
	var stderr bytes.Buffer
	if code := mainCode(bad, &stderr); code != 1 || !strings.Contains(stderr.String(), "must not run as root") {
		t.Fatalf("a root agent: exit %d, log %q", code, stderr.String())
	}
	dir := shortDir(t)
	serveContainerd(t, filepath.Join(dir, "containerd.sock"), &fakeContainerd{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, helperEnv(dir, "aerolvm"), slog.New(slog.DiscardHandler)) }()
	if runtime.GOOS != "linux" {
		if err := <-done; err == nil || !strings.Contains(err.Error(), "Linux only") {
			t.Fatalf("run off Linux = %v", err)
		}
		cancel()
		return
	}
	sock := filepath.Join(dir, "root.sock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("run never made its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
}
