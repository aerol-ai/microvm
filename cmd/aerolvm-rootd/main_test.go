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

	"github.com/aerol-ai/microvm/pkg/wasm/worker"
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
func helperEnv(t *testing.T, dir, namespace string) func(string) string {
	// The helper's own folders sit apart from both sockets' folder, in
	// which no sandbox may bind anything.
	files := shortDir(t)
	e := map[string]string{
		"SB_ROOTD_SOCKET":         filepath.Join(dir, "root.sock"),
		"SB_ROOTD_SOCKET_GROUP":   strconv.Itoa(os.Getgid()),
		"SB_ROOTD_AGENT_UID":      "54321",
		"SB_CONTAINERD_SOCKET":    filepath.Join(dir, "containerd.sock"),
		"SB_CONTAINERD_NAMESPACE": namespace,
		"SB_HOST_MEMORY_MB":       "1024",
		// The helper's own folders, made at start.
		"SB_ROOTD_STATE_DIR": filepath.Join(files, "state"),
		"SB_ROOTD_FIFO_DIR":  filepath.Join(files, "run", "fifo"),
		"SB_ROOTD_READY_DIR": filepath.Join(files, "run", "ready"),
		"SB_MOUNTS_CRED_DIR": filepath.Join(files, "agent"),
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
	go func() { done <- serve(ctx, cfg, opts, nil, slog.New(slog.NewTextHandler(logs, nil))) }()
	// serve makes the helper's folders, then its socket, in the background:
	// wait for the socket, or the first dial below races it.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Lstat(cfg.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no socket at %s", cfg.Socket)
		}
	}
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
	cfg, err := rootd.ConfigFromEnv(helperEnv(t, dir, "tenant-x"))
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
	cfg, err := rootd.ConfigFromEnv(helperEnv(t, dir, "aerolvm"))
	if err != nil {
		t.Fatal(err)
	}
	serveContainerd(t, cfg.ContainerdSocket, &fakeContainerd{labels: map[string]string{"containerd.io/defaults/runtime": "io.containerd.runc.v2"}})
	err = serve(ctxT(t), cfg, rootd.Options{Peer: func(net.Conn) error { return nil }}, nil, slog.New(slog.DiscardHandler))
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
		cfg, err := rootd.ConfigFromEnv(helperEnv(t, dir, "aerolvm"))
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
		cfg, err := rootd.ConfigFromEnv(helperEnv(t, dir, "aerolvm"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := serve(ctx, cfg, rootd.Options{Peer: func(net.Conn) error { return nil }}, nil, slog.New(slog.DiscardHandler)); err != nil {
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
	go func() { done <- run(ctx, helperEnv(t, dir, "aerolvm"), slog.New(slog.DiscardHandler)) }()
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

// TestNetnsBindingWaitsForTheServer: the gate is built before the server
// it asks; until the server is set, no namespace is vouched for.
func TestNetnsBindingWaitsForTheServer(t *testing.T) {
	var b netnsBinding
	if ok, err := b.Bound(context.Background(), "aerol-netns-0", "sb-1"); ok || err == nil {
		t.Fatalf("an unset binding = %v, %v", ok, err)
	}
	env := helperEnv(t, shortDir(t), "aerolvm")
	// No CNI plugins, wherever the test runs (a node with /opt/cni/bin
	// would open the network, and vouch for nothing without an error).
	noCNI := filepath.Join(t.TempDir(), "no-cni")
	cfg, err := rootd.ConfigFromEnv(func(k string) string {
		if k == "SB_CONTAINERD_CNI_PLUGIN_DIR" {
			return noCNI
		}
		return env(k)
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := rootd.New(cfg, rootd.Options{
		Containerd: func(any, grpc.ServerStream) error { return nil },
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	b.srv.Store(srv)
	// This server has no network configuration, so it vouches for nothing,
	// and says why.
	if ok, err := b.Bound(context.Background(), "aerol-netns-0", "sb-1"); ok || err == nil || !strings.Contains(err.Error(), "network") {
		t.Fatalf("a set binding = %v, %v", ok, err)
	}
}

// TestShimCode: the helper's own binary is the V8 jail's shim (M1 PR 9);
// a shim that fails reports why, with its own exit code.
func TestShimCode(t *testing.T) {
	old := runJailShim
	t.Cleanup(func() { runJailShim = old })
	var got []string
	runJailShim = func(args []string) error { got = args; return nil }
	var out bytes.Buffer
	if code := shimCode([]string{"x"}, &out); code != 0 || len(got) != 1 || got[0] != "x" {
		t.Fatalf("shimCode = %d with %v", code, got)
	}
	runJailShim = func([]string) error { return errors.New("chroot: denied") }
	if code := shimCode(nil, &out); code != 125 || !strings.Contains(out.String(), "chroot: denied") {
		t.Fatalf("shimCode = %d, output %q", code, out.String())
	}
}

// TestWasmHostCode: the helper's own binary is the WASM hosts' too.
func TestWasmHostCode(t *testing.T) {
	ow, or := runWasmWorker, runWasmResident
	t.Cleanup(func() { runWasmWorker, runWasmResident = ow, or })
	var ran string
	runWasmWorker = func(a []string) error { ran = "worker " + a[0]; return nil }
	runWasmResident = func(a []string) error { ran = "resident " + a[0]; return errors.New("bind: in use") }
	var out bytes.Buffer
	if code := wasmHostCode(worker.WorkerFlag, []string{"/s/w.sock"}, &out); code != 0 || ran != "worker /s/w.sock" {
		t.Fatalf("worker: %d %q", code, ran)
	}
	if code := wasmHostCode(worker.ResidentHostFlag, []string{"/s/r.sock"}, &out); code != 1 || ran != "resident /s/r.sock" ||
		!strings.Contains(out.String(), "bind: in use") {
		t.Fatalf("resident: %d %q %q", code, ran, out.String())
	}
}
