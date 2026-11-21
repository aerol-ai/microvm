package rootclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/version"
)

// sockPath is a socket path short enough for sun_path (104 bytes on
// macOS), which t.TempDir's often is not. The socket's folder holds the
// socket alone, as the helper requires; realHelper lays the helper's other
// folders out beside it.
func sockPath(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// The helper follows no link to its socket (macOS: /var is one).
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d, "s"), 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, "s", "root.sock")
}

// fakeHelper is a helper of any version: it answers Version with resp and
// EnsureHost with ensureErr, and counts both.
type fakeHelper struct {
	rootdpb.UnimplementedRootHelperServer
	resp      *rootdpb.VersionResponse
	ensureErr error
	slow      time.Duration // each Version takes this long

	mu          sync.Mutex
	versions    int
	ensureHosts int
	lastReq     *rootdpb.VersionRequest
}

func (f *fakeHelper) Version(_ context.Context, req *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	time.Sleep(f.slow)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions++
	f.lastReq = req
	return f.resp, nil
}

func (f *fakeHelper) EnsureHost(context.Context, *rootdpb.EnsureHostRequest) (*rootdpb.EnsureHostResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureHosts++
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	return &rootdpb.EnsureHostResponse{}, nil
}

func (f *fakeHelper) counts() (versions, ensureHosts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.versions, f.ensureHosts
}

func helperAt(api uint32, features ...string) *fakeHelper {
	return &fakeHelper{resp: &rootdpb.VersionResponse{HelperVersion: "v-test", Api: api, Features: features}}
}

// running is a fake helper process on a socket.
type running struct {
	srv     *grpc.Server
	accepts atomic.Int32
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func serveFake(t *testing.T, sock string, f *fakeHelper) *running {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	r := &running{srv: grpc.NewServer()}
	rootdpb.RegisterRootHelperServer(r.srv, f)
	go func() { _ = r.srv.Serve(countingListener{ln, &r.accepts}) }()
	t.Cleanup(r.srv.Stop)
	return r
}

func newClient(t *testing.T, sock string) *Client {
	t.Helper()
	// The test's own process serves the fakes, so it stands in for root.
	c := New(Config{Socket: sock, Timeout: 500 * time.Millisecond, AgentVersion: "agent-test", HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestConcurrentFirstCallsDialOnce: a burst of first callers shares one
// dial and one handshake, and after it every call is the latch's atomic
// load (the EnsureLayer4Ready shape).
func TestConcurrentFirstCallsDialOnce(t *testing.T) {
	sock := sockPath(t)
	f := helperAt(rootdpb.APIVersion)
	f.slow = 20 * time.Millisecond // keep the first handshake open while the rest arrive
	h := serveFake(t, sock, f)
	c := newClient(t, sock)

	const n = 32
	start := make(chan struct{})
	errs := make(chan error, n)
	for range n {
		go func() {
			<-start
			errs <- c.Ensure(ctxT(t))
		}()
	}
	close(start)
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for range 10 {
		if err := c.Ensure(ctxT(t)); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := f.counts(); v != 1 {
		t.Fatalf("%d handshakes, want 1", v)
	}
	if a := h.accepts.Load(); a != 1 {
		t.Fatalf("%d connections, want 1", a)
	}
	if d := c.dials.Load(); d != 1 {
		t.Fatalf("%d dials, want 1", d)
	}
	if f.lastReq.GetAgentVersion() != "agent-test" || f.lastReq.GetAgentApi() != rootdpb.APIVersion {
		t.Fatalf("handshake sent %v", f.lastReq)
	}
}

// TestFailedBootstrapRetriesLater: a helper that is not up yet fails the
// call and leaves the latch unset; the next call, once it is up, succeeds
// at once rather than after gRPC's reconnect backoff.
func TestFailedBootstrapRetriesLater(t *testing.T) {
	sock := sockPath(t)
	c := newClient(t, sock)
	if err := c.Ensure(ctxT(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ensure with no helper = %v, want ErrUnavailable", err)
	}
	if c.ready.Load() {
		t.Fatal("a failed handshake must not latch")
	}
	if _, ok := c.Info(); ok {
		t.Fatal("no Info before a handshake")
	}
	f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
	serveFake(t, sock, f)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatalf("Ensure once the helper is up: %v", err)
	}
	info, ok := c.Info()
	if !ok || info.HelperVersion != "v-test" || info.API != rootdpb.APIVersion || !info.Has(rootdpb.FeatureEnsureHost) {
		t.Fatalf("Info = %+v, %v", info, ok)
	}
}

// TestDownHelperFailsFast: every way of being down ends in ErrUnavailable
// within the client's timeout, never a hang.
func TestDownHelperFailsFast(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, sock string)
	}{
		{"no socket", func(*testing.T, string) {}},
		{"a socket nobody listens on", func(t *testing.T, sock string) {
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			l.SetUnlinkOnClose(false)
			_ = l.Close()
		}},
		{"a helper that accepts and never answers", func(t *testing.T, sock string) {
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { _ = c.Close() })
				}
			}()
		}},
		{"a helper that refuses this peer", func(t *testing.T, sock string) {
			srv := realHelper(t, sock, func(o *rootd.Options) {
				o.Peer = func(net.Conn) error { return errors.New("peer uid 1 not allowed") }
			})
			_ = srv
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := sockPath(t)
			tc.setup(t, sock)
			c := newClient(t, sock) // 500ms timeout
			start := time.Now()
			err := c.Ensure(context.Background())
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), sock) {
				t.Fatalf("Ensure = %v, want ErrUnavailable naming the socket", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("Ensure took %v; a down helper must fail within the timeout", d)
			}
		})
	}
}

// TestHelperGoneAfterHandshake: once latched, a helper that dies fails
// calls with ErrUnavailable at once, and the client reaches it again when
// it is back, as after a restart by the supervisor.
func TestHelperGoneAfterHandshake(t *testing.T) {
	sock := sockPath(t)
	f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
	h := serveFake(t, sock, f)
	c := newClient(t, sock)
	if err := c.EnsureHost(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	h.srv.Stop()
	_ = os.Remove(sock)
	start := time.Now()
	if err := c.EnsureHost(ctxT(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("EnsureHost with the helper gone = %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	serveFake(t, sock, f)
	eventually(t, func() error { return c.EnsureHost(ctxT(t)) })
}

// TestOlderHelper: agent N with helper N-1 (eng review D5). A call the
// helper lacks is refused here, before anything is sent, with a reason
// that names the call and the helper; a helper older than MinHelperAPI is
// refused whole and not latched; a newer helper is fine.
func TestOlderHelper(t *testing.T) {
	t.Run("lacks a call", func(t *testing.T) {
		sock := sockPath(t)
		f := helperAt(rootdpb.MinHelperAPI) // one release back: no EnsureHost
		serveFake(t, sock, f)
		c := newClient(t, sock)
		err := c.EnsureHost(ctxT(t))
		var ue *UnsupportedError
		if !errors.As(err, &ue) || !errors.Is(err, ErrUnsupported) || ue.Feature != rootdpb.FeatureEnsureHost {
			t.Fatalf("EnsureHost = %v, want an UnsupportedError for EnsureHost", err)
		}
		for _, want := range []string{"v-test", "does not have EnsureHost", "newer helper"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%q does not say %q", err, want)
			}
		}
		if _, sent := f.counts(); sent != 0 {
			t.Fatal("the call reached a helper that lacks it")
		}
		// The connection is the same one, so asking again sends nothing.
		for range 3 {
			_ = c.Require(ctxT(t), "Realize")
		}
		if v, _ := f.counts(); v != 1 {
			t.Fatalf("%d handshakes for misses on a live connection, want 1", v)
		}
	})
	t.Run("older than MinHelperAPI", func(t *testing.T) {
		sock := sockPath(t)
		f := helperAt(rootdpb.MinHelperAPI-1, rootdpb.FeatureEnsureHost)
		serveFake(t, sock, f)
		c := newClient(t, sock)
		err := c.Ensure(ctxT(t))
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Feature != "" || !strings.Contains(err.Error(), "upgrade the helper") {
			t.Fatalf("Ensure = %v, want the whole helper refused", err)
		}
		if c.ready.Load() {
			t.Fatal("a refused helper must not latch")
		}
		_ = c.Ensure(ctxT(t))
		if v, _ := f.counts(); v != 2 {
			t.Fatalf("%d handshakes, want 2: a later call asks again", v)
		}
	})
	t.Run("newer helper", func(t *testing.T) {
		sock := sockPath(t)
		serveFake(t, sock, helperAt(rootdpb.APIVersion+1, rootdpb.FeatureEnsureHost, "SomethingNew"))
		if err := newClient(t, sock).EnsureHost(ctxT(t)); err != nil {
			t.Fatal(err)
		}
	})
}

// TestSwappedHelperIsAskedAgain: the supervisor swaps in the newer helper
// the agent staged (eng review D4), closing the old one's connections. A
// call the old helper lacked works on the new one without restarting the
// agent.
func TestSwappedHelperIsAskedAgain(t *testing.T) {
	sock := sockPath(t)
	old := serveFake(t, sock, helperAt(rootdpb.MinHelperAPI))
	c := newClient(t, sock)
	if err := c.EnsureHost(ctxT(t)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EnsureHost on the old helper = %v", err)
	}
	old.srv.Stop()
	_ = os.Remove(sock)
	f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
	serveFake(t, sock, f)
	eventually(t, func() error { return c.EnsureHost(ctxT(t)) })
	if _, sent := f.counts(); sent != 1 {
		t.Fatalf("the new helper got %d EnsureHost calls, want 1", sent)
	}
}

// TestCallErrors: what the helper answers a typed call becomes the
// client's error.
func TestCallErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		is   error
		code codes.Code
	}{
		{"ok", nil, nil, codes.OK},
		{"unimplemented after all", status.Error(codes.Unimplemented, "no"), ErrUnsupported, codes.Unknown},
		{"unavailable", status.Error(codes.Unavailable, "restarting"), ErrUnavailable, codes.Unknown},
		{"refused", rootdpb.Refused(codes.PermissionDenied, "not_agent_socket", "aerolvm root helper refused"), ErrRefused, codes.Unknown},
		// A PermissionDenied without the helper's refusal mark is passed
		// on as it is: only the helper's own mark makes a refusal.
		{"denied, unmarked", status.Error(codes.PermissionDenied, "denied"), nil, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := sockPath(t)
			f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
			f.ensureErr = tc.err
			serveFake(t, sock, f)
			err := newClient(t, sock).EnsureHost(ctxT(t))
			switch {
			case tc.err == nil:
				if err != nil {
					t.Fatal(err)
				}
			case tc.is != nil:
				if !errors.Is(err, tc.is) {
					t.Fatalf("err %v, want %v", err, tc.is)
				}
			default:
				if status.Code(err) != tc.code {
					t.Fatalf("err %v, want code %v", err, tc.code)
				}
			}
		})
	}
}

// helperFiles lays the helper's own folders out under base, as
// rootd.ConfigFromEnv lays them out under its state and run folders.
func helperFiles(t testing.TB, c *rootd.Config, base string) {
	t.Helper()
	c.Files = rootd.FileDirs{
		Hosts:      filepath.Join(base, "state", "hosts"),
		Ready:      filepath.Join(base, "run", "ready"),
		Runsc:      filepath.Join(base, "state", "runsc"),
		AgentReady: filepath.Join(base, "agent", "ready"),
	}
	c.Policy.FIFODir = filepath.Join(base, "run", "fifo")
	c.Policy.HelperFileRoots = []string{c.Files.Hosts, c.Files.Ready}
	c.Policy.RunscConfigPaths = []string{filepath.Join(c.Files.Runsc, "config.toml"), filepath.Join(c.Files.Runsc, "restore.toml")}
}

// realHelper serves internal/rootd's server on sock, its containerd side
// answering containerd's Version as containerd 2.1.4 would. The peer check
// is egress.UnixPeerCheck for this uid: the real one on Linux.
func realHelper(t testing.TB, sock string, mutate func(*rootd.Options)) *rootd.Server {
	t.Helper()
	opts := rootd.Options{
		Containerd: func(_ any, ss grpc.ServerStream) error {
			if name, _ := grpc.MethodFromServerStream(ss); name != "/containerd.services.version.v1.Version/Version" {
				return status.Errorf(codes.PermissionDenied, "not %s", name)
			}
			if err := ss.RecvMsg(&emptypb.Empty{}); err != nil {
				return err
			}
			return ss.SendMsg(&versionapi.VersionResponse{Version: "2.1.4", Revision: "fake"})
		},
		Peer: egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
	}
	if mutate != nil {
		mutate(&opts)
	}
	cfg := rootd.Config{
		Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()),
		Firewall: rootd.FirewallConfig{NodePorts: []rootpolicy.NodePort{{Proto: "tcp", Port: 15080}}},
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: "/var/lib/sandboxd/containerd/moves",
			Limits: rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
	}
	helperFiles(t, &cfg, filepath.Dir(filepath.Dir(sock)))
	srv, err := rootd.New(cfg, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return srv
}

// TestRealHelper: the agent's client against the helper's own server, on
// one socket: the handshake, the placeholder refused before it is sent,
// and containerd's Go client reaching containerd's API through the dialer.
func TestRealHelper(t *testing.T) {
	sock := sockPath(t)
	realHelper(t, sock, nil)
	c := newClient(t, sock)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if info, _ := c.Info(); info.HelperVersion != version.Version || info.API != rootdpb.APIVersion ||
		!info.Has(rootdpb.FeatureEnsureHostFiles) || info.Has(rootdpb.FeatureEnsureHost) {
		t.Fatalf("Info = %+v", info)
	}
	if err := c.EnsureHost(ctxT(t)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EnsureHost = %v, want ErrUnsupported: no helper builds it yet", err)
	}

	ctr, err := cntr.New(c.Socket(), append(c.ContainerdOptions(), cntr.WithDefaultNamespace("aerolvm"))...)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Close()
	v, err := ctr.Version(ctxT(t))
	if err != nil || v.Version != "2.1.4" {
		t.Fatalf("containerd Version through the helper = %v, %v", v, err)
	}
}

// TestContainerdDialFailsFast: with the helper down, containerd's client
// fails at once and says why, instead of waiting out its own timeout.
func TestContainerdDialFailsFast(t *testing.T) {
	c := newClient(t, sockPath(t))
	ctr, err := cntr.New(c.Socket(), c.ContainerdOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Close()
	start := time.Now()
	_, err = ctr.Version(ctxT(t))
	if !errors.Is(err, ErrUnavailable) || status.Code(err) != codes.Unavailable {
		t.Fatalf("Version = %v, want ErrUnavailable with code Unavailable", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

// TestDefaultSocketIsTheHelpers: the agent dials where the helper listens.
func TestDefaultSocketIsTheHelpers(t *testing.T) {
	if DefaultSocket != rootd.DefaultSocket {
		t.Fatalf("agent dials %s, the helper listens on %s", DefaultSocket, rootd.DefaultSocket)
	}
}

// TestServerMustBeRoot is review M3: on Linux the client reads who serves
// the socket and talks only to the configured uid (root, outside tests).
// Anyone else that binds the path gets nothing: no handshake, and no
// containerd call.
func TestServerMustBeRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux only")
	}
	sock := sockPath(t)
	f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
	serveFake(t, sock, f)
	c := New(Config{Socket: sock, Timeout: 500 * time.Millisecond, HelperUID: uint32(os.Getuid()) + 1})
	defer c.Close()
	err := c.Ensure(ctxT(t))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "not the helper") {
		t.Fatalf("Ensure against a non-root server = %v", err)
	}
	if conn, err := c.DialContainerd(ctxT(t), ""); err == nil {
		_ = conn.Close()
		t.Fatal("DialContainerd reached a non-root server")
	}
	if v, _ := f.counts(); v != 0 {
		t.Fatalf("%d handshakes reached the impostor", v)
	}
}

func TestClose(t *testing.T) {
	sock := sockPath(t)
	serveFake(t, sock, helperAt(rootdpb.APIVersion))
	c := newClient(t, sock)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ensure(ctxT(t)); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Ensure after Close = %v", err)
	}
	if err := c.Require(ctxT(t), rootdpb.FeatureEnsureHost); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Require after Close = %v", err)
	}
	if _, ok := c.Info(); ok {
		t.Fatal("Info after Close")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewDefaults(t *testing.T) {
	c := New(Config{})
	if c.Socket() != DefaultSocket || c.timeout != DefaultTimeout || c.agentVersion != version.Version {
		t.Fatalf("defaults %q %v %q", c.Socket(), c.timeout, c.agentVersion)
	}
}

// eventually retries fn for a few seconds: a client notices a closed
// connection, and redials, on gRPC's own time.
func eventually(t *testing.T, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := fn()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still failing: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hangingSocket accepts connections and never answers, like a helper that
// is stuck.
func hangingSocket(t *testing.T, sock string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
}

// TestWaitingCallers: callers that arrive during a handshake wait for it,
// but no longer than their own context, and Close ends it for everyone.
func TestWaitingCallers(t *testing.T) {
	t.Run("a waiter's own deadline", func(t *testing.T) {
		sock := sockPath(t)
		hangingSocket(t, sock)
		c := New(Config{Socket: sock, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
		defer c.Close()
		go func() { _ = c.Ensure(context.Background()) }()
		eventually(t, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.inflight == nil {
				return errors.New("no handshake in flight yet")
			}
			return nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := c.Ensure(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Ensure = %v, want ErrUnavailable", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("the waiter waited %v past its 100ms deadline", d)
		}
	})
	t.Run("Close during a handshake", func(t *testing.T) {
		sock := sockPath(t)
		hangingSocket(t, sock)
		c := New(Config{Socket: sock, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
		done := make(chan error, 1)
		go func() { done <- c.Ensure(context.Background()) }()
		eventually(t, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.inflight == nil {
				return errors.New("no handshake in flight yet")
			}
			return nil
		})
		_ = c.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "closed") {
				t.Fatalf("Ensure = %v, want the closed client's ErrUnavailable", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not end the handshake")
		}
	})
}

// TestRefreshOnAGoneHelper: a missing call on a connection that has
// dropped asks the helper again; with the helper gone that is
// ErrUnavailable, and the next call dials afresh.
func TestRefreshOnAGoneHelper(t *testing.T) {
	sock := sockPath(t)
	h := serveFake(t, sock, helperAt(rootdpb.MinHelperAPI))
	c := newClient(t, sock)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	h.srv.Stop()
	_ = os.Remove(sock)
	eventually(t, func() error {
		if err := c.Require(ctxT(t), rootdpb.FeatureEnsureHost); !errors.Is(err, ErrUnavailable) {
			return fmt.Errorf("Require = %v, want ErrUnavailable", err)
		}
		return nil
	})
	if c.ready.Load() {
		t.Fatal("a failed refresh must unlatch")
	}
}
