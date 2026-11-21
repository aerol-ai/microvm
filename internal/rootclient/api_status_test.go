package rootclient_test

// The client's contract as the API sees it: a helper that is down, hung or
// gone gives a 503 (apihttp.Classify), on the helper's own calls and on
// containerd's, within the client's timeout. These are the review's proofs
// against c5dbb884e (M1, M2, M4), kept as regression tests; they live
// outside the package because apihttp imports it.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

func sock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "root.sock")
}

// client is the agent's client with the test process standing in for root.
func client(t *testing.T, sock string, timeout time.Duration) *rootclient.Client {
	t.Helper()
	c := rootclient.New(rootclient.Config{Socket: sock, Timeout: timeout, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func containerd(t *testing.T, c *rootclient.Client) *cntr.Client {
	t.Helper()
	ctr, err := cntr.New(c.Socket(), append(c.ContainerdOptions(), cntr.WithDefaultNamespace("aerolvm"))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Close() })
	return ctr
}

// want503 checks err is the helper unavailable, as the API answers it:
// 503, with a fixed message that does not name the socket.
func want503(t *testing.T, what string, err error, sock string) {
	t.Helper()
	cl := apihttp.Classify(err)
	if !errors.Is(err, rootclient.ErrUnavailable) || cl.Status != http.StatusServiceUnavailable {
		t.Fatalf("%s: %v; Is ErrUnavailable %v, status %d; want 503", what, err, errors.Is(err, rootclient.ErrUnavailable), cl.Status)
	}
	if strings.Contains(cl.Message, sock) {
		t.Fatalf("%s: the API message %q names the socket", what, cl.Message)
	}
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestContainerdCallsOnADownHelperAre503: with no helper, containerd's
// own calls through the client are 503, both the one containerd's client
// hands back as it is (Version) and one it rebuilds (Containers.List).
func TestContainerdCallsOnADownHelperAre503(t *testing.T) {
	p := sock(t)
	ctr := containerd(t, client(t, p, 300*time.Millisecond))
	_, err := ctr.Version(ctx5(t))
	want503(t, "Version", err, p)
	_, err = ctr.ContainerService().List(ctx5(t))
	want503(t, "Containers.List", err, p)
}

type fakeVersion struct {
	versionapi.UnimplementedVersionServer
}

func (fakeVersion) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "2.1.4"}, nil
}

type fakeHelper struct {
	rootdpb.UnimplementedRootHelperServer
	stuck bool // EnsureHost never answers
}

func (fakeHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "h", Api: rootdpb.APIVersion, Features: []string{rootdpb.FeatureEnsureHost}}, nil
}

func (f fakeHelper) EnsureHost(ctx context.Context, _ *rootdpb.EnsureHostRequest) (*rootdpb.EnsureHostResponse, error) {
	if f.stuck {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &rootdpb.EnsureHostResponse{}, nil
}

func serve(t *testing.T, p string, h fakeHelper) *grpc.Server {
	t.Helper()
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	rootdpb.RegisterRootHelperServer(srv, h)
	versionapi.RegisterVersionServer(srv, fakeVersion{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return srv
}

// TestContainerdCallsAfterTheHelperDiesAre503: the latch is set, then the
// helper dies. containerd's calls fail with 503, not the raw dial error as
// a 400.
func TestContainerdCallsAfterTheHelperDiesAre503(t *testing.T) {
	p := sock(t)
	srv := serve(t, p, fakeHelper{})
	ctr := containerd(t, client(t, p, 300*time.Millisecond))
	if _, err := ctr.Version(ctx5(t)); err != nil {
		t.Fatal(err)
	}
	srv.Stop()
	_ = os.Remove(p)
	time.Sleep(100 * time.Millisecond)
	_, err := ctr.Version(ctx5(t))
	want503(t, "Version", err, p)
	if !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("Version error %q does not say what failed", err)
	}
	_, err = ctr.ContainerService().List(ctx5(t))
	want503(t, "Containers.List", err, p)
}

// TestHungHelperFailsEveryCallerInTime: a helper that accepts and never
// answers fails each of many concurrent first callers within about one
// timeout, not one timeout per caller in turn.
func TestHungHelperFailsEveryCallerInTime(t *testing.T) {
	p := sock(t)
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	const timeout, n = 200 * time.Millisecond, 10
	c := client(t, p, timeout)
	var wg sync.WaitGroup
	durs := make([]time.Duration, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := c.Ensure(context.Background())
			durs[i] = time.Since(start)
			want503(t, "Ensure", err, p)
		}()
	}
	wg.Wait()
	for i, d := range durs {
		if d > 3*timeout {
			t.Fatalf("caller %d waited %v, %.1fx the timeout", i, d, float64(d)/float64(timeout))
		}
	}
}

// TestStuckCallIs503InTime: a helper stuck inside a call fails the call
// within the client's timeout when the caller set no deadline, and as a
// 503 when the caller's own deadline ends it.
func TestStuckCallIs503InTime(t *testing.T) {
	p := sock(t)
	serve(t, p, fakeHelper{stuck: true})
	c := client(t, p, 200*time.Millisecond)

	start := time.Now()
	err := c.EnsureHost(context.Background())
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("EnsureHost took %v with a 200ms timeout", d)
	}
	want503(t, "EnsureHost, no deadline", err, p)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	want503(t, "EnsureHost, the caller's deadline", c.EnsureHost(ctx), p)
}

// TestCallOnAConnectionClosedUnderIt: Close ends a call in flight; that is
// the client going away, a 503, not the caller cancelling.
func TestCallOnAConnectionClosedUnderIt(t *testing.T) {
	p := sock(t)
	serve(t, p, fakeHelper{stuck: true})
	c := client(t, p, 5*time.Second)
	if err := c.Ensure(ctx5(t)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.EnsureHost(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-done:
		want503(t, "EnsureHost after Close", err, p)
	case <-time.After(3 * time.Second):
		t.Fatal("EnsureHost still running after Close")
	}
}

type fakeEvents struct {
	eventsapi.UnimplementedEventsServer
	subscribed chan struct{}
}

func (f fakeEvents) Subscribe(_ *eventsapi.SubscribeRequest, ss eventsapi.Events_SubscribeServer) error {
	close(f.subscribed)
	<-ss.Context().Done()
	return nil
}

// TestEventStreamCutByAGoneHelperIs503: a subscription open when the
// helper dies ends with a 503, through containerd's own stream handling.
func TestEventStreamCutByAGoneHelperIs503(t *testing.T) {
	p := sock(t)
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	rootdpb.RegisterRootHelperServer(srv, fakeHelper{})
	ev := fakeEvents{subscribed: make(chan struct{})}
	eventsapi.RegisterEventsServer(srv, ev)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	ctr := containerd(t, client(t, p, time.Second))
	_, errs := ctr.EventService().Subscribe(ctx5(t))
	<-ev.subscribed
	srv.Stop()
	select {
	case err := <-errs:
		want503(t, "Subscribe", err, p)
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription outlived the helper")
	}
}

// slowHelper answers Version after slow, speaking api, and hands every
// other call to containerd.
type slowHelper struct {
	rootdpb.UnimplementedRootHelperServer
	api      uint32
	slow     time.Duration
	versions *atomic.Int32
}

func (h slowHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	if h.versions != nil {
		h.versions.Add(1)
	}
	time.Sleep(h.slow)
	return &rootdpb.VersionResponse{HelperVersion: "h", Api: h.api}, nil
}

func serveWith(t *testing.T, p string, h slowHelper, containerd grpc.StreamHandler) {
	t.Helper()
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(containerd))
	rootdpb.RegisterRootHelperServer(srv, h)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

func answerVersion(_ any, ss grpc.ServerStream) error {
	if err := ss.RecvMsg(&emptypb.Empty{}); err != nil {
		return err
	}
	return ss.SendMsg(&versionapi.VersionResponse{Version: "2.1.4"})
}

// TestSharedHandshakeOutlivesTheFirstCaller is review N1: callers share
// one handshake, and the one that started it giving up (its request
// cancelled) does not fail the others. Each still ends on its own
// context.
func TestSharedHandshakeOutlivesTheFirstCaller(t *testing.T) {
	p := sock(t)
	var versions atomic.Int32
	serveWith(t, p, slowHelper{api: rootdpb.APIVersion, slow: 300 * time.Millisecond, versions: &versions}, answerVersion)
	c := client(t, p, 2*time.Second)

	first, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- c.Ensure(first) }()
	time.Sleep(50 * time.Millisecond) // the first caller's handshake is in flight
	second := make(chan error, 1)
	go func() { second <- c.Ensure(ctx5(t)) }()
	time.Sleep(50 * time.Millisecond)
	cancelFirst()

	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the first caller got %v, want its own cancel", err)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("the first caller kept waiting after its cancel")
	}
	if err := <-second; err != nil {
		t.Fatalf("a caller with 5 s left failed with the first caller's cancel: %v", err)
	}
	if n := versions.Load(); n != 1 {
		t.Fatalf("%d handshakes, want 1 shared", n)
	}
}

// TestTooOldHelperOnContainerdPathIsUnsupported is review N5: on the
// containerd path a helper older than MinHelperAPI is unsupported, with
// its reason (upgrade it), as on the helper's own calls; not "unavailable".
func TestTooOldHelperOnContainerdPathIsUnsupported(t *testing.T) {
	p := sock(t)
	serveWith(t, p, slowHelper{api: rootdpb.MinHelperAPI - 1}, answerVersion)
	_, err := containerd(t, client(t, p, time.Second)).Version(ctx5(t))
	cl := apihttp.Classify(err)
	if !errors.Is(err, rootclient.ErrUnsupported) || errors.Is(err, rootclient.ErrUnavailable) || cl.Status != http.StatusServiceUnavailable {
		t.Fatalf("Version = %v; Is Unsupported %v, Is Unavailable %v, status %d", err,
			errors.Is(err, rootclient.ErrUnsupported), errors.Is(err, rootclient.ErrUnavailable), cl.Status)
	}
	if !strings.Contains(cl.Message, "upgrade the helper") {
		t.Fatalf("the API message %q does not say what to do", cl.Message)
	}
	// The same through containerd's error conversion.
	_, err = containerd(t, client(t, p, time.Second)).ContainerService().List(ctx5(t))
	if !errors.Is(err, rootclient.ErrUnsupported) {
		t.Fatalf("Containers.List = %v, want ErrUnsupported", err)
	}
}

// TestContainerdsOwnUnavailablePassesThrough is review N4: Unavailable
// that the helper answered (containerd's own error, passed on by the gate)
// keeps containerd's meaning; only a failure to reach the helper is the
// helper unavailable. This needs the helper's real server, which marks
// every call it answers.
func TestContainerdsOwnUnavailablePassesThrough(t *testing.T) {
	p := sock(t)
	dir, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	p = filepath.Join(dir, "root.sock")
	cfg := rootd.Config{
		Socket: p, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()),
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: "/var/lib/aerolvm-rootd/moves",
			Limits: rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
	}
	// The helper's own folders, which every helper needs (the file calls
	// are not what this test is about).
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Files = rootd.FileDirs{
		Hosts: filepath.Join(base, "state", "hosts"), Ready: filepath.Join(base, "run", "ready"),
		Runsc: filepath.Join(base, "state", "runsc"), AgentReady: filepath.Join(base, "agent", "ready"),
	}
	cfg.Policy.FIFODir = filepath.Join(base, "run", "fifo")
	cfg.Policy.HelperFileRoots = []string{cfg.Files.Hosts, cfg.Files.Ready}
	cfg.Policy.RunscConfigPaths = []string{filepath.Join(cfg.Files.Runsc, "config.toml"), filepath.Join(cfg.Files.Runsc, "restore.toml")}
	srv, err := rootd.New(cfg, rootd.Options{
		Containerd: func(_ any, ss grpc.ServerStream) error {
			_ = ss.RecvMsg(&emptypb.Empty{})
			return status.Error(codes.Unavailable, "snapshotter overlayfs not loaded")
		},
		Peer: egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })

	_, err = containerd(t, client(t, p, time.Second)).ContainerService().List(ctx5(t))
	if errors.Is(err, rootclient.ErrUnavailable) || !errdefs.IsUnavailable(err) || !strings.Contains(err.Error(), "snapshotter overlayfs not loaded") {
		t.Fatalf("Containers.List = %v; Is helper unavailable %v; want containerd's own Unavailable", err, errors.Is(err, rootclient.ErrUnavailable))
	}
	if strings.Contains(apihttp.Classify(err).Message, "root helper") {
		t.Fatalf("the API blames the helper: %q", apihttp.Classify(err).Message)
	}
}

// TestDeadlinesOnContainerdPathAre503 is review N3: a deadline that runs
// out on the containerd path is a 503, as on the helper's own calls.
func TestDeadlinesOnContainerdPathAre503(t *testing.T) {
	t.Run("the helper stuck in a call", func(t *testing.T) {
		p := sock(t)
		serveWith(t, p, slowHelper{api: rootdpb.APIVersion}, func(_ any, ss grpc.ServerStream) error {
			<-ss.Context().Done()
			return ss.Context().Err()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := containerd(t, client(t, p, time.Second)).ContainerService().List(ctx)
		want503(t, "Containers.List", err, p)
	})
	t.Run("a hung handshake and a shorter caller deadline", func(t *testing.T) {
		p := sock(t)
		ln, err := net.Listen("unix", p)
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
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err = containerd(t, client(t, p, 2*time.Second)).ContainerService().List(ctx)
		want503(t, "Containers.List", err, p)
	})
}
