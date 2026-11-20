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
	"testing"
	"time"

	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
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
