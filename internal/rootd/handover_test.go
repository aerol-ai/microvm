package rootd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// supervisorSocket is the socket the supervisor owns, and a way to hand a
// copy of it to each helper, as a child inherits it.
type supervisorSocket struct {
	path string
	f    *os.File
}

func newSupervisorSocket(t *testing.T) supervisorSocket {
	t.Helper()
	path := filepath.Join(shortDir(t), "root.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close()
	t.Cleanup(func() { _ = f.Close() })
	return supervisorSocket{path: path, f: f}
}

func (s supervisorSocket) inherit(t *testing.T) *net.UnixListener {
	t.Helper()
	ln, err := net.FileListener(s.f)
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	return ul
}

func serveOn(t *testing.T, cfg Config, ln *net.UnixListener, containerd *stubContainerd) (*Server, <-chan error) {
	t.Helper()
	srv, err := New(cfg, Options{Containerd: containerd.handle, Peer: func(net.Conn) error { return nil }, Listener: ln}, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	return srv, served
}

// TestHandoverOnInheritedSocket: a helper serves the supervisor's socket
// and leaves it when it stops; an agent that connects between two helpers
// waits in the socket's backlog and is served by the next helper, never
// by both (outside review O6).
func TestHandoverOnInheritedSocket(t *testing.T) {
	sock := newSupervisorSocket(t)
	cfg := testConfig(t)
	cfg.Socket = sock.path
	containerd := &stubContainerd{}
	conn := dialSocket(t, sock.path)
	client := rootdpb.NewRootHelperClient(conn)

	old, oldServed := serveOn(t, cfg, sock.inherit(t), containerd)
	if _, err := client.Version(callCtx(t), &rootdpb.VersionRequest{}); err != nil {
		t.Fatalf("Version on the first helper: %v", err)
	}
	old.Shutdown(callCtx(t))
	if err := <-oldServed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock.path); err != nil {
		t.Fatalf("the helper removed the supervisor's socket: %v", err)
	}

	// No helper serves now: a call waits in the backlog for the next one.
	answered := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := client.Version(ctx, &rootdpb.VersionRequest{}, grpc.WaitForReady(true))
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("a call was answered with no helper serving: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	next, nextServed := serveOn(t, testConfigAt(t, cfg), sock.inherit(t), containerd)
	if err := <-answered; err != nil {
		t.Fatalf("the waiting call on the next helper: %v", err)
	}
	next.Shutdown(callCtx(t))
	if err := <-nextServed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock.path); err != nil {
		t.Fatalf("the socket is gone after the second helper: %v", err)
	}
}

// testConfigAt is cfg with fresh folders for a second helper's files: the
// folders are opened at New, and the first helper closed its handles.
func testConfigAt(t *testing.T, cfg Config) Config {
	t.Helper()
	next := testConfig(t)
	next.Socket = cfg.Socket
	return next
}

// TestDrainEndsEndlessCallsFirst: a stop ends the event subscription at
// once, so it never holds a swap to its deadline, and still waits for the
// calls in flight that end by themselves.
func TestDrainEndsEndlessCallsFirst(t *testing.T) {
	r := newRig(t, nil)
	subscribed, getting := make(chan struct{}), make(chan struct{})
	r.containerd.hold = func(ctx context.Context, method string) error {
		switch method {
		case "/containerd.services.events.v1.Events/Subscribe":
			close(subscribed)
			<-ctx.Done()
			return ctx.Err()
		default:
			close(getting)
			time.Sleep(300 * time.Millisecond) // a call that ends by itself
			return nil
		}
	}
	subErr, getErr := make(chan error, 1), make(chan error, 1)
	go func() {
		subErr <- r.conn.Invoke(context.Background(), "/containerd.services.events.v1.Events/Subscribe", &emptypb.Empty{}, &emptypb.Empty{})
	}()
	<-subscribed
	go func() {
		getErr <- r.conn.Invoke(context.Background(), "/containerd.services.tasks.v1.Tasks/Get", &emptypb.Empty{}, &emptypb.Empty{})
	}()
	<-getting
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	r.srv.Shutdown(ctx)
	d := time.Since(start)
	if d > 5*time.Second {
		t.Fatalf("Shutdown took %v: the subscription held the drain", d)
	}
	if err := <-getErr; err != nil {
		t.Fatalf("a call in flight was cut by the drain: %v", err)
	}
	if err := <-subErr; err == nil {
		t.Fatal("the subscription outlived the helper")
	}
}

// TestEndlessCallTurnedAwayWhileDraining: a subscription that arrives once
// the drain began is answered Unavailable, never parked.
func TestEndlessCallTurnedAwayWhileDraining(t *testing.T) {
	s := &Server{endless: map[*grpc.ServerStream]context.CancelFunc{}}
	s.endEndless()
	called := false
	err := s.endOnDrain(nil, fakeServerStream{}, &grpc.StreamServerInfo{FullMethod: "/containerd.services.events.v1.Events/Subscribe"},
		func(any, grpc.ServerStream) error { called = true; return nil })
	if status.Code(err) != codes.Unavailable || called {
		t.Fatalf("endOnDrain while draining = %v (handler called %v)", err, called)
	}
	err = s.endOnDrain(nil, fakeServerStream{}, &grpc.StreamServerInfo{FullMethod: "/containerd.services.tasks.v1.Tasks/Get"},
		func(any, grpc.ServerStream) error { return errors.New("ran") })
	if err == nil || err.Error() != "ran" {
		t.Fatalf("a call that ends by itself was not run while draining: %v", err)
	}
}

type fakeServerStream struct{ grpc.ServerStream }

func (fakeServerStream) Context() context.Context { return context.Background() }
