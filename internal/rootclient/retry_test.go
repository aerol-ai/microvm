package rootclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// TestEveryCallHasARetryRule: each call the helper can serve says whether
// a dropped one is sent again, so a new call is never retried by default.
func TestEveryCallHasARetryRule(t *testing.T) {
	for _, f := range rootdpb.Features() {
		if _, ok := retrySafe[f]; !ok {
			t.Errorf("%s has no retry rule in retrySafe", f)
		}
	}
}

// swapHelper is one helper generation on a socket the test owns, as the
// supervisor owns it: each generation serves a copy of one listener, and
// connections made between two of them wait in its backlog.
type swapHelper struct {
	rootdpb.UnimplementedRootHelperServer
	name string
	// hostFiles answers EnsureHostFiles; nil answers it at once.
	hostFiles func(ctx context.Context) error
	calls     atomic.Int32
}

func (h *swapHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: h.name, Api: rootdpb.APIVersion, Features: rootdpb.Features()}, nil
}

func (h *swapHelper) EnsureHostFiles(ctx context.Context, _ *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	h.calls.Add(1)
	if h.hostFiles != nil {
		if err := h.hostFiles(ctx); err != nil {
			return nil, err
		}
	}
	return &rootdpb.EnsureHostFilesResponse{HostnamePath: h.name}, nil
}

type ownedSocket struct {
	path string
	f    *os.File
}

func newOwnedSocket(t *testing.T) ownedSocket {
	t.Helper()
	path := sockPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	t.Cleanup(func() { _ = f.Close() })
	return ownedSocket{path: path, f: f}
}

// serve runs h on a copy of the socket; the trailer interceptor marks
// every answer as the helper's, as rootd's server does.
func (o ownedSocket) serve(t *testing.T, h rootdpb.RootHelperServer) *grpc.Server {
	t.Helper()
	ln, err := net.FileListener(o.f)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		_ = grpc.SetTrailer(ctx, metadata.Pairs(rootdpb.AnsweredTrailer, "1"))
		return next(ctx, req)
	}))
	rootdpb.RegisterRootHelperServer(srv, h)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return srv
}

// TestCallCutBySwapIsRetried: a call in flight when the old helper is cut
// off (its drain deadline passed) reaches the next helper and succeeds;
// the caller sees one answer, from the new helper.
func TestCallCutBySwapIsRetried(t *testing.T) {
	sock := newOwnedSocket(t)
	inFlight := make(chan struct{})
	var once sync.Once
	old := &swapHelper{name: "old", hostFiles: func(ctx context.Context) error {
		once.Do(func() { close(inFlight) })
		<-ctx.Done()
		return ctx.Err()
	}}
	oldSrv := sock.serve(t, old)
	c := New(Config{Socket: sock.path, Timeout: 2 * time.Second, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	type result struct {
		resp *rootdpb.EnsureHostFilesResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.EnsureHostFiles(ctxT(t), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"})
		done <- result{resp, err}
	}()
	<-inFlight
	oldSrv.Stop() // cut: the call's connection closes with no answer
	time.Sleep(50 * time.Millisecond)
	next := &swapHelper{name: "new"}
	sock.serve(t, next)
	r := <-done
	if r.err != nil {
		t.Fatalf("the cut call = %v, want it answered by the next helper", r.err)
	}
	if r.resp.GetHostnamePath() != "new" || old.calls.Load() != 1 || next.calls.Load() != 1 {
		t.Fatalf("answered by %q; old saw %d, new %d", r.resp.GetHostnamePath(), old.calls.Load(), next.calls.Load())
	}
}

// TestAnsweredFailuresAreNotRetried: only a call the helper did not answer
// goes again. Its own Unavailable (containerd's, passed on), a refusal, a
// timeout and a call with no retry rule come back after one try.
func TestAnsweredFailuresAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		stuck bool
		setup func(t *testing.T)
		want  error
	}{
		{"its own Unavailable", status.Error(codes.Unavailable, "containerd is restarting"), false, nil, nil},
		{"a refusal", rootdpb.Refused(codes.InvalidArgument, "bad_request", "no"), false, nil, ErrRefused},
		{"a timeout", nil, true, nil, ErrUnavailable},
		{"a call with no retry rule", nil, false, func(t *testing.T) {
			delete(retrySafe, rootdpb.FeatureEnsureHostFiles)
			t.Cleanup(func() { retrySafe[rootdpb.FeatureEnsureHostFiles] = true })
		}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			sock := newOwnedSocket(t)
			h := &swapHelper{name: "h", hostFiles: func(ctx context.Context) error {
				if tc.stuck {
					<-ctx.Done()
					return ctx.Err()
				}
				return tc.err
			}}
			srv := sock.serve(t, h)
			c := New(Config{Socket: sock.path, Timeout: 300 * time.Millisecond, HelperUID: uint32(os.Getuid())})
			t.Cleanup(func() { _ = c.Close() })
			if err := c.Ensure(ctxT(t)); err != nil {
				t.Fatal(err)
			}
			if tc.name == "a call with no retry rule" {
				h.hostFiles = func(context.Context) error { srv.Stop(); return nil }
			}
			// No deadline of the caller's: the client's own bounds a stuck call.
			_, err := c.EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"})
			switch {
			case err == nil:
				t.Fatal("the call succeeded")
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err %v, want %v", err, tc.want)
			case tc.want == nil && status.Code(err) != codes.Unavailable:
				t.Fatalf("err %v, want the helper's Unavailable as it is", err)
			}
			if n := h.calls.Load(); n != 1 {
				t.Fatalf("the helper saw the call %d times, want 1", n)
			}
		})
	}
}

// TestRetriesStayWithinTheWindow: a helper that stays away fails the call
// within about one client timeout of retries, as a 503; a caller that
// gives up stops them at once.
func TestRetriesStayWithinTheWindow(t *testing.T) {
	sock := sockPath(t)
	c := newClient(t, sock) // 500 ms
	start := time.Now()
	_, err := c.EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"})
	d := time.Since(start)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v, want ErrUnavailable", err)
	}
	if d < c.timeout/2 || d > 3*c.timeout {
		t.Fatalf("gave up after %v; the window is about %v", d, c.timeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if _, err := c.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"}); err == nil {
		t.Fatal("a cancelled call succeeded")
	}
	if d := time.Since(start); d > c.timeout/2 {
		t.Fatalf("a cancelled call retried for %v", d)
	}

	_ = c.Close()
	start = time.Now()
	if _, err := c.EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed client: %v", err)
	}
	if d := time.Since(start); d > c.timeout/2 {
		t.Fatalf("a closed client retried for %v", d)
	}
}

// TestFirstCallWaitsOutAShortGap: a helper that comes up just after the
// first call (the supervisor starting it) is reached by that call.
func TestFirstCallWaitsOutAShortGap(t *testing.T) {
	sock := sockPath(t)
	c := newClient(t, sock) // 500 ms
	go func() {
		time.Sleep(100 * time.Millisecond)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return
		}
		srv := grpc.NewServer()
		rootdpb.RegisterRootHelperServer(srv, &swapHelper{name: "late"})
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)
	}()
	resp, err := c.EnsureHostFiles(ctxT(t), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"})
	if err != nil || resp.GetHostnamePath() != "late" {
		t.Fatalf("EnsureHostFiles = %v, %v", resp, err)
	}
}

func TestDroppedRules(t *testing.T) {
	answered := metadata.Pairs(rootdpb.AnsweredTrailer, "1")
	for _, tc := range []struct {
		name    string
		err     error
		trailer metadata.MD
		want    bool
	}{
		{"connection gone", status.Error(codes.Unavailable, "transport is closing"), nil, true},
		{"the helper's own Unavailable", status.Error(codes.Unavailable, "containerd down"), answered, false},
		{"a refusal without the trailer", rootdpb.Refused(codes.Unavailable, "x", "y"), nil, false},
		{"a timeout", status.Error(codes.DeadlineExceeded, "slow"), nil, false},
		{"cancelled", status.Error(codes.Canceled, "client closing"), nil, false},
	} {
		if got := dropped(tc.err, tc.trailer); got != tc.want {
			t.Errorf("%s: dropped = %v, want %v", tc.name, got, tc.want)
		}
	}
	if !droppedBefore(&wrapErr{ErrUnavailable}) || droppedBefore(&UnsupportedError{Feature: "x"}) || droppedBefore(errors.New("other")) {
		t.Fatal("droppedBefore misjudged")
	}
}

type wrapErr struct{ err error }

func (e *wrapErr) Error() string { return e.err.Error() }
func (e *wrapErr) Unwrap() error { return e.err }

// olderHelper is an older copy a supervisor went back to: it lacks
// EnsureHostFiles, and says so in its handshake.
type olderHelper struct {
	rootdpb.UnimplementedRootHelperServer
}

func (olderHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	var feats []string
	for _, f := range rootdpb.Features() {
		if f != rootdpb.FeatureEnsureHostFiles {
			feats = append(feats, f)
		}
	}
	return &rootdpb.VersionResponse{HelperVersion: "older", Api: rootdpb.APIVersion, Features: feats}, nil
}

// TestRollbackIsSeenOnTheNextCall: a newer helper answered the handshake,
// then the supervisor went back to an older copy. A call the newer one
// listed comes back Unimplemented; the next call asks the helper again,
// so the client names the helper that runs, not the one it remembers, and
// it picks the newer helper up again when that one returns.
func TestRollbackIsSeenOnTheNextCall(t *testing.T) {
	sock := newOwnedSocket(t)
	newerSrv := sock.serve(t, &swapHelper{name: "newer"})
	c := New(Config{Socket: sock.path, Timeout: 2 * time.Second, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	req := &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"}
	if _, err := c.EnsureHostFiles(ctxT(t), req); err != nil {
		t.Fatalf("on the newer helper: %v", err)
	}
	newerSrv.Stop()
	olderSrv := sock.serve(t, olderHelper{})

	var ue *UnsupportedError
	if _, err := c.EnsureHostFiles(ctxT(t), req); !errors.As(err, &ue) {
		t.Fatalf("first call on the older helper: %v, want an UnsupportedError", err)
	}
	_, err := c.EnsureHostFiles(ctxT(t), req)
	if !errors.As(err, &ue) || ue.Helper.HelperVersion != "older" {
		t.Fatalf("second call on the older helper: %v, want an UnsupportedError naming the older helper", err)
	}
	if info, _ := c.Info(); info.HelperVersion != "older" {
		t.Fatalf("the client still believes helper %q runs", info.HelperVersion)
	}

	olderSrv.Stop()
	sock.serve(t, &swapHelper{name: "newer"})
	eventually(t, func() error {
		resp, err := c.EnsureHostFiles(ctxT(t), req)
		if err == nil && resp.GetHostnamePath() != "newer" {
			err = fmt.Errorf("answered by %q", resp.GetHostnamePath())
		}
		return err
	})
}
