package containerd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"google.golang.org/grpc"
)

// A restart of a Kubernetes worker's runtime container alone moves the
// sandboxes' cgroup parent (cgroup_parent_moved.go). Privilege mode single
// reads the runtime container's file again on each new connection to
// containerd, refuses a connection once the file names another parent, and
// tells sandboxd once, so it starts again with the new parent.

const (
	parentA = "/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope/sandboxes"
	parentB = "/kubepods.slice/kubepods-pod1.slice/cri-containerd-b.scope/sandboxes"
)

// movedLog records what the driver told sandboxd.
type movedLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *movedLog) hear(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, err)
}

func (l *movedLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errs)
}

func parentDriver(t *testing.T, file string) *Driver {
	t.Helper()
	return New(Config{Socket: "/run/containerd/containerd.sock", Namespace: "aerolvm", CgroupParent: parentA, CgroupParentFile: file},
		nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func writeParent(t *testing.T, file, parent string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(parent), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCgroupParentFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content *string // nil: no file
		ok      bool
		moved   bool
	}{
		{name: "the parent sandboxd started with", content: ptr(parentA + "\n"), ok: true},
		{name: "the same parent, written unclean", content: ptr(parentA + "/\n"), ok: true},
		{name: "a new parent", content: ptr(parentB + "\n"), moved: true},
		{name: "no file", content: nil},
		{name: "an empty file", content: ptr("\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "cgroup-parent")
			if tc.content != nil {
				writeParent(t, file, *tc.content)
			}
			d := parentDriver(t, file)
			var heard movedLog
			d.OnCgroupParentMoved(heard.hear)

			err := d.checkCgroupParent()
			if tc.ok {
				if err != nil || heard.count() != 0 {
					t.Fatalf("check = %v, told %d times; want it to pass quietly", err, heard.count())
				}
				return
			}
			if err == nil {
				t.Fatal("check passed; want the connection refused")
			}
			var moved *CgroupParentMovedError
			if !tc.moved {
				// Unreadable or empty: refused, and retried, never a restart.
				if errors.As(err, &moved) || heard.count() != 0 {
					t.Fatalf("check = %v, told %d times; want a plain refusal", err, heard.count())
				}
				return
			}
			if !errors.As(err, &moved) || moved.Started != parentA || moved.Now != parentB || moved.File != file {
				t.Fatalf("check = %#v; want a move from %s to %s", err, parentA, parentB)
			}
			// Told once, however many connections find it.
			_ = d.checkCgroupParent()
			if heard.count() != 1 || !errors.As(heard.errs[0], &moved) {
				t.Fatalf("told %d times (%v); want once, with the move", heard.count(), heard.errs)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// The listener is told once, whether it is set before the move is seen or
// after (the daemon sets it once the engine is wired, and a warm-pool
// refill may have connected first).
func TestCgroupParentWatchTellsOnce(t *testing.T) {
	moved := &CgroupParentMovedError{File: "/f", Started: parentA, Now: parentB}

	var early movedLog
	var w cgroupParentWatch
	w.listen(early.hear)
	w.report(moved)
	w.report(errors.New("a second move"))
	if early.count() != 1 || early.errs[0] != moved {
		t.Fatalf("listener set first: told %v; want the first move once", early.errs)
	}

	var late movedLog
	var w2 cgroupParentWatch
	w2.report(moved)
	if late.count() != 0 {
		t.Fatal("told before any listener")
	}
	w2.listen(late.hear)
	w2.report(moved)
	if late.count() != 1 || late.errs[0] != moved {
		t.Fatalf("listener set after the move: told %v; want it once, at once", late.errs)
	}

	var quiet movedLog
	var w3 cgroupParentWatch
	w3.listen(quiet.hear)
	if quiet.count() != 0 {
		t.Fatal("told with no move")
	}
}

// The check runs on a connection already made, and a refused one is closed
// unused.
func TestCheckedDialer(t *testing.T) {
	orig := dialContainerdFn
	t.Cleanup(func() { dialContainerdFn = orig })
	var dialed []string
	var served net.Conn
	dialContainerdFn = func(_ context.Context, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		client, server := net.Pipe()
		served = server
		return client, nil
	}

	conn, err := checkedDialer(func() error { return nil })(context.Background(), "unix:///run/containerd/containerd.sock")
	if err != nil || conn == nil || len(dialed) != 1 || dialed[0] != "unix:///run/containerd/containerd.sock" {
		t.Fatalf("a passing check: conn %v, err %v, dialed %v", conn, err, dialed)
	}
	_ = conn.Close()

	refused := errors.New("moved")
	if conn, err := checkedDialer(func() error { return refused })(context.Background(), "a"); conn != nil || !errors.Is(err, refused) {
		t.Fatalf("a failing check: conn %v, err %v; want no connection and the check's error", conn, err)
	}
	// The refused connection was closed: its other end reads EOF.
	_ = served.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := served.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the refused connection is still open (read %v)", err)
	}

	dialErr := errors.New("connection refused")
	dialContainerdFn = func(context.Context, string) (net.Conn, error) { return nil, dialErr }
	checked := false
	if _, err := checkedDialer(func() error { checked = true; return nil })(context.Background(), "a"); !errors.Is(err, dialErr) || checked {
		t.Fatalf("a failed dial: err %v, checked %v; want the dial's error and no check", err, checked)
	}
}

// Privilege mode single with a parent file connects through the checked
// dialer; without one, as before; split goes through its helper.
func TestEnsureClientChecksTheParentInSingleMode(t *testing.T) {
	origChecked, origPlain, origHelper := connectCheckedFn, connectFn, connectHelperFn
	t.Cleanup(func() { connectCheckedFn, connectFn, connectHelperFn = origChecked, origPlain, origHelper })
	var used string
	var check func() error
	connectCheckedFn = func(socket, ns string, c func() error) (*Client, error) {
		used, check = "checked "+socket+" "+ns, c
		return &Client{namespace: ns}, nil
	}
	connectFn = func(socket, ns string) (*Client, error) {
		used = "plain " + socket + " " + ns
		return &Client{namespace: ns}, nil
	}
	connectHelperFn = func(_ RootHelper, ns string) (*Client, error) {
		used = "helper " + ns
		return &Client{namespace: ns}, nil
	}

	file := filepath.Join(t.TempDir(), "cgroup-parent")
	writeParent(t, file, parentB+"\n")
	d := parentDriver(t, file)
	var heard movedLog
	d.OnCgroupParentMoved(heard.hear)
	if _, err := d.ensureClient(); err != nil || used != "checked /run/containerd/containerd.sock aerolvm" {
		t.Fatalf("single with a parent file: %q, %v", used, err)
	}
	// The check it was given is this driver's: it reads the file.
	if err := check(); err == nil || heard.count() != 1 {
		t.Fatalf("the dialer's check = %v, told %d; want the move", err, heard.count())
	}

	if _, err := parentDriver(t, "").ensureClient(); err != nil || used != "plain /run/containerd/containerd.sock aerolvm" {
		t.Fatalf("single with no parent file: %q, %v", used, err)
	}

	split := parentDriver(t, file)
	split.SetRootHelper(&fakeHelper{socket: "/run/aerolvm-rootd/root.sock"})
	if _, err := split.ensureClient(); err != nil || used != "helper aerolvm" {
		t.Fatalf("split: %q, %v", used, err)
	}
}

// The real client and dialer, against a socket that answers containerd's
// version. While the file names the parent sandboxd started with, calls go
// through. Then containerd goes away and a new one comes up, after the
// runtime container's supervisor wrote its new parent: the client's next
// connection is refused, and sandboxd is told once.
func TestConnectCheckedFollowsARuntimeRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "ctdp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock, file := filepath.Join(dir, "c.sock"), filepath.Join(dir, "cgroup-parent")
	serve := func() *grpc.Server {
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := grpc.NewServer()
		versionapi.RegisterVersionServer(srv, versionServer{})
		go func() { _ = srv.Serve(ln) }()
		return srv
	}
	writeParent(t, file, parentA+"\n")
	srv := serve()

	d := New(Config{Socket: sock, Namespace: "aerolvm", CgroupParent: parentA, CgroupParentFile: file}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var heard movedLog
	d.OnCgroupParentMoved(heard.hear)
	c, err := d.ensureClient()
	if err != nil {
		t.Fatalf("connect with the parent unchanged: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()
	if _, err := c.raw.Version(ctx); err != nil || heard.count() != 0 {
		t.Fatalf("version = %v, told %d; want it served", err, heard.count())
	}

	// The runtime container starts again: containerd goes, the new
	// supervisor writes its parent, then the new containerd comes up.
	srv.Stop()
	writeParent(t, file, parentB+"\n")
	srv = serve()
	t.Cleanup(srv.Stop)

	deadline := time.Now().Add(10 * time.Second)
	for heard.count() == 0 && time.Now().Before(deadline) {
		callCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, _ = c.raw.Version(callCtx)
		cancel()
	}
	if heard.count() != 1 {
		t.Fatalf("told %d times after the restart; want once", heard.count())
	}
	callCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if _, err := c.raw.Version(callCtx); err == nil {
		t.Fatal("a call reached the new containerd with the old parent")
	}
	if heard.count() != 1 {
		t.Fatalf("told %d times; want once", heard.count())
	}
}
