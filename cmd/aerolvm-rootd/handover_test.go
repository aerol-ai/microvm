package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootswap"
	"github.com/aerol-ai/microvm/internal/version"
)

func TestVersionLine(t *testing.T) {
	want := "aerolvm-rootd " + version.Version + " (API " + strconv.Itoa(int(rootdpb.APIVersion)) + ")"
	if got := versionLine(); got != want {
		t.Fatalf("versionLine = %q, want %q", got, want)
	}
}

// supervisorListener is the socket at path as the supervisor holds it,
// and a descriptor of it only the code under test owns.
func supervisorListener(t *testing.T, path string) (*net.UnixListener, int) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = ln.Close() })
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return ln, fd
}

// TestServeOnInheritedSocket: under the supervisor the helper serves the
// socket it was passed, says so just before it serves, and leaves the
// socket when it stops, for the next helper.
func TestServeOnInheritedSocket(t *testing.T) {
	dir := shortDir(t)
	cfg, err := rootd.ConfigFromEnv(helperEnv(t, dir, "aerolvm"))
	if err != nil {
		t.Fatal(err)
	}
	serveContainerd(t, cfg.ContainerdSocket, &fakeContainerd{})
	_, fd := supervisorListener(t, cfg.Socket)
	ln, err := rootswap.InheritedListener(func(k string) string {
		if k == rootswap.ListenFDEnv {
			return strconv.Itoa(fd)
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, cfg, rootd.Options{Peer: func(net.Conn) error { return nil }, Listener: ln}, func() { close(ready) }, slog.New(slog.DiscardHandler))
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("the helper never said it serves")
	}
	conn := dialUnix(t, cfg.Socket)
	if _, err := rootdpb.NewRootHelperClient(conn).Version(ctxT(t), &rootdpb.VersionRequest{}); err != nil {
		t.Fatalf("Version on the inherited socket: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve = %v", err)
	}
	if _, err := os.Lstat(cfg.Socket); err != nil {
		t.Fatalf("the helper removed the supervisor's socket: %v", err)
	}
}

// TestRunUnderTheSupervisor: run takes the socket and the ready pipe from
// the environment the supervisor sets (Linux: run's peer check needs
// SO_PEERCRED), and refuses a socket that is not one.
func TestRunUnderTheSupervisor(t *testing.T) {
	dir := shortDir(t)
	env := helperEnv(t, dir, "aerolvm")
	bad := func(k string) string {
		if k == rootswap.ListenFDEnv {
			return "1"
		}
		return env(k)
	}
	if err := run(ctxT(t), bad, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), rootswap.ListenFDEnv) {
		t.Fatalf("run with stdout as the socket = %v", err)
	}
	if runtime.GOOS != "linux" {
		t.Skip("run serves on Linux only")
	}
	serveContainerd(t, env("SB_CONTAINERD_SOCKET"), &fakeContainerd{})
	sock := env("SB_ROOTD_SOCKET")
	_, fd := supervisorListener(t, sock)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	wfd, err := unix.Dup(int(pw.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	withHandover := func(k string) string {
		switch k {
		case rootswap.ListenFDEnv:
			return strconv.Itoa(fd)
		case rootswap.ReadyFDEnv:
			return strconv.Itoa(wfd)
		}
		return env(k)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, withHandover, slog.New(slog.DiscardHandler)) }()
	b := make([]byte, 1)
	if n, err := pr.Read(b); n != 1 || err != nil {
		t.Fatalf("ready pipe: %d %v", n, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("run removed the supervisor's socket: %v", err)
	}
}

func dialUnix(t *testing.T, sock string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///rootd", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestMainVersion: `aerolvm-rootd --version` prints the line the signing
// tool reads, and nothing starts.
func TestMainVersion(t *testing.T) {
	oldArgs, oldOut := os.Args, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdout = oldArgs, oldOut })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args, os.Stdout = []string{"aerolvm-rootd", "--version"}, w
	main()
	_ = w.Close()
	os.Stdout = oldOut
	out := make([]byte, 256)
	n, _ := r.Read(out)
	if string(out[:n]) != versionLine()+"\n" {
		t.Fatalf("--version printed %q", out[:n])
	}
}
