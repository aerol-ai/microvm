package gatewayd

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/observability"
)

func TestSocketListenerFailures(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("LISTEN_FDS", "1")
	if _, err := socketListener(""); err == nil {
		t.Fatal("a different activation pid must not claim the socket")
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "0")
	if _, err := socketListener(""); err == nil {
		t.Fatal("activation with no fds must fall through to the missing path")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := socketListener(filepath.Join(file, "gw.sock")); err == nil {
		t.Fatal("a file used as a parent directory must fail")
	}
	// sun_path is 104 bytes on Darwin and 108 on Linux. Removing a directory
	// succeeds, so an existing directory is not a listen failure; a path
	// the kernel refuses to bind is.
	if _, err := socketListener(filepath.Join(dir, strings.Repeat("n", 120))); err == nil {
		t.Fatal("a socket path past sun_path must fail")
	}
}

func TestRunUnprivilegedPaths(t *testing.T) {
	orig := productionKernel
	poll := operatorPoll
	t.Cleanup(func() {
		productionKernel = orig
		operatorPoll = poll
	})
	productionKernel = func() (egress.Backend, egress.ConntrackFlusher) {
		return egress.NewMemBackend(), nil
	}
	operatorPoll = 15 * time.Millisecond
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dir := t.TempDir()
	if err := Run(ctx, Config{
		OperatorFile: filepath.Join(dir, "missing.yaml"),
		DNSPort:      53054, ProxyPort: 15080,
	}, log); err == nil {
		t.Fatal("a missing operator file must stop the gateway before it serves")
	}

	productionKernel = func() (egress.Backend, egress.ConntrackFlusher) {
		return &failingBackend{}, nil
	}
	if err := Run(ctx, Config{DNSPort: 53054, ProxyPort: 15080}, log); err == nil {
		t.Fatal("a kernel that rejects the layout must stop the gateway")
	}
	productionKernel = func() (egress.Backend, egress.ConntrackFlusher) {
		return egress.NewMemBackend(), nil
	}

	t.Setenv("SB_EGRESS_DNS_PORT", "0")
	if err := RunCLI(ctx, log); err == nil {
		t.Fatal("port 0 must be rejected before the gateway starts")
	}
	t.Setenv("SB_EGRESS_DNS_PORT", "")

	if err := Run(ctx, Config{
		DNSPort: freePort(t), ProxyPort: freePort(t),
		Traces: observability.OTELTracesConfig{Enabled: true},
	}, log); err == nil {
		t.Fatal("no socket path must stop the gateway")
	}

	op := filepath.Join(dir, "op.yaml")
	body := []byte("version: 1\ndeny_cidrs: [10.99.0.0/16]\n")
	if err := os.WriteFile(op, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "gw.sock")
	serveCtx, serveCancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- Run(serveCtx, Config{
			SocketPath: sock, StateDir: t.TempDir(), OperatorFile: op,
			DNSPort: freePort(t), ProxyPort: freePort(t), DNSQPS: 10,
			DNSUpstreams:      []string{"127.0.0.1:1"},
			HeartbeatInterval: time.Hour, FlowReadInterval: time.Hour, SnapshotDebounce: time.Hour,
			Traces: observability.OTELTracesConfig{Enabled: true, Endpoint: "http://127.0.0.1:1"},
		}, log)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			serveCancel()
			t.Fatal("gateway did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(op, []byte("version: 1\ndeny_cidrs: [10.98.0.0/16]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	serveCancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRunCLIServesWithoutTracing (P1-15): an exporter that can't start is
// logged and the gateway serves anyway, from the SB_EGRESS_* environment.
func TestRunCLIServesWithoutTracing(t *testing.T) {
	orig := productionKernel
	t.Cleanup(func() { productionKernel = orig })
	productionKernel = func() (egress.Backend, egress.ConntrackFlusher) {
		return egress.NewMemBackend(), nil
	}
	sockDir, err := os.MkdirTemp("", "egc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	state := t.TempDir()
	t.Setenv("SB_EGRESS_GATEWAY_SOCKET", filepath.Join(sockDir, "gw.sock"))
	t.Setenv("SB_EGRESS_STATE_DIR", state)
	t.Setenv("SB_EGRESS_DNS_PORT", "")
	t.Setenv("SB_EGRESS_PROXY_PORT", "")
	t.Setenv("SB_EGRESS_OPERATOR_FILE", "")
	t.Setenv("SB_EGRESS_DNS_UPSTREAMS", "127.0.0.1:1")
	t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
	// A context that is already over makes the exporter's start fail and
	// the gateway return as soon as it has served.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs syncBuffer
	if err := RunCLI(ctx, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("RunCLI: %v", err)
	}
	if !strings.Contains(logs.String(), "trace exporter not started") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	if _, err := os.Stat(filepath.Join(state, "snapshot.json")); err != nil {
		t.Fatalf("the gateway must have served from SB_EGRESS_STATE_DIR: %v", err)
	}
}

// TestSocketActivation (S5): under systemd the gateway serves the socket the
// unit passed as fd 3 and refuses an fd that isn't a listening socket. The
// fd only exists in a child process, so each case re-runs this test binary
// as TestSocketActivationChild.
func TestSocketActivation(t *testing.T) {
	dir, err := os.MkdirTemp("", "ega")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "gw.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sockFile, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sockFile.Close() })
	notSock, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notSock.Close() })
	for _, tc := range []struct {
		name string
		fd   *os.File
	}{
		{"listener", sockFile},
		{"not-a-socket", notSock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-test.run=^TestSocketActivationChild$", "-test.count=1", "-test.v"}
			// The child adds its coverage to this run's (go test merges every
			// process's counters in the cover dir).
			if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
				args = append(args, "-test.gocoverdir="+f.Value.String())
			}
			cmd := exec.Command(os.Args[0], args...)
			// Under -race a child otherwise sleeps a second at exit.
			cmd.Env = append(os.Environ(), "GATEWAYD_ACTIVATION_CHILD="+tc.name,
				"GORACE="+strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
			cmd.ExtraFiles = []*os.File{tc.fd}
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "--- PASS: TestSocketActivationChild") {
				t.Fatalf("child: %v\n%s", err, out)
			}
		})
	}
}

// TestSocketActivationChild is the activated gateway for TestSocketActivation.
func TestSocketActivationChild(t *testing.T) {
	want := os.Getenv("GATEWAYD_ACTIVATION_CHILD")
	if want == "" {
		t.Skip("run by TestSocketActivation")
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	ln, err := socketListener("")
	if want == "listener" {
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		return
	}
	if err == nil || !strings.Contains(err.Error(), "activated socket") {
		t.Fatalf("socketListener = %v, want the activated socket refused", err)
	}
}
