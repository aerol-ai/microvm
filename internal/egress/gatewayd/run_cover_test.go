package gatewayd

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
