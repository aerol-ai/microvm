package gatewayd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

func TestBridgeListenerLifecycle(t *testing.T) {
	r := startDaemon(t, t.TempDir(), egress.NewMemBackend())
	ctx := context.Background()
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "v6", GatewayIP: netip.MustParseAddr("fd00::1")}}); err == nil {
		t.Fatal("an IPv6 bridge must be refused (CEO D18)")
	}
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}}); err != nil {
		t.Fatal(err)
	}
	// Same bridge again keeps its listeners; a port conflict on a second
	// bridge name with the same IP is reported.
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}, {Name: "dup", GatewayIP: lo}}); err == nil {
		t.Fatal("binding the same ports twice must fail")
	}
	if err := r.client.SetBridges(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.client.Ready(ctx); len(st.Listeners) != 0 {
		t.Fatalf("removed bridges must close listeners: %v", st.Listeners)
	}
	if got := r.d.lns.Bridges(); len(got) != 0 {
		t.Fatalf("bridges = %v", got)
	}
}

func TestBackgroundLoops(t *testing.T) {
	be := egress.NewMemBackend()
	sockDir, _ := os.MkdirTemp("", "egl")
	defer os.RemoveAll(sockDir)
	state := t.TempDir()
	cfg := Config{SocketPath: filepath.Join(sockDir, "gw.sock"), StateDir: state, DNSPort: freePort(t), ProxyPort: freePort(t),
		HeartbeatInterval: 10 * time.Millisecond, FlowReadInterval: 10 * time.Millisecond, SnapshotDebounce: time.Millisecond,
		DNSUpstreams: []string{"127.0.0.1:1"}}
	d, err := New(cfg, Deps{Backend: be}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := socketListener(cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx, ln) }()
	if err := d.Gateway().Attach(egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	d.markDirty()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(state, "snapshot.json")); err == nil && d.Events().Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d.Events().Len() == 0 {
		t.Fatal("heartbeat loop never published")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNewFailsWithoutLayout(t *testing.T) {
	if _, err := New(Config{}, Deps{Backend: &failingBackend{}}, nil); err == nil {
		t.Fatal("a backend that can't create the layout must fail New (kernel probe)")
	}
	// A corrupt snapshot is logged and ignored; the gateway waits for Sync.
	state := t.TempDir()
	_ = os.WriteFile(filepath.Join(state, "snapshot.json"), []byte("{bad"), 0o600)
	if _, err := New(Config{StateDir: state, DNSPort: freePort(t), ProxyPort: freePort(t)}, Deps{Backend: egress.NewMemBackend()}, nil); err != nil {
		t.Fatal(err)
	}
}

type failingBackend struct{ egress.MemBackend }

func (*failingBackend) EnsureLayout(egress.LayoutConfig) error { return net.ErrClosed }

// TestRunEntrypoint runs the production entrypoint where it can run without
// privileges: off Linux the kernel seam is in-memory.
func TestRunEntrypoint(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("Run needs CAP_NET_ADMIN on Linux")
	}
	if runtime.GOOS == "linux" {
		t.Skip("covered by the kerneltest suite on Linux")
	}
	sockDir, _ := os.MkdirTemp("", "egr")
	defer os.RemoveAll(sockDir)
	t.Setenv("SB_EGRESS_GATEWAY_SOCKET", filepath.Join(sockDir, "gw.sock"))
	t.Setenv("SB_EGRESS_STATE_DIR", t.TempDir())
	t.Setenv("SB_EGRESS_DNS_PORT", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := RunCLI(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("port 0 must be rejected by FromEnv")
	}
	t.Setenv("SB_EGRESS_DNS_PORT", "53054")
	t.Setenv("SB_EGRESS_OPERATOR_FILE", filepath.Join(sockDir, "missing.yaml"))
	if err := RunCLI(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("a missing operator file must stop the gateway")
	}
	t.Setenv("SB_EGRESS_OPERATOR_FILE", "")
	if err := RunCLI(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("RunCLI: %v", err)
	}
}
