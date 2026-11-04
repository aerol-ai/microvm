//go:build linux && kerneltest

package gatewayd

// Real-kernel test of the per-bridge self-test (T41), run in a privileged
// Linux container:
//
//	go test -tags kerneltest ./internal/egress/gatewayd/ -run KernelSelfTest
//
// It drives the production pieces end to end: the gateway daemon with real
// nftables listening on a test bridge, and sandboxd's netlink probe network
// sending through the redirect.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
)

func kexec(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func TestKernelSelfTest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	const brName, brIP = "egst-br", "10.203.0.1"
	_ = exec.Command("ip", "link", "del", brName).Run()
	_ = exec.Command("nft", "delete", "table", "inet", "aerolvm_egress").Run()
	kexec(t, "ip", "link", "add", brName, "type", "bridge")
	kexec(t, "ip", "addr", "add", brIP+"/24", "dev", brName)
	kexec(t, "ip", "link", "set", brName, "up")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", brName).Run()
		_ = exec.Command("nft", "delete", "table", "inet", "aerolvm_egress").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "egst_hostfw").Run()
	})
	nf := "/proc/sys/net/bridge/bridge-nf-call-iptables"
	if _, err := os.Stat(nf); err != nil {
		_ = exec.Command("modprobe", "br_netfilter").Run()
	}
	if err := os.WriteFile(nf, []byte("1"), 0o644); err != nil {
		t.Skipf("br_netfilter unavailable in this container: %v", err)
	}

	sockDir := t.TempDir()
	cfg := Config{
		SocketPath: filepath.Join(sockDir, "gw.sock"), StateDir: t.TempDir(),
		DNSPort: 53054, ProxyPort: 15080, DNSQPS: 1000, DNSUpstreams: []string{"127.0.0.1:1"},
		HeartbeatInterval: time.Hour, FlowReadInterval: time.Hour, SnapshotDebounce: 10 * time.Millisecond,
		AuditBuffer: 100, LearnMax: 64, LearnedMax: 64, ProxyMaxConns: 64, ProxyMaxPerSandbox: 16,
	}
	be, ct := productionKernel()
	d, err := New(cfg, Deps{Backend: be, Conntrack: ct, OriginalDst: proxy.OriginalDst}, nil)
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
	client := egress.NewClient(cfg.SocketPath)
	t.Cleanup(func() {
		cancel()
		client.Close()
		<-done
	})
	bridge := egress.Bridge{Name: brName, GatewayIP: netip.MustParseAddr(brIP)}
	if err := client.SetBridges(ctx, []egress.Bridge{bridge}); err != nil {
		t.Fatal(err)
	}
	pn := egress.NewProbeNet()

	t.Run("a working redirect passes", func(t *testing.T) {
		if err := egress.SelfTest(ctx, client, pn, bridge, 0); err != nil {
			t.Fatal(err)
		}
		assertProbeCleanedUp(t, 0)
	})
	t.Run("a host INPUT policy of drop fails", func(t *testing.T) {
		// What ufw or a hardened AMI does: a second input base chain that
		// drops. Every base chain must accept, so redirected traffic dies.
		kexec(t, "nft", "add", "table", "inet", "egst_hostfw")
		kexec(t, "nft", "add", "chain", "inet", "egst_hostfw", "input", "{ type filter hook input priority 10 ; policy drop ; }")
		defer func() { _ = exec.Command("nft", "delete", "table", "inet", "egst_hostfw").Run() }()
		err := egress.SelfTest(ctx, client, pn, bridge, 0)
		if !errors.Is(err, egress.ErrSelfTest) {
			t.Fatalf("got %v, want ErrSelfTest", err)
		}
		assertProbeCleanedUp(t, 0)
	})
	t.Run("a missing bridge is pending, not failed", func(t *testing.T) {
		err := egress.SelfTest(ctx, client, pn, egress.Bridge{Name: "egst-nope", GatewayIP: netip.MustParseAddr("10.204.0.1")}, 1)
		if !errors.Is(err, egress.ErrBridgeAbsent) {
			t.Fatalf("got %v, want ErrBridgeAbsent", err)
		}
	})
	t.Run("bridge netfilter off fails", func(t *testing.T) {
		if err := os.WriteFile(nf, []byte("0"), 0o644); err != nil {
			t.Skip(err)
		}
		defer func() { _ = os.WriteFile(nf, []byte("1"), 0o644) }()
		if err := egress.SelfTest(ctx, client, pn, bridge, 0); !errors.Is(err, egress.ErrSelfTest) {
			t.Fatalf("got %v, want ErrSelfTest", err)
		}
	})
}

// assertProbeCleanedUp checks the probe left no netns, veth or route.
func assertProbeCleanedUp(t *testing.T, index int) {
	t.Helper()
	if _, err := net.InterfaceByName(fmt.Sprintf("egprobe%dh", index)); err == nil {
		t.Fatal("probe veth left behind")
	}
	if _, err := os.Stat(fmt.Sprintf("/var/run/netns/aerolvm-egprobe%d", index)); err == nil {
		t.Fatal("probe netns left behind")
	}
	out, _ := exec.Command("ip", "route", "show", egress.ProbeSource(index).String()+"/32").CombinedOutput()
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("probe host route left behind: %s", out)
	}
}
