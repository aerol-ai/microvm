//go:build linux && kerneltest

package gatewayd

// Real-kernel test of the gateway serving Firecracker guests (plans/
// egress-domain-filtering.md Phase 4), run in a privileged Linux container:
//
//	go test -tags kerneltest ./internal/egress/gatewayd/ -run KernelTapPool
//
// Each "TAP" is a veth named like one, its far end in a guest netns on a
// routed /30, as the Firecracker driver lays them out. The gateway gets
// the TAP pool as its only bridge, so it listens on the wildcard address.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
)

// tapGuest is one TAP slot: the host end, the guest netns and addresses.
type tapGuest struct{ tap, ns, hostIP, guestIP string }

var (
	tapAttached = tapGuest{"fctap91", "fcgw-g1", "172.30.0.1", "172.30.0.2"}
	tapPlain    = tapGuest{"fctap92", "fcgw-g2", "172.30.0.5", "172.30.0.6"}
)

// TestTapPoolKernelHelper runs inside a guest netns: "connect" reports one
// TCP connect, "dns" one UDP query's answer.
func TestTapPoolKernelHelper(t *testing.T) {
	switch os.Getenv("TPK_MODE") {
	case "connect":
		c, err := net.DialTimeout("tcp", os.Getenv("TPK_ADDR"), 1500*time.Millisecond)
		if err != nil {
			fmt.Println("FAIL", err)
			os.Exit(0)
		}
		_ = c.Close()
		fmt.Println("OK")
		os.Exit(0)
	case "dns":
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(os.Getenv("TPK_NAME")), dns.TypeA)
		cl := &dns.Client{Timeout: 1500 * time.Millisecond}
		r, _, err := cl.Exchange(m, os.Getenv("TPK_ADDR"))
		if err != nil {
			fmt.Println("FAIL", err)
			os.Exit(0)
		}
		fmt.Println("RCODE", dns.RcodeToString[r.Rcode])
		os.Exit(0)
	default:
		t.Skip("helper")
	}
}

func (g tapGuest) run(t *testing.T, env ...string) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", g.ns, os.Args[0], "-test.run=TestTapPoolKernelHelper$")
	cmd.Env = append(os.Environ(), env...)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(strings.Split(string(out), "\n")[0])
}

func (g tapGuest) setUp(t *testing.T) {
	t.Helper()
	peer := g.tap + "g"
	_ = exec.Command("ip", "netns", "del", g.ns).Run()
	_ = exec.Command("ip", "link", "del", g.tap).Run()
	kexec(t, "ip", "netns", "add", g.ns)
	kexec(t, "ip", "link", "add", g.tap, "type", "veth", "peer", "name", peer)
	kexec(t, "ip", "link", "set", peer, "netns", g.ns)
	kexec(t, "ip", "addr", "add", g.hostIP+"/30", "dev", g.tap)
	kexec(t, "ip", "link", "set", g.tap, "up")
	kexec(t, "ip", "netns", "exec", g.ns, "ip", "addr", "add", g.guestIP+"/30", "dev", peer)
	kexec(t, "ip", "netns", "exec", g.ns, "ip", "link", "set", peer, "up")
	kexec(t, "ip", "netns", "exec", g.ns, "ip", "link", "set", "lo", "up")
	kexec(t, "ip", "netns", "exec", g.ns, "ip", "route", "add", "default", "via", g.hostIP)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", g.tap).Run()
		_ = exec.Command("ip", "netns", "del", g.ns).Run()
	})
}

func TestKernelTapPool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	_ = exec.Command("nft", "delete", "table", "inet", "aerolvm_egress").Run()
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "aerolvm_egress").Run() })
	tapAttached.setUp(t)
	tapPlain.setUp(t)
	kexec(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	cfg := Config{
		SocketPath: filepath.Join(t.TempDir(), "gw.sock"), StateDir: t.TempDir(),
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
	if err := client.SetBridges(ctx, []egress.Bridge{egress.TapPoolBridge(netip.MustParsePrefix("172.30.0.0/16"))}); err != nil {
		t.Fatal(err)
	}
	if st, err := client.Ready(ctx); err != nil || !strings.Contains(strings.Join(st.Listeners, " "), "0.0.0.0:15080") {
		t.Fatalf("wildcard listeners: %+v, %v", st, err)
	}
	if err := client.Attach(ctx, egress.Spec{ID: "g1", IP: netip.MustParseAddr(tapAttached.guestIP), AllowOut: []string{"allowed.test"}}); err != nil {
		t.Fatal(err)
	}

	t.Run("an attached guest's HTTPS lands on the proxy", func(t *testing.T) {
		// TEST-NET-1 is unroutable: only the redirect can answer.
		if got := tapAttached.run(t, "TPK_MODE=connect", "TPK_ADDR=192.0.2.1:443"); got != "OK" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("an attached guest's DNS is answered by the filter", func(t *testing.T) {
		got := tapAttached.run(t, "TPK_MODE=dns", "TPK_ADDR=192.0.2.53:53", "TPK_NAME=denied.test")
		if !strings.HasPrefix(got, "RCODE") {
			t.Fatalf("got %q, want an answer from the gateway", got)
		}
	})
	t.Run("an unattached guest is not redirected", func(t *testing.T) {
		if got := tapPlain.run(t, "TPK_MODE=connect", "TPK_ADDR=192.0.2.1:443"); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("the input guard keeps the wildcard listener from other sources", func(t *testing.T) {
		if got := tapPlain.run(t, "TPK_MODE=connect", "TPK_ADDR="+tapPlain.hostIP+":15080"); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("got %q", got)
		}
		if got := tapPlain.run(t, "TPK_MODE=dns", "TPK_ADDR="+tapPlain.hostIP+":53054", "TPK_NAME=allowed.test"); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("got %q", got)
		}
	})
}
