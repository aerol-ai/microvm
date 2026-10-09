//go:build linux && kerneltest

package egress

// Real-kernel tests for the nftables layout, run in a privileged Linux
// container:
//
//	go test -tags kerneltest ./internal/egress/ -run Kernel
//
// Topology: a "sandbox" netns (10.201.0.2) and a "remote" netns (10.202.0.2)
// are routed through the host (10.201.0.1 / 10.202.0.1). The host plays the
// gateway: its DNS and proxy listeners sit on 10.201.0.1.

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

const (
	kSbxNS    = "egk-sbx"
	kRemoteNS = "egk-remote"
	kHostSbx  = "10.201.0.1"
	kSbxIP    = "10.201.0.2"
	kHostRem  = "10.202.0.1"
	kRemoteIP = "10.202.0.2"
	kDNSPort  = 53054
	kProxy    = 15080
)

func krun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// TestKernelHelper is re-executed inside a netns: "serve" runs TCP listeners
// on the given ports, "dial" classifies one TCP connect, "udp" sends one
// datagram and waits for a reply.
func TestKernelHelper(t *testing.T) {
	switch os.Getenv("EGK_MODE") {
	case "serve":
		for _, p := range strings.Split(os.Getenv("EGK_PORTS"), ",") {
			ln, err := net.Listen("tcp", net.JoinHostPort(os.Getenv("EGK_ADDR"), p))
			if err != nil {
				fmt.Println("ERR", err)
				os.Exit(1)
			}
			go func(ln net.Listener, p string) {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("remote-" + p + "\n"))
					_ = c.Close()
				}
			}(ln, p)
		}
		fmt.Println("READY")
		select {}
	case "dial":
		c, err := net.DialTimeout("tcp", os.Getenv("EGK_ADDR"), 1500*time.Millisecond)
		switch {
		case err == nil:
			line, _ := bufio.NewReader(c).ReadString('\n')
			fmt.Println("OK", strings.TrimSpace(line))
		case errors.Is(err, syscall.ECONNREFUSED):
			fmt.Println("REFUSED")
		case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EACCES):
			fmt.Println("UNREACH")
		default:
			fmt.Println("TIMEOUT", err)
		}
		os.Exit(0)
	case "udp":
		c, err := net.Dial("udp", os.Getenv("EGK_ADDR"))
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(0)
		}
		_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _ = c.Write([]byte("q"))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			fmt.Println("NOREPLY", err)
		} else {
			fmt.Println("OK", string(buf[:n]))
		}
		os.Exit(0)
	default:
		t.Skip("helper")
	}
}

func inNS(t *testing.T, ns string, env ...string) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=TestKernelHelper$")
	cmd.Env = append(os.Environ(), env...)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(strings.Split(string(out), "\n")[0])
}

func dialFromSandbox(t *testing.T, addr string) string {
	return inNS(t, kSbxNS, "EGK_MODE=dial", "EGK_ADDR="+addr)
}

func setupTopology(t *testing.T) {
	t.Helper()
	for _, ns := range []string{kSbxNS, kRemoteNS} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		krun(t, "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}
	for _, l := range []struct{ host, peer, ns, hostIP, peerIP string }{
		{"egk-h1", "egk-s1", kSbxNS, kHostSbx, kSbxIP},
		{"egk-h2", "egk-r1", kRemoteNS, kHostRem, kRemoteIP},
	} {
		_ = exec.Command("ip", "link", "del", l.host).Run()
		krun(t, "ip", "link", "add", l.host, "type", "veth", "peer", "name", l.peer)
		krun(t, "ip", "link", "set", l.peer, "netns", l.ns)
		krun(t, "ip", "addr", "add", l.hostIP+"/24", "dev", l.host)
		krun(t, "ip", "link", "set", l.host, "up")
		krun(t, "ip", "netns", "exec", l.ns, "ip", "addr", "add", l.peerIP+"/24", "dev", l.peer)
		krun(t, "ip", "netns", "exec", l.ns, "ip", "link", "set", l.peer, "up")
		krun(t, "ip", "netns", "exec", l.ns, "ip", "link", "set", "lo", "up")
		krun(t, "ip", "netns", "exec", l.ns, "ip", "route", "add", "default", "via", l.hostIP)
	}
	krun(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	srv := exec.Command("ip", "netns", "exec", kRemoteNS, os.Args[0], "-test.run=TestKernelHelper$")
	srv.Env = append(os.Environ(), "EGK_MODE=serve", "EGK_ADDR="+kRemoteIP, "EGK_PORTS=9000,443,22")
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("remote helper not ready: %q", line)
	}
}

// hostListeners stands in for the DNS filter and proxy.
func hostListeners(t *testing.T) {
	t.Helper()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", kHostSbx, kDNSPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = pc.WriteTo([]byte("dnsfilter"), addr)
		}
	}()
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", kHostSbx, kProxy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("proxy\n"))
			_ = c.Close()
		}
	}()
}

func resetTable(t *testing.T) {
	t.Helper()
	_ = exec.Command("nft", "delete", "table", "inet", TableName).Run()
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", TableName).Run() })
}

func TestKernelLayoutLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	resetTable(t)
	be := NewNFTBackend()
	cfg := LayoutConfig{DNSPort: kDNSPort, ProxyPort: kProxy}
	if err := be.CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("CheckLayout before create = %v", err)
	}
	if err := be.EnsureLayout(cfg); err != nil {
		t.Fatal(err)
	}
	if err := be.CheckLayout(); err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr(kSbxIP)
	ops := []Op{
		{Set: SetFQDNSrc, Elems: []Elem{{Src: src}}},
		{Set: SetAllowCIDR, Elems: []Elem{{Src: src, Dst: netip.MustParseAddr("10.0.0.0"), DstEnd: netip.MustParseAddr("10.255.255.255")}}},
		{Set: SetAllowLearned, Elems: []Elem{{Src: src, Dst: netip.MustParseAddr("140.82.112.3"), Port: 22, Timeout: time.Minute}}},
	}
	if err := be.Apply(ops); err != nil {
		t.Fatal(err)
	}
	// A matching layout is kept: contents survive EnsureLayout (D13).
	if err := be.EnsureLayout(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := be.List(SetAllowCIDR)
	if err != nil || len(got) != 1 || got[0].DstEnd.String() != "10.255.255.255" {
		t.Fatalf("allow_cidr after re-ensure = %+v, %v", got, err)
	}
	learned, err := be.List(SetAllowLearned)
	if err != nil || len(learned) != 1 || learned[0].Port != 22 || learned[0].Dst.String() != "140.82.112.3" {
		t.Fatalf("allow_learned = %+v, %v", learned, err)
	}
	// Replace is atomic flush+add.
	other := netip.MustParseAddr("10.201.0.9")
	if err := be.Replace(map[string][]Elem{SetFQDNSrc: {{Src: other}}, SetAllowCIDR: nil}); err != nil {
		t.Fatal(err)
	}
	srcs, _ := be.List(SetFQDNSrc)
	if len(srcs) != 1 || srcs[0].Src != other {
		t.Fatalf("fqdn_src after Replace = %+v", srcs)
	}
	if cidrs, _ := be.List(SetAllowCIDR); len(cidrs) != 0 {
		t.Fatalf("allow_cidr after Replace = %+v", cidrs)
	}
	// Another layout version (different ports) replaces the table in one
	// transaction, carrying the per-source sets with every gateway-mode
	// source blocked until Sync (review finding 11); learned elements, with
	// their timeouts, start over.
	cidr := Elem{Src: other, Dst: netip.MustParseAddr("192.168.0.0"), DstEnd: netip.MustParseAddr("192.168.255.255")}
	if err := be.Apply([]Op{{Set: SetAllowCIDR, Elems: []Elem{cidr}}}); err != nil {
		t.Fatal(err)
	}
	if err := be.EnsureLayout(LayoutConfig{DNSPort: kDNSPort + 1, ProxyPort: kProxy}); err != nil {
		t.Fatal(err)
	}
	if err := be.CheckLayout(); err != nil {
		t.Fatal(err)
	}
	if srcs, _ := be.List(SetFQDNSrc); len(srcs) != 1 || srcs[0].Src != other {
		t.Fatalf("fqdn_src must be carried: %+v", srcs)
	}
	if blocked, _ := be.List(SetBlockedSrc); len(blocked) != 1 || blocked[0].Src != other {
		t.Fatalf("carried sources must be blocked until Sync: %+v", blocked)
	}
	if cidrs, _ := be.List(SetAllowCIDR); len(cidrs) != 1 || cidrs[0].DstEnd != cidr.DstEnd {
		t.Fatalf("allow_cidr intervals must be carried: %+v", cidrs)
	}
	if learned, _ := be.List(SetAllowLearned); len(learned) != 0 {
		t.Fatalf("learned elements start over: %+v", learned)
	}
	// Table loss is detected.
	krun(t, "nft", "delete", "table", "inet", TableName)
	if err := be.CheckLayout(); !errors.Is(err, ErrLayoutMissing) {
		t.Fatalf("CheckLayout after delete = %v", err)
	}
}

// TestKernelDataPath drives real packets through the layout via the Gateway.
func TestKernelDataPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	setupTopology(t)
	hostListeners(t)
	resetTable(t)
	remote9000 := net.JoinHostPort(kRemoteIP, "9000")
	if got := dialFromSandbox(t, remote9000); !strings.HasPrefix(got, "OK remote-9000") {
		t.Fatalf("baseline forward broken: %s", got)
	}

	g := New(Options{Backend: NewNFTBackend(), Conntrack: NetlinkConntrack{},
		Layout: LayoutConfig{DNSPort: kDNSPort, ProxyPort: kProxy, FlowSetSize: 8}})
	if err := g.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	sbx := netip.MustParseAddr(kSbxIP)
	if err := g.Attach(Spec{ID: "sb", IP: sbx, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}

	t.Run("unlisted destination is rejected fast", func(t *testing.T) {
		if got := dialFromSandbox(t, remote9000); got != "REFUSED" {
			t.Fatalf("got %s, want REFUSED (TCP reset, CEO D10)", got)
		}
	})
	t.Run("443 is redirected to the proxy", func(t *testing.T) {
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "443")); got != "OK proxy" {
			t.Fatalf("got %s, want the host proxy", got)
		}
	})
	t.Run("DNS to any resolver lands on the filter", func(t *testing.T) {
		got := inNS(t, kSbxNS, "EGK_MODE=udp", "EGK_ADDR=8.8.8.8:53")
		if got != "OK dnsfilter" {
			t.Fatalf("got %s, want the DNS filter", got)
		}
	})
	t.Run("host services are refused", func(t *testing.T) {
		if got := dialFromSandbox(t, net.JoinHostPort(kHostSbx, "21212")); got != "REFUSED" {
			t.Fatalf("got %s, want REFUSED (D7)", got)
		}
	})
	t.Run("rejected flows are recorded for audit", func(t *testing.T) {
		flows, err := NewNFTBackend().List(SetRejectedFlows)
		if err != nil || len(flows) == 0 {
			t.Fatalf("rejected_flows = %+v, %v", flows, err)
		}
	})
	t.Run("allow CIDR forwards directly", func(t *testing.T) {
		if err := g.Update(Spec{ID: "sb", IP: sbx, AllowOut: []string{"pypi.org", kRemoteIP + "/32"}}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); got != "OK remote-9000" {
			t.Fatalf("got %s, want direct forward", got)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "443")); got != "OK remote-443" {
			t.Fatalf("CIDR-allowed 443 must skip the proxy: %s", got)
		}
	})
	t.Run("learned host:port opens one port", func(t *testing.T) {
		if err := g.Update(Spec{ID: "sb", IP: sbx, AllowOut: []string{"github.com:22"}}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); got != "REFUSED" {
			t.Fatalf("before learning: %s", got)
		}
		if err := g.AddLearned("sb", netip.MustParseAddr(kRemoteIP), 22, time.Minute); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); got != "OK remote-22" {
			t.Fatalf("learned port: %s", got)
		}
		if got := dialFromSandbox(t, remote9000); got != "REFUSED" {
			t.Fatalf("other port on the learned IP must stay closed: %s", got)
		}
	})
	t.Run("a per-binary host:port is redirected to the proxy", func(t *testing.T) {
		// P3-3: the flow reaches the proxy, which traces its executable,
		// even with a CIDR allow covering the address.
		spec := Spec{ID: "sb", IP: sbx, AllowOut: []string{"github.com:22", kRemoteIP + "/32"},
			Rules: []egresspolicy.RuleSpec{{Host: "github.com", Ports: []uint16{22}, Binaries: []string{"/usr/bin/git"}}}}
		if err := g.Update(spec); err != nil {
			t.Fatal(err)
		}
		if err := g.LearnFor("sb", "github.com", netip.MustParseAddr(kRemoteIP), 22, time.Minute); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); got != "OK proxy" {
			t.Fatalf("got %s, want the host proxy", got)
		}
		if name, ok := g.BinName("sb", netip.AddrPortFrom(netip.MustParseAddr(kRemoteIP), 22)); !ok || name != "github.com" {
			t.Fatalf("BinName = %q %v", name, ok)
		}
		if err := g.Update(Spec{ID: "sb", IP: sbx, AllowOut: []string{"github.com:22"}}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); got != "REFUSED" {
			t.Fatalf("a changed policy flushes the redirect: %s", got)
		}
		// Leave the learned port the next subtests expect.
		if err := g.AddLearned("sb", netip.MustParseAddr(kRemoteIP), 22, time.Minute); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("blocked sandbox is dropped, stays in fqdn_src", func(t *testing.T) {
		if err := g.SetBlocked("sb", BlockQuota, true); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); !strings.HasPrefix(got, "TIMEOUT") {
			t.Fatalf("blocked learned flow: %s, want silent drop", got)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "443")); !strings.HasPrefix(got, "TIMEOUT") {
			t.Fatalf("blocked redirect path: %s, want drop at input (D2)", got)
		}
		if err := g.SetBlocked("sb", BlockQuota, false); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "22")); got != "OK remote-22" {
			t.Fatalf("unblock: %s", got)
		}
	})
	// S10/EF-77: a full rejected_flows set must not turn rejects into accepts.
	t.Run("full audit set keeps rejecting", func(t *testing.T) {
		be := NewNFTBackend()
		var fill []Elem
		for i := 0; i < 8; i++ {
			fill = append(fill, Elem{Src: netip.MustParseAddr("10.9.9.9"), Dst: netip.AddrFrom4([4]byte{10, 9, 9, byte(i)}), Port: 1, Timeout: time.Minute})
		}
		for _, e := range fill {
			// One element per transaction: the set may already hold flows
			// from earlier subtests, and the kernel refuses an insert into a
			// full set with ENFILE.
			_ = be.Apply([]Op{{Set: SetRejectedFlows, Elems: []Elem{e}}})
		}
		if flows, err := be.List(SetRejectedFlows); err != nil || len(flows) != 8 {
			t.Fatalf("rejected_flows not full: %d elements, %v", len(flows), err)
		}
		if got := dialFromSandbox(t, remote9000); got != "REFUSED" {
			t.Fatalf("with a full audit set: %s, want REFUSED", got)
		}
	})
	t.Run("detach restores plain forwarding", func(t *testing.T) {
		if err := g.Detach("sb", sbx); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); got != "OK remote-9000" {
			t.Fatalf("after detach: %s", got)
		}
	})
	// §5.10 PC-2: the node-wide floor and control-port guard apply to a
	// sandbox that is not in gateway mode at all (it was just detached).
	t.Run("node-wide floor drops for every sandbox", func(t *testing.T) {
		sbxNet := netip.MustParsePrefix(kSbxIP + "/24")
		if err := g.SetNodeWide(NodeWide{Subnets: []netip.Prefix{sbxNet}, Floor: []netip.Prefix{netip.MustParsePrefix(kRemoteIP + "/32")}}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); !strings.HasPrefix(got, "TIMEOUT") {
			t.Fatalf("floor: %s, want a silent drop", got)
		}
		if err := g.SetNodeWide(NodeWide{Subnets: []netip.Prefix{sbxNet}, ControlKnown: true}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); got != "OK remote-9000" {
			t.Fatalf("floor cleared: %s", got)
		}
	})
	t.Run("control-port guard drops other nodes and this host", func(t *testing.T) {
		sbxNet := netip.MustParsePrefix(kSbxIP + "/24")
		ctl := []netip.AddrPort{
			netip.AddrPortFrom(netip.MustParseAddr(kRemoteIP), 9000),  // another node's control port
			netip.AddrPortFrom(netip.MustParseAddr(kHostSbx), kProxy), // this host
		}
		if err := g.SetNodeWide(NodeWide{Subnets: []netip.Prefix{sbxNet}, Control: ctl, ControlKnown: true}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); !strings.HasPrefix(got, "TIMEOUT") {
			t.Fatalf("remote control port: %s, want dropped", got)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kRemoteIP, "443")); got != "OK remote-443" {
			t.Fatalf("ingress-style ports stay reachable: %s", got)
		}
		if got := dialFromSandbox(t, net.JoinHostPort(kHostSbx, fmt.Sprint(kProxy))); !strings.HasPrefix(got, "TIMEOUT") {
			t.Fatalf("local control port: %s, want dropped", got)
		}
		if err := g.SetNodeWide(NodeWide{Subnets: []netip.Prefix{sbxNet}, ControlKnown: true}); err != nil {
			t.Fatal(err)
		}
		if got := dialFromSandbox(t, remote9000); got != "OK remote-9000" {
			t.Fatalf("guard cleared: %s", got)
		}
	})
}
