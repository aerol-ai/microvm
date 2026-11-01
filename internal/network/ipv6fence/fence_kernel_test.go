//go:build linux && kerneltest

package ipv6fence

// Real-kernel reproduction of the IPv6 link-local hole and its fix, run in a
// privileged Linux container:
//
//	docker run --rm --privileged -v "$PWD":/src -w /src golang:1.26-bookworm \
//	  go test -tags kerneltest -run KernelIPv6 -v ./internal/network/ipv6fence/
//
// (the image needs iproute2 and nft). The topology is the live one: two
// sandbox namespaces on one bridge, plus a routed TAP-like link the way a
// Firecracker guest sits on the node. Before the fence, sandbox A reaches
// a listener in sandbox B at fe80::…%eth0 and the node's own listener at
// the bridge's and the link's fe80 addresses, while IPv4 between the
// sandboxes is whatever the IPv4 rules say. With the fence all IPv6 paths
// are dropped and IPv4 is unchanged; each layer (the fence's tables, IPv6
// off inside the namespace, IPv6 off on the host link) holds on its own.

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

const (
	kBridge = "v6kbr0"
	kLink   = "fct6c" // matched by the fence's "fct6*", as fctap* is in production
	kNSA    = "v6k-a"
	kNSB    = "v6k-b"
	kNSC    = "v6k-c"
)

func kRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func kQuiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

func kCleanup() {
	for _, ns := range []string{kNSA, kNSB, kNSC} {
		kQuiet("ip", "netns", "del", ns)
	}
	kQuiet("ip", "link", "del", kBridge)
	kQuiet("ip", "link", "del", kLink)
	kQuiet("nft", "delete", "table", "bridge", TableName)
	kQuiet("nft", "delete", "table", "ip6", TableName)
}

// kSandbox is a namespace whose eth0 is a veth whose host end is host.
func kSandbox(t *testing.T, ns, host, addr string) {
	t.Helper()
	kRun(t, "ip", "netns", "add", ns)
	kRun(t, "ip", "link", "add", host, "type", "veth", "peer", "name", "eth0", "netns", ns)
	// IPv6 on, DAD off, as on the live node before the fix.
	kRun(t, "ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0", "net.ipv6.conf.eth0.disable_ipv6=0", "net.ipv6.conf.eth0.accept_dad=0")
	kRun(t, "ip", "-n", ns, "addr", "add", addr, "dev", "eth0")
	kRun(t, "ip", "-n", ns, "link", "set", "lo", "up")
	kRun(t, "ip", "-n", ns, "link", "set", "eth0", "up")
}

var fe80RE = regexp.MustCompile(`inet6 (fe80::[0-9a-f:]+)/64`)

// kLinkLocal waits for dev's link-local address, in ns ("" = the host).
func kLinkLocal(t *testing.T, ns, dev string) string {
	t.Helper()
	for i := 0; i < 50; i++ {
		if a := linkLocalNow(ns, dev); a != "" {
			return a
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s %s never got a link-local address", ns, dev)
	return ""
}

func linkLocalNow(ns, dev string) string {
	args := []string{"-6", "-o", "addr", "show", "dev", dev, "scope", "link"}
	if ns != "" {
		args = append([]string{"-n", ns}, args...)
	}
	out, _ := exec.Command("ip", args...).CombinedOutput()
	if strings.Contains(string(out), "tentative") {
		return ""
	}
	if m := fe80RE.FindStringSubmatch(string(out)); m != nil {
		return m[1]
	}
	return ""
}

// inNS runs fn on a thread in ns (a socket keeps the namespace it was
// created in, so a listener or dialer made here works from any thread).
func inNS(t *testing.T, ns string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		target, err := netns.GetFromName(ns)
		if err != nil {
			t.Errorf("netns %s: %v", ns, err)
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			t.Errorf("enter %s: %v", ns, err)
			return
		}
		fn() // the thread stays locked and dies with the goroutine
	}()
	<-done
}

func kServe(t *testing.T, ln net.Listener) {
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HELLO\n"))
			_ = c.Close()
		}
	}()
}

func kListen(t *testing.T, ns, network, addr string) {
	t.Helper()
	var ln net.Listener
	var err error
	open := func() { ln, err = net.Listen(network, addr) }
	if ns == "" {
		open()
	} else {
		inNS(t, ns, open)
	}
	if err != nil {
		t.Fatalf("listen %s %s in %q: %v", network, addr, ns, err)
	}
	kServe(t, ln)
}

// kDial connects from ns to addr and reads the greeting.
func kDial(t *testing.T, ns, addr string) error {
	t.Helper()
	var conn net.Conn
	var err error
	inNS(t, ns, func() { conn, err = net.DialTimeout("tcp", addr, 2*time.Second) })
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if line != "HELLO\n" {
		return fmt.Errorf("unexpected greeting %q", line)
	}
	return nil
}

// kReach reports whether a connection from ns to addr gets the greeting.
func kReach(t *testing.T, ns, addr string) bool {
	t.Helper()
	return kDial(t, ns, addr) == nil
}

// kDropped asserts the path is closed by a drop on the way: the SYN goes
// out and nothing comes back. A local error (no route, no address) would
// mean the test never reached the fence.
func kDropped(t *testing.T, ns, addr, what string) {
	t.Helper()
	err := kDial(t, ns, addr)
	var ne net.Error
	if err == nil {
		t.Fatalf("%s (%s)", what, addr)
	}
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("%s: want the SYN dropped (a timeout), got %v; the probe did not reach the fence", what, err)
	}
}

// kIfindex is dev's interface index in ns: the zone of a link-local
// address, numeric so it never goes through Go's interface-name cache
// (which one namespace's lookup fills for every other).
func kIfindex(t *testing.T, ns, dev string) int {
	t.Helper()
	out := kRun(t, "ip", "-n", ns, "-o", "link", "show", "dev", dev)
	var idx int
	if _, err := fmt.Sscanf(out, "%d:", &idx); err != nil || idx == 0 {
		t.Fatalf("ifindex of %s in %s from %q: %v", dev, ns, out, err)
	}
	return idx
}

// kReachWithin retries kReach for up to d: after the fence held a path
// closed, the neighbour entry it starved needs a moment to resolve again.
func kReachWithin(t *testing.T, ns, addr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if kReach(t, ns, addr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func kNoInet6(t *testing.T, ns, dev string) {
	t.Helper()
	out := kRun(t, "ip", "-n", ns, "-6", "-o", "addr", "show", "dev", dev)
	if strings.Contains(out, "inet6") {
		t.Fatalf("%s %s still has an IPv6 address:\n%s", ns, dev, out)
	}
}

func TestKernelIPv6Fence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	kCleanup()
	t.Cleanup(kCleanup)
	// The test's own namespace plays the node: IPv6 on (docker turns it
	// off in a container) so the bridge and the link get fe80 addresses.
	kRun(t, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0", "net.ipv6.conf.default.accept_dad=0")

	kRun(t, "ip", "link", "add", kBridge, "type", "bridge")
	kRun(t, "ip", "addr", "add", "10.231.0.1/24", "dev", kBridge)
	kRun(t, "ip", "link", "set", kBridge, "up")
	kSandbox(t, kNSA, "v6k-ha", "10.231.0.2/24")
	kSandbox(t, kNSB, "v6k-hb", "10.231.0.3/24")
	for _, h := range []string{"v6k-ha", "v6k-hb"} {
		kRun(t, "ip", "link", "set", h, "master", kBridge)
		kRun(t, "ip", "link", "set", h, "up")
	}
	// The routed link, the way a Firecracker TAP sits on the node.
	kSandbox(t, kNSC, kLink, "10.232.0.2/30")
	kRun(t, "ip", "addr", "add", "10.232.0.1/30", "dev", kLink)
	kRun(t, "ip", "link", "set", kLink, "up")

	b6 := kLinkLocal(t, kNSB, "eth0")
	kLinkLocal(t, kNSA, "eth0")
	kLinkLocal(t, kNSC, "eth0")
	br6 := kLinkLocal(t, "", kBridge)
	link6 := kLinkLocal(t, "", kLink)

	kListen(t, kNSB, "tcp4", "0.0.0.0:9998")
	kListen(t, kNSB, "tcp6", "[::]:9999")
	kListen(t, "", "tcp6", "[::]:9997") // a node service on [::], like sshd

	aIf, cIf := kIfindex(t, kNSA, "eth0"), kIfindex(t, kNSC, "eth0")
	bV4 := "10.231.0.3:9998"
	bV6 := fmt.Sprintf("[%s%%%d]:9999", b6, aIf)
	nodeViaBridge := fmt.Sprintf("[%s%%%d]:9997", br6, aIf)
	nodeViaLink := fmt.Sprintf("[%s%%%d]:9997", link6, cIf)

	// The live hole, before any fix: every IPv6 path is open.
	for _, p := range []struct{ ns, addr, what string }{
		{kNSA, bV4, "sandbox A to sandbox B over IPv4"},
		{kNSA, bV6, "sandbox A to sandbox B over link-local"},
		{kNSA, nodeViaBridge, "sandbox A to the node over the bridge's link-local"},
		{kNSC, nodeViaLink, "a guest to the node over its link's link-local"},
	} {
		if !kReach(t, p.ns, p.addr) {
			t.Fatalf("baseline: %s (%s) did not connect; the topology is broken", p.what, p.addr)
		}
		t.Logf("before the fix: %s at %s connects", p.what, p.addr)
	}

	spec, err := Spec{Bridges: []string{kBridge}, Links: []string{"fct6*"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	rules := Plan(spec)
	be := &NFTBackend{}
	if err := be.Apply(rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Logf("fence installed, layers: %s", be.Layers())

	blocked := func(when string) {
		t.Helper()
		for _, p := range []struct{ ns, addr, what string }{
			{kNSA, bV6, "sandbox A reached sandbox B over link-local"},
			{kNSA, nodeViaBridge, "sandbox A reached a node service over the bridge's link-local"},
			{kNSC, nodeViaLink, "a guest reached a node service over its link's link-local"},
		} {
			kDropped(t, p.ns, p.addr, when+": "+p.what)
		}
		if !kReach(t, kNSA, bV4) {
			t.Fatalf("%s: IPv4 between the sandboxes changed (the fence is IPv6 only)", when)
		}
	}
	blocked("with the fence")
	if ok, err := be.Check(rules); err != nil || !ok {
		t.Fatalf("Check right after Apply = %v, %v", ok, err)
	}

	// Idempotent: a second Apply replaces, never stacks.
	if err := be.Apply(rules); err != nil {
		t.Fatal(err)
	}
	out := kRun(t, "nft", "list", "table", "ip6", TableName)
	if n := strings.Count(out, "drop"); n != len(onlyFamily(rules, FamilyIP6)) {
		t.Fatalf("ip6 table after a second Apply has %d drops, want %d:\n%s", n, len(onlyFamily(rules, FamilyIP6)), out)
	}
	if !strings.Contains(out, `comment "aerolvm ipv6 fence:`) {
		t.Fatalf("rules carry no operator-visible comment:\n%s", out)
	}

	// Something flushes the fence: Check notices, the hole is back, and
	// Apply closes it again.
	kRun(t, "nft", "delete", "table", "ip6", TableName)
	kQuiet("nft", "delete", "table", "bridge", TableName)
	if ok, err := be.Check(rules); err != nil || ok {
		t.Fatalf("Check after a flush = %v, %v; want missing", ok, err)
	}
	start := time.Now()
	if !kReachWithin(t, kNSA, bV6, 15*time.Second) {
		t.Fatal("with the tables gone the link-local path should be open again (the fence is what closed it)")
	}
	t.Logf("tables flushed: the link-local path reopened after %s", time.Since(start).Round(time.Millisecond))
	if err := be.Apply(rules); err != nil {
		t.Fatal(err)
	}
	blocked("after the re-apply")

	// Something turns br_netfilter's IPv6 hook off. With the bridge-family
	// table nothing changes; without it the ip6 table no longer sees
	// bridged frames, so Check must call it missing and Apply must turn
	// the hook back on.
	t.Run("br_netfilter_turned_off", func(t *testing.T) {
		kRun(t, "sysctl", "-qw", "net.bridge.bridge-nf-call-ip6tables=0")
		if be.bridgeLayer.Load() {
			kDropped(t, kNSA, bV6, "bridge layer with br_netfilter off")
			if ok, err := be.Check(rules); err != nil || !ok {
				t.Fatalf("Check = %v, %v", ok, err)
			}
			kRun(t, "sysctl", "-qw", "net.bridge.bridge-nf-call-ip6tables=1")
			return
		}
		if ok, err := be.Check(rules); err != nil || ok {
			t.Fatalf("Check with br_netfilter off = %v, %v; want missing", ok, err)
		}
		if err := be.Apply(rules); err != nil {
			t.Fatal(err)
		}
		blocked("after Apply turned br_netfilter back on")
	})

	// The bridge-family table holds on its own, with br_netfilter not
	// handing bridged frames to the ip6 hooks at all.
	t.Run("bridge_table_alone", func(t *testing.T) {
		if !be.bridgeLayer.Load() {
			t.Skip("this kernel refuses `meta ibrname` (no nft_meta_bridge); the ip6 table via br_netfilter holds instead (checked above)")
		}
		kRun(t, "nft", "delete", "table", "ip6", TableName)
		kRun(t, "sysctl", "-qw", "net.bridge.bridge-nf-call-ip6tables=0")
		defer kRun(t, "sysctl", "-qw", "net.bridge.bridge-nf-call-ip6tables=1")
		kDropped(t, kNSA, bV6, "the bridge-family table alone must drop IPv6 between the ports")
		kDropped(t, kNSA, nodeViaBridge, "the bridge-family table alone must drop IPv6 from a port to the node")
		if !kReach(t, kNSA, bV4) {
			t.Fatal("IPv4 changed")
		}
		if err := be.Apply(rules); err != nil {
			t.Fatal(err)
		}
	})

	// The sandbox-side layer alone: no fence tables, IPv6 off inside the
	// namespaces (what netns.Host.Realize and the runtimes' sysctls do)
	// and on the node's end of the link (what tap.Host.Ensure does).
	kRun(t, "nft", "delete", "table", "ip6", TableName)
	kQuiet("nft", "delete", "table", "bridge", TableName)
	if !kReachWithin(t, kNSA, bV6, 15*time.Second) {
		t.Fatal("precondition: the hole is open again without the tables")
	}
	// C keeps IPv6 on, as a guest's root could: the node's end of its link
	// alone must hold.
	for _, ns := range []string{kNSA, kNSB} {
		if err := hostnet.DisableIPv6InNetns("/run/netns/" + ns); err != nil {
			t.Fatalf("DisableIPv6InNetns(%s): %v", ns, err)
		}
		kNoInet6(t, ns, "eth0")
		kNoInet6(t, ns, "lo")
	}
	if err := hostnet.DisableIPv6OnLink(kLink); err != nil {
		t.Fatal(err)
	}
	if a := linkLocalNow("", kLink); a != "" {
		t.Fatalf("the node's end of the link kept %s", a)
	}
	if err := kDial(t, kNSA, bV6); err == nil {
		t.Fatal("with IPv6 off inside the namespaces, A still reached B over link-local")
	} else {
		t.Logf("IPv6 off in the namespaces: A to B over link-local fails: %v", err)
	}
	// The guest still has IPv6 and still sends; the node, with IPv6 off
	// on its end, answers nothing.
	kDropped(t, kNSC, nodeViaLink, "with IPv6 off on the node's end of the link, the guest still reached the node")
	if !kReach(t, kNSA, bV4) {
		t.Fatal("IPv4 changed")
	}
}
