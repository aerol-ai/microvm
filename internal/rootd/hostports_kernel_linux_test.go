//go:build linux

package rootd

// Raw-TCP host-port forwarding through the helper on the real kernel, as
// root in a privileged container with the real CNI plugins
// (AEROL_KT_CNI_DIR): a connection to the node's host port reaches the
// sandbox's listener; a removed port and a helper restart leave nothing;
// and the helper refuses to forward to the node's own address.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestKernelEchoHelper is re-executed inside a sandbox's namespace as a
// tiny server on AEROL_ECHO_ADDR: "pong" to every connection.
func TestKernelEchoHelper(t *testing.T) {
	addr := os.Getenv("AEROL_ECHO_ADDR")
	if addr == "" {
		t.Skip("helper")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("READY")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("pong\n"))
		_ = c.Close()
	}
}

// echoIn starts the echo server in the namespace at nsPath, on port.
func echoIn(t *testing.T, nsPath string, port int) {
	t.Helper()
	srv := exec.Command("nsenter", "--net="+nsPath, "--", os.Args[0], "-test.run=^TestKernelEchoHelper$")
	srv.Env = append(os.Environ(), fmt.Sprintf("AEROL_ECHO_ADDR=:%d", port))
	out, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(out).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("echo helper not ready: %q", line)
	}
}

// dialPong reports whether addr answers "pong" within a second.
func dialPong(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line == "pong\n"
}

func hostPortRules(t *testing.T) string {
	return shell(t, "iptables", "-w", "-t", "nat", "-S", "AEROLVM-HOSTPORT")
}

func TestKernelHostPorts(t *testing.T) {
	needRoot(t)
	if os.Getenv("AEROL_KT_CNI_DIR") == "" {
		t.Skip("needs the real CNI plugins (a routed sandbox)")
	}
	k := reviewKernelNet(t)
	bounds := rootpolicy.HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215}
	// Whatever this test leaves, the next test's kernel does not get.
	t.Cleanup(func() {
		if b, err := hostport.NewIPTablesBackend(); err == nil {
			_ = hostport.New(b, nil).Reconcile(nil)
		}
	})
	// One of this node's own addresses outside the sandbox range, to offer
	// as a peer.
	const own = "198.51.100.10"
	shell(t, "ip", "addr", "add", own+"/32", "dev", "lo")
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", own+"/32", "dev", "lo").Run() })
	helper := func() (*rig, rootdpb.RootHelperClient) {
		r := newRig(t, func(c *Config, o *Options) {
			c.Policy.NetnsDir = k.netnsDir
			c.HostPorts = bounds
			o.Network = k
		})
		return r, rootdpb.NewRootHelperClient(r.conn)
	}
	r1, c := helper()
	ctx := callCtx(t)
	sb, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	echoIn(t, sb.GetNetnsPath(), 5432)
	node := k.Subnet().Masked().Addr().Next().String() // the bridge's address: this node's own
	set := func(c rootdpb.RootHelperClient, f *rootdpb.HostPortForward) error {
		_, err := c.HostPort(callCtx(t), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET, Forwards: []*rootdpb.HostPortForward{f}})
		return err
	}
	if err := set(c, &rootdpb.HostPortForward{HostPort: 22000, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX, Address: sb.GetContainerIp(), Port: 5432}); err != nil {
		t.Fatal(err)
	}
	if !dialPong(node + ":22000") {
		t.Fatalf("the node's host port does not reach the sandbox:\n%s", hostPortRules(t))
	}
	// The same again: one rule, not two.
	if err := set(c, &rootdpb.HostPortForward{HostPort: 22000, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX, Address: sb.GetContainerIp(), Port: 5432}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(hostPortRules(t), "aerolvm-hp-22000"); n != 1 {
		t.Fatalf("%d NAT rules for host port 22000 after a repeat:\n%s", n, hostPortRules(t))
	}
	// The node's own address as a peer: refused, nothing written.
	err = set(c, &rootdpb.HostPortForward{HostPort: 22001, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_PEER, Address: own, Port: 22001})
	wantRefusal(t, r1, err, codes.PermissionDenied, string(rootpolicy.RuleHostPort))
	if strings.Contains(hostPortRules(t), "aerolvm-hp-22001") {
		t.Fatal("a refused forward was written")
	}
	// A helper restart: the new helper removes the port the old one
	// forwarded, from the kernel's rules.
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	r1.srv.Shutdown(sctx)
	cancel()
	_, c2 := helper()
	if _, err := c2.HostPort(callCtx(t), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, HostPort: 22000}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hostPortRules(t), "aerolvm-hp-22000") || dialPong(node+":22000") {
		t.Fatalf("a removed host port still forwards:\n%s", hostPortRules(t))
	}
	// A reconcile to a set, then to none (the routing rollback).
	if _, err := c2.HostPort(callCtx(t), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE, Forwards: []*rootdpb.HostPortForward{
		{HostPort: 22002, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX, Address: sb.GetContainerIp(), Port: 5432},
		{HostPort: 22003, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_REDIRECT, Port: 21215},
	}}); err != nil {
		t.Fatal(err)
	}
	if !dialPong(node+":22002") || !strings.Contains(hostPortRules(t), "REDIRECT --to-ports 21215") {
		t.Fatalf("after a reconcile:\n%s", hostPortRules(t))
	}
	if _, err := c2.HostPort(callCtx(t), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hostPortRules(t), "aerolvm-hp-") {
		t.Fatalf("rules left after the rollback:\n%s", hostPortRules(t))
	}
}
