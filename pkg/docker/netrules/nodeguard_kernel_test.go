//go:build linux && kerneltest

package netrules

// Real-kernel test of the node guard, run in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run KernelNodeGuard
//
// A "sandbox" netns sits on a Linux bridge, like a container on docker0 or
// aerolvm0. The host has the bridge's gateway address and a second
// "private" address on a dummy interface, and runs listeners on every
// address: an allowlisted TCP and UDP port, and a TCP and UDP port standing
// for the node's own agents (an EDR, a log shipper). With the guard on, the
// sandbox reaches only the allowlisted ports, on either address, while the
// host's own connections into the sandbox (sandboxd to the toolbox) still
// get their replies.

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	ngNS      = "aerolvm-ng-sbx"
	ngBridge  = "ngbr0"
	ngGateway = "10.220.0.1"
	ngSandbox = "10.220.0.2"
	ngPrivate = "10.230.0.5"
	ngAllowed = "18090" // tcp, allowlisted
	ngAgent   = "18091" // tcp, the node's own agent
	ngUDPOK   = "18092" // udp, allowlisted
	ngUDPNo   = "18093" // udp, the node's own agent
	ngSbxPort = "18094" // the sandbox's own listener (the toolbox)
)

// TestKernelNodeGuardHelper is re-executed inside the sandbox netns as a
// tiny TCP server on AEROLVM_NODEGUARD_HELPER.
func TestKernelNodeGuardHelper(t *testing.T) {
	addr := os.Getenv("AEROLVM_NODEGUARD_HELPER")
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

func ngServeTCP(t *testing.T, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
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
			_, _ = c.Write([]byte("pong\n"))
			_ = c.Close()
		}
	}()
}

// ngServeUDP answers on one address: a wildcard socket would answer from
// the routed source address, which the sandbox's connected socket ignores.
func ngServeUDP(t *testing.T, addr, port string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte("pong"), from)
		}
	}()
}

// ngSandboxTCP reports whether the sandbox opens a TCP connection to
// addr:port and reads the server's reply.
func ngSandboxTCP(addr, port string) bool {
	out, err := exec.Command("ip", "netns", "exec", ngNS, "timeout", "2", "bash", "-c",
		fmt.Sprintf("exec 3<>/dev/tcp/%s/%s && head -c4 <&3", addr, port)).CombinedOutput()
	return err == nil && strings.HasPrefix(string(out), "pong")
}

// ngSandboxUDP reports whether a datagram from the sandbox to addr:port
// gets an answer.
func ngSandboxUDP(addr, port string) bool {
	out, _ := exec.Command("ip", "netns", "exec", ngNS, "timeout", "2", "bash", "-c",
		fmt.Sprintf("exec 3<>/dev/udp/%s/%s && printf ping >&3 && head -c4 <&3", addr, port)).CombinedOutput()
	return strings.HasPrefix(string(out), "pong")
}

func ngHostToSandbox() bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ngSandbox, ngSbxPort), 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && line == "pong\n"
}

// ngCleanChains removes every chain the guard made, so each backend starts
// from a host that never ran it.
func ngCleanChains(subnet netip.Prefix) {
	for exec.Command("iptables", "-D", "INPUT", "-j", ChainAerolvmNode).Run() == nil {
	}
	chains := NodeChainsFor(subnet)
	for _, c := range []string{ChainAerolvmNode, chains[0], chains[1]} {
		_ = exec.Command("iptables", "-F", c).Run()
	}
	for _, c := range []string{ChainAerolvmNode, chains[0], chains[1]} {
		_ = exec.Command("iptables", "-X", c).Run()
	}
}

func TestKernelNodeGuard(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	// The topology: a bridge with the gateway address, the sandbox's veth
	// on it, and a dummy interface carrying the node's private address.
	_ = exec.Command("ip", "netns", "del", ngNS).Run()
	_ = exec.Command("ip", "link", "del", ngBridge).Run()
	_ = exec.Command("ip", "link", "del", "ngh0").Run()
	_ = exec.Command("ip", "link", "del", "ngpriv0").Run()
	run(t, "ip", "netns", "add", ngNS)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", ngNS).Run()
		_ = exec.Command("ip", "link", "del", ngBridge).Run()
		_ = exec.Command("ip", "link", "del", "ngpriv0").Run()
	})
	run(t, "ip", "link", "add", ngBridge, "type", "bridge")
	run(t, "ip", "addr", "add", ngGateway+"/24", "dev", ngBridge)
	run(t, "ip", "link", "set", ngBridge, "up")
	run(t, "ip", "link", "add", "ngpriv0", "type", "dummy")
	run(t, "ip", "addr", "add", ngPrivate+"/24", "dev", "ngpriv0")
	run(t, "ip", "link", "set", "ngpriv0", "up")
	run(t, "ip", "link", "add", "ngh0", "type", "veth", "peer", "name", "ngs0")
	run(t, "ip", "link", "set", "ngh0", "master", ngBridge)
	run(t, "ip", "link", "set", "ngh0", "up")
	run(t, "ip", "link", "set", "ngs0", "netns", ngNS)
	run(t, "ip", "netns", "exec", ngNS, "ip", "addr", "add", ngSandbox+"/24", "dev", "ngs0")
	run(t, "ip", "netns", "exec", ngNS, "ip", "link", "set", "ngs0", "up")
	run(t, "ip", "netns", "exec", ngNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", ngNS, "ip", "route", "add", "default", "via", ngGateway)
	// iptables-nft creates the compat filter table and its base chains
	// (dockerd or the CNI plugin has always done that on a real node).
	run(t, "iptables", "-L", "INPUT", "-n")
	_ = exec.Command("iptables", "-N", ChainDockerUser).Run()

	for _, p := range []string{ngAllowed, ngAgent} {
		ngServeTCP(t, p)
	}
	for _, a := range []string{ngGateway, ngPrivate} {
		for _, p := range []string{ngUDPOK, ngUDPNo} {
			ngServeUDP(t, a, p)
		}
	}
	srv := exec.Command("ip", "netns", "exec", ngNS, os.Args[0], "-test.run=TestKernelNodeGuardHelper$")
	srv.Env = append(os.Environ(), "AEROLVM_NODEGUARD_HELPER="+net.JoinHostPort(ngSandbox, ngSbxPort))
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("helper not ready: %q", line)
	}

	subnet := netip.MustParsePrefix("10.220.0.0/24")
	allow := []NodePort{{Proto: "tcp", Port: 18090}, {Proto: "udp", Port: 18092}}
	addrs := []string{ngGateway, ngPrivate}

	for _, backend := range []string{BackendNetlink, BackendExec} {
		t.Run(backend, func(t *testing.T) {
			ngCleanChains(subnet)
			t.Cleanup(func() { ngCleanChains(subnet) })
			for _, a := range addrs {
				if !ngSandboxTCP(a, ngAgent) || !ngSandboxUDP(a, ngUDPNo) || !ngHostToSandbox() {
					t.Fatalf("baseline: without the guard the sandbox reaches %s (this is the bug the guard closes)", a)
				}
			}
			mgr, err := NewWithOptions(true, backend, ChainDockerUser)
			if err != nil {
				t.Fatal(err)
			}
			if err := mgr.SetNodeGuard(subnet, allow); err != nil {
				t.Fatal(err)
			}
			check := func(stage string) {
				t.Helper()
				for _, a := range addrs {
					if ngSandboxTCP(a, ngAgent) {
						t.Errorf("%s: the sandbox reached the node's agent at %s:%s", stage, a, ngAgent)
					}
					if ngSandboxUDP(a, ngUDPNo) {
						t.Errorf("%s: the sandbox got a UDP answer from %s:%s", stage, a, ngUDPNo)
					}
					if !ngSandboxTCP(a, ngAllowed) {
						t.Errorf("%s: the allowlisted tcp port %s:%s is closed", stage, a, ngAllowed)
					}
					if !ngSandboxUDP(a, ngUDPOK) {
						t.Errorf("%s: the allowlisted udp port %s:%s is closed", stage, a, ngUDPOK)
					}
				}
				if !ngHostToSandbox() {
					t.Errorf("%s: the host's own connection into the sandbox got no reply (toolbox path)", stage)
				}
			}
			check("guard on")

			// Something flushes the guard: the sandbox is open again until
			// the re-assert puts it back.
			run(t, "iptables", "-F", ChainAerolvmNode)
			if !ngSandboxTCP(ngGateway, ngAgent) {
				t.Fatal("a flushed guard chain should have opened the node (the test is not testing anything)")
			}
			repaired, err := mgr.ReassertNodeGuard()
			if err != nil || !repaired {
				t.Fatalf("re-assert after a flush: repaired=%v err=%v", repaired, err)
			}
			check("after re-assert")
			if repaired, err := mgr.ReassertNodeGuard(); err != nil || repaired {
				t.Fatalf("an intact guard is not rebuilt: repaired=%v err=%v", repaired, err)
			}

			// A host firewall reload puts its own rule above ours: the
			// re-assert moves the jump back to the top.
			run(t, "iptables", "-I", "INPUT", "1", "-s", "10.220.0.0/24", "-j", "ACCEPT")
			if !ngSandboxTCP(ngPrivate, ngAgent) {
				t.Fatal("an ACCEPT above the guard should have opened the node")
			}
			if _, err := mgr.ReassertNodeGuard(); err != nil {
				t.Fatal(err)
			}
			check("after the jump moved back to the top")
			run(t, "iptables", "-D", "INPUT", "-s", "10.220.0.0/24", "-j", "ACCEPT")

			// A new allowlist swaps chains without opening anything.
			if err := mgr.SetNodeGuard(subnet, []NodePort{{Proto: "tcp", Port: 18091}}); err != nil {
				t.Fatal(err)
			}
			if !ngSandboxTCP(ngGateway, ngAgent) || ngSandboxTCP(ngGateway, ngAllowed) || ngSandboxUDP(ngGateway, ngUDPOK) {
				t.Fatal("after a new allowlist only its port answers")
			}
			out, _ := exec.Command("iptables", "-S", ChainAerolvmNode).CombinedOutput()
			if strings.Count(string(out), "-j "+ChainAerolvmNode+"-") != 1 {
				t.Fatalf("one jump per subnet after a swap:\n%s", out)
			}
			if !ngHostToSandbox() {
				t.Fatal("toolbox path after the swap")
			}
		})
	}
}
