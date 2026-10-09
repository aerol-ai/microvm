//go:build linux && kerneltest

package netrules

// Real-kernel test of the operator deny floor (plans/egress-domain-
// filtering.md §5.10 PC-2), run in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run KernelFloor
//
// A "sandbox" netns (10.210.0.2) forwards through the host to a "remote"
// netns (10.211.0.2). The floor must drop that forwarded path for every
// sandbox on the subnet, and clearing it must restore it, on both rule
// backends.

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func floorNS(t *testing.T, ns, hostIf, nsIf, hostIP, nsIP, gw string) {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", ns).Run()
	_ = exec.Command("ip", "link", "del", hostIf).Run()
	run(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", nsIf)
	run(t, "ip", "link", "set", nsIf, "netns", ns)
	run(t, "ip", "addr", "add", hostIP+"/24", "dev", hostIf)
	run(t, "ip", "link", "set", hostIf, "up")
	run(t, "ip", "netns", "exec", ns, "ip", "addr", "add", nsIP+"/24", "dev", nsIf)
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsIf, "up")
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gw)
}

func TestKernelFloor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	const sbxNS, remNS = "aerolvm-fl-sbx", "aerolvm-fl-rem"
	floorNS(t, sbxNS, "flsh", "flss", "10.210.0.1", "10.210.0.2", "10.210.0.1")
	floorNS(t, remNS, "flrh", "flrs", "10.211.0.1", "10.211.0.2", "10.211.0.1")
	run(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// iptables-nft creates the compat filter table on the first chain add
	// (docker or CNI has always done that on a real host).
	run(t, "iptables", "-L", "FORWARD", "-n")
	_ = exec.Command("iptables", "-N", ChainAerolvmUser).Run()

	srv := exec.Command("ip", "netns", "exec", remNS, os.Args[0], "-test.run=TestKernelFloorHelper$")
	srv.Env = append(os.Environ(), "AEROLVM_FLOOR_HELPER=10.211.0.2:"+kSbxPort)
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("helper not ready: %q", line)
	}

	canReach := func() bool {
		out, err := exec.Command("ip", "netns", "exec", sbxNS, "timeout", "2", "bash", "-c",
			fmt.Sprintf("exec 3<>/dev/tcp/10.211.0.2/%s && head -c4 <&3", kSbxPort)).CombinedOutput()
		return err == nil && strings.HasPrefix(string(out), "pong")
	}
	waitReach := func() bool {
		for i := 0; i < 10; i++ {
			if canReach() {
				return true
			}
		}
		return false
	}

	subnet := netip.MustParsePrefix("10.210.0.0/24")
	floor := []netip.Prefix{netip.MustParsePrefix("10.211.0.0/24")}
	for _, backend := range []string{BackendNetlink, BackendExec} {
		t.Run(backend, func(t *testing.T) {
			_ = exec.Command("iptables", "-F", ChainAerolvmFloor).Run()
			mgr, err := NewWithOptions(true, backend, ChainAerolvmUser)
			if err != nil {
				t.Fatal(err)
			}
			if err := mgr.EnsureChain(); err != nil {
				t.Fatal(err)
			}
			if !waitReach() {
				t.Fatal("baseline forwarding broken before the floor")
			}
			if err := mgr.SetFloor(subnet, floor); err != nil {
				t.Fatal(err)
			}
			if canReach() {
				t.Fatal("the floor must drop forwarded traffic from the sandbox subnet")
			}
			// Replacing is whole-chain: a second set with the same entry
			// leaves one rule, not two.
			if err := mgr.SetFloor(subnet, floor); err != nil {
				t.Fatal(err)
			}
			out, _ := exec.Command("iptables", "-S", ChainAerolvmFloor).CombinedOutput()
			if n := strings.Count(string(out), "-j DROP"); n != 1 {
				t.Fatalf("floor rules after a repeat = %d:\n%s", n, out)
			}
			if err := mgr.SetFloor(subnet, nil); err != nil {
				t.Fatal(err)
			}
			if !waitReach() {
				t.Fatal("clearing the floor must restore forwarding")
			}
		})
	}
}

// TestKernelFloorHelper is re-executed inside the remote netns as a tiny
// echo server on AEROLVM_FLOOR_HELPER.
func TestKernelFloorHelper(t *testing.T) {
	addr := os.Getenv("AEROLVM_FLOOR_HELPER")
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
