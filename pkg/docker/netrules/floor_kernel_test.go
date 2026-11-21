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
	ResetFloorsForTest()
	t.Cleanup(ResetFloorsForTest)
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
			// The last subtest's floor chains (both slots), so the baseline
			// is open whichever slot it left in use.
			for _, c := range []string{FloorChainFor(subnet), floorSlotB(FloorChainFor(subnet))} {
				_ = exec.Command("iptables", "-D", ChainAerolvmUser, "-j", c).Run()
				_ = exec.Command("iptables", "-F", c).Run()
			}
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
			// The chain in use: a change fills the other slot and moves the
			// jump, so damage aimed at the floor must aim at this one.
			active := func() string { c, _ := mgr.floorChain.Load().(string); return c }
			// Something takes the floor away (a host firewall reload): the
			// re-assert puts it back, and a floor in place is left alone.
			for _, damage := range []struct {
				name string
				do   func()
			}{
				{"chain and jump deleted", func() { deleteFloorChain(t, ChainAerolvmUser, active()) }},
				{"chain flushed", func() { run(t, "iptables", "-F", active()) }},
			} {
				damage.do()
				if !waitReach() {
					t.Fatalf("%s: the damage did not open the path, so the re-assert proves nothing", damage.name)
				}
				if repaired, err := mgr.ReassertFloor(); !repaired || err != nil {
					t.Fatalf("%s: re-assert repaired=%v err=%v", damage.name, repaired, err)
				}
				if canReach() {
					t.Fatalf("%s: the re-assert must drop the path again", damage.name)
				}
				if repaired, err := mgr.ReassertFloor(); repaired || err != nil {
					t.Fatalf("%s: a whole floor must not be rewritten: repaired=%v err=%v", damage.name, repaired, err)
				}
			}
			// A change never opens the path: while the floor is replaced
			// again and again (the new one built in the other slot, then the
			// jump moved), no packet to the floored address gets past the
			// filter table. A witness after it counts the ones that do.
			floorChangeKeepsDropping(t, mgr, subnet, floor, sbxNS)
			// Replacing is whole-chain: a second set with the same entry
			// leaves the same two rules (the entry, and the subnet to itself
			// while sandboxes are isolated from each other), not four.
			if err := mgr.SetFloor(subnet, floor); err != nil {
				t.Fatal(err)
			}
			out, _ := exec.Command("iptables", "-S", active()).CombinedOutput()
			if n := strings.Count(string(out), "-j DROP"); n != 2 {
				t.Fatalf("floor rules after a repeat = %d:\n%s", n, out)
			}
			// One jump to a floor slot, first in the user chain: the old
			// slot's jump went with the change.
			user, _ := exec.Command("iptables", "-S", ChainAerolvmUser).CombinedOutput()
			if n := strings.Count(string(user), "-j "+FloorChainFor(subnet)); n != 1 ||
				!strings.HasPrefix(strings.Split(string(user), "\n")[1], "-A "+ChainAerolvmUser+" -j "+active()) {
				t.Fatalf("user chain after a repeat (%d floor jumps):\n%s", n, user)
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

// floorChangeKeepsDropping replaces subnet's floor in a loop (two lists
// that both hold floor) while the sandbox knocks on 10.211.0.2, and fails
// if a knock got past the filter table.
func floorChangeKeepsDropping(t *testing.T, mgr *Manager, subnet netip.Prefix, floor []netip.Prefix, sbxNS string) {
	t.Helper()
	for _, cmd := range []string{"add table inet flwit", "add chain inet flwit wit { type filter hook forward priority 10 ; }",
		"add rule inet flwit wit ip daddr 10.211.0.2 counter"} {
		run(t, append([]string{"nft"}, strings.Fields(cmd)...)...)
	}
	defer func() { _ = exec.Command("nft", "delete", "table", "inet", "flwit").Run() }()
	var lists [2][]netip.Prefix
	for n := range lists {
		lists[n] = append([]netip.Prefix(nil), floor...)
		for i := range 256 {
			lists[n] = append(lists[n], netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + n), byte(i), 0, 0}), 16))
		}
	}
	stop, done := make(chan struct{}), make(chan int)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				done <- n
				return
			default:
			}
			if err := mgr.SetFloor(subnet, lists[n%2]); err != nil {
				t.Errorf("floor change %d: %v", n, err)
			}
			n++
		}
	}()
	_ = exec.Command("ip", "netns", "exec", sbxNS, "bash", "-c", fmt.Sprintf(
		"end=$((SECONDS+3)); while [ $SECONDS -lt $end ]; do timeout 0.05 bash -c 'exec 3<>/dev/tcp/10.211.0.2/%s' 2>/dev/null; done", kSbxPort)).Run()
	close(stop)
	changes := <-done
	out, _ := exec.Command("nft", "list", "chain", "inet", "flwit", "wit").CombinedOutput()
	t.Logf("%d floor changes; witness: %s", changes, strings.Join(strings.Fields(string(out)), " "))
	if changes < 2 || !strings.Contains(string(out), "counter packets 0 ") {
		t.Fatalf("a floor change let traffic to a floored address through (%d changes):\n%s", changes, out)
	}
	if err := mgr.SetFloor(subnet, floor); err != nil {
		t.Fatal(err)
	}
}

// deleteFloorChain removes a floor the way a host firewall reload would:
// every jump to it from parent, then the chain itself (nft, so it works on
// rules either backend wrote).
func deleteFloorChain(t *testing.T, parent, chain string) {
	t.Helper()
	out, err := exec.Command("nft", "-a", "list", "chain", "ip", "filter", parent).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list %s: %v\n%s", parent, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		_, handle, ok := strings.Cut(line, "# handle ")
		if ok && strings.Contains(line, "jump "+chain) {
			run(t, "nft", "delete", "rule", "ip", "filter", parent, "handle", strings.TrimSpace(handle))
		}
	}
	run(t, "nft", "flush", "chain", "ip", "filter", chain)
	run(t, "nft", "delete", "chain", "ip", "filter", chain)
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
