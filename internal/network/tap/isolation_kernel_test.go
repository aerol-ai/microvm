//go:build linux && kerneltest

package tap

// Guest isolation on a real kernel, as root:
//
//	sudo go test -tags kerneltest ./internal/network/tap/ -run KernelIsolation
//
// Two "guests" sit on routed /30s behind veths named like TAPs, a
// "container" on a link of its own in 10.88.0.0/16. filter FORWARD gets
// ACCEPTs for both subnets on top, the way AEROLVM-FC and AEROLVM-USER
// accept their whole subnet: the drops must hold anyway.

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

const (
	isoNSA       = "fci-a"
	isoNSB       = "fci-b"
	isoNSCtr     = "fci-ctr"
	isoSubnet    = "172.30.0.0/16"
	isoHostA     = "172.30.0.1"
	isoGuestA    = "172.30.0.2"
	isoHostB     = "172.30.0.5"
	isoGuestB    = "172.30.0.6"
	isoCtrSubnet = "10.88.250.0/24"
	isoCtrHost   = "10.88.250.1"
	isoCtr       = "10.88.250.2"
)

func isoLink(t *testing.T, ns, hostDev, nsDev, hostAddr, nsAddr, gw string) {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", ns).Run()
	fcrun(t, "ip", "netns", "add", ns)
	_ = exec.Command("ip", "link", "del", hostDev).Run()
	fcrun(t, "ip", "link", "add", hostDev, "type", "veth", "peer", "name", nsDev)
	fcrun(t, "ip", "link", "set", nsDev, "netns", ns)
	fcrun(t, "ip", "addr", "add", hostAddr, "dev", hostDev)
	fcrun(t, "ip", "link", "set", hostDev, "up")
	fcrun(t, "ip", "netns", "exec", ns, "ip", "addr", "add", nsAddr, "dev", nsDev)
	fcrun(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsDev, "up")
	fcrun(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	fcrun(t, "ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gw)
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", hostDev).Run()
		_ = exec.Command("ip", "netns", "del", ns).Run()
	})
}

// isoServe runs a TCP listener in ns at addr (the agent's port).
func isoServe(t *testing.T, ns, addr string) {
	t.Helper()
	srv := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=TestFCKernelHelper$")
	srv.Env = append(os.Environ(), "FCK_MODE=serve", "FCK_ADDR="+addr)
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("listener in %s not ready: %q", ns, line)
	}
}

// isoDial reports "OK ..." or "FAIL ..." for one TCP connect; ns "" dials
// from the host itself.
func isoDial(t *testing.T, ns, addr string) string {
	t.Helper()
	args := []string{os.Args[0], "-test.run=TestFCKernelHelper$"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "FCK_MODE=dial", "FCK_ADDR="+addr)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(strings.Split(string(out), "\n")[0])
}

func isoPing(ns, addr string) bool {
	return exec.Command("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", addr).Run() == nil
}

func TestKernelIsolation(t *testing.T) {
	isoLink(t, isoNSA, "fctapi0", "fci-a0", isoHostA+"/30", isoGuestA+"/30", isoHostA)
	isoLink(t, isoNSB, "fctapi1", "fci-b0", isoHostB+"/30", isoGuestB+"/30", isoHostB)
	isoLink(t, isoNSCtr, "fci-ctr0", "fci-ctr1", isoCtrHost+"/24", isoCtr+"/24", isoCtrHost)
	fcrun(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	isoServe(t, isoNSB, isoGuestB+":2280")
	isoServe(t, isoNSCtr, isoCtr+":8080")

	ipt, err := iptables.New()
	if err != nil {
		t.Fatal(err)
	}
	// The whole-subnet ACCEPTs the FC and containerd chains install, at the
	// top of filter FORWARD.
	accepts := [][]string{{"-s", isoSubnet, "-j", "ACCEPT"}, {"-d", isoSubnet, "-j", "ACCEPT"}, {"-s", isoCtrSubnet, "-j", "ACCEPT"}, {"-d", isoCtrSubnet, "-j", "ACCEPT"}}
	for _, a := range accepts {
		if err := ipt.Insert("filter", "FORWARD", 1, a...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, a := range accepts {
			_ = ipt.Delete("filter", "FORWARD", a...)
		}
		_ = ipt.Delete(isolationTable, "FORWARD", isolationJump...)
		_ = ipt.ClearChain(isolationTable, IsolationChain)
		_ = ipt.DeleteChain(isolationTable, IsolationChain)
	})

	// Before: the ACCEPTs let everything through, which is the finding.
	if got := isoDial(t, isoNSA, isoGuestB+":2280"); !strings.HasPrefix(got, "OK") {
		t.Fatalf("control: guest A could not reach guest B before isolation: %q", got)
	}
	if !isoPing(isoNSA, isoGuestB) || !isoPing(isoNSCtr, isoGuestB) {
		t.Fatal("control: ICMP to guest B did not work before isolation")
	}

	if err := EnsureIsolation(ipt, isoSubnet); err != nil {
		t.Fatal(err)
	}

	t.Run("guest to guest: TCP to the agent port", func(t *testing.T) {
		if got := isoDial(t, isoNSA, isoGuestB+":2280"); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("guest to guest: ICMP echo", func(t *testing.T) {
		if isoPing(isoNSA, isoGuestB) {
			t.Fatal("guest A gets ICMP echo replies from guest B")
		}
	})
	t.Run("container to guest: TCP to the agent port and ICMP", func(t *testing.T) {
		if got := isoDial(t, isoNSCtr, isoGuestB+":2280"); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("got %q", got)
		}
		if isoPing(isoNSCtr, isoGuestB) {
			t.Fatal("the container gets ICMP echo replies from guest B")
		}
	})
	t.Run("host to guest: the toolbox path still works", func(t *testing.T) {
		if got := isoDial(t, "", isoGuestB+":2280"); !strings.HasPrefix(got, "OK") {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("guest egress and its replies still work", func(t *testing.T) {
		if got := isoDial(t, isoNSB, isoCtr+":8080"); !strings.HasPrefix(got, "OK") {
			t.Fatalf("got %q", got)
		}
		if !isoPing(isoNSB, isoCtrHost) {
			t.Fatal("guest B cannot ping a host address")
		}
	})
}
