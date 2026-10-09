//go:build linux && kerneltest

package tap

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// The Firecracker egress data path (plans/egress-domain-filtering.md Phase
// 4) on a real kernel: a veth named like a TAP stands in for the VM's
// device, a netns for the guest, another for a remote host.
const (
	fcGuestNS  = "fck-guest"
	fcRemoteNS = "fck-remote"
	fcTap      = "fctap90"
	fcHostIP   = "172.31.0.1"
	fcGuestIP  = "172.31.0.2"
	fcSubnet   = "172.31.0.0/16"
	fcRemHost  = "10.250.0.1"
	fcRemoteIP = "10.250.0.2"
)

func fcrun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// TestFCKernelHelper runs inside a netns: "serve" answers with the peer's
// address, "dial" reports one connect from an optional source.
func TestFCKernelHelper(t *testing.T) {
	switch os.Getenv("FCK_MODE") {
	case "serve":
		ln, err := net.Listen("tcp", os.Getenv("FCK_ADDR"))
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		fmt.Println("READY")
		for {
			c, err := ln.Accept()
			if err != nil {
				os.Exit(0)
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			_, _ = c.Write([]byte("from-" + host + "\n"))
			_ = c.Close()
		}
	case "dial":
		d := net.Dialer{Timeout: 1500 * time.Millisecond}
		if src := os.Getenv("FCK_SRC"); src != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
		}
		c, err := d.Dial("tcp", os.Getenv("FCK_ADDR"))
		if err != nil {
			fmt.Println("FAIL", err)
			os.Exit(0)
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Println("OK", strings.TrimSpace(line))
		os.Exit(0)
	default:
		t.Skip("helper")
	}
}

func fcDial(t *testing.T, src string) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", fcGuestNS, os.Args[0], "-test.run=TestFCKernelHelper$")
	cmd.Env = append(os.Environ(), "FCK_MODE=dial", "FCK_ADDR="+fcRemoteIP+":9000", "FCK_SRC="+src)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(strings.Split(string(out), "\n")[0])
}

func TestKernelFirecrackerEgress(t *testing.T) {
	for _, ns := range []string{fcGuestNS, fcRemoteNS} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		fcrun(t, "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}
	// The "TAP": a routed /30, the guest end in its own netns.
	_ = exec.Command("ip", "link", "del", fcTap).Run()
	fcrun(t, "ip", "link", "add", fcTap, "type", "veth", "peer", "name", "fck-g0")
	fcrun(t, "ip", "link", "set", "fck-g0", "netns", fcGuestNS)
	fcrun(t, "ip", "addr", "add", fcHostIP+"/30", "dev", fcTap)
	fcrun(t, "ip", "link", "set", fcTap, "up")
	fcrun(t, "ip", "netns", "exec", fcGuestNS, "ip", "addr", "add", fcGuestIP+"/30", "dev", "fck-g0")
	fcrun(t, "ip", "netns", "exec", fcGuestNS, "ip", "link", "set", "fck-g0", "up")
	fcrun(t, "ip", "netns", "exec", fcGuestNS, "ip", "link", "set", "lo", "up")
	fcrun(t, "ip", "netns", "exec", fcGuestNS, "ip", "route", "add", "default", "via", fcHostIP)
	// The remote, on another link the host routes to.
	_ = exec.Command("ip", "link", "del", "fck-r0").Run()
	fcrun(t, "ip", "link", "add", "fck-r0", "type", "veth", "peer", "name", "fck-r1")
	fcrun(t, "ip", "link", "set", "fck-r1", "netns", fcRemoteNS)
	fcrun(t, "ip", "addr", "add", fcRemHost+"/24", "dev", "fck-r0")
	fcrun(t, "ip", "link", "set", "fck-r0", "up")
	fcrun(t, "ip", "netns", "exec", fcRemoteNS, "ip", "addr", "add", fcRemoteIP+"/24", "dev", "fck-r1")
	fcrun(t, "ip", "netns", "exec", fcRemoteNS, "ip", "link", "set", "fck-r1", "up")
	fcrun(t, "ip", "netns", "exec", fcRemoteNS, "ip", "link", "set", "lo", "up")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", fcTap).Run()
		_ = exec.Command("ip", "link", "del", "fck-r0").Run()
	})
	fcrun(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	srv := exec.Command("ip", "netns", "exec", fcRemoteNS, os.Args[0], "-test.run=TestFCKernelHelper$")
	srv.Env = append(os.Environ(), "FCK_MODE=serve", "FCK_ADDR="+fcRemoteIP+":9000")
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("remote not ready: %q", line)
	}

	ipt, err := iptables.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureNAT(ipt, fcSubnet); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ipt.Delete("nat", "POSTROUTING", "-s", fcSubnet, "!", "-d", fcSubnet, "-m", "comment", "--comment", natComment, "-j", "MASQUERADE")
	})
	rules, err := netrules.NewWithOptions(true, netrules.BackendExec, netrules.ChainAerolvmFC)
	if err != nil {
		t.Fatal(err)
	}
	rules.SetBridgeSubnet(fcSubnet)
	if err := rules.EnsureChain(); err != nil {
		t.Fatal(err)
	}

	t.Run("the guest reaches out, masqueraded", func(t *testing.T) {
		if got := fcDial(t, ""); got != "OK from-"+fcRemHost {
			t.Fatalf("got %q, want the host's address on the remote link", got)
		}
	})
	t.Run("block-all on the guest IP", func(t *testing.T) {
		if err := rules.BlockAllEgress(fcGuestIP); err != nil {
			t.Fatal(err)
		}
		if got := fcDial(t, ""); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("blocked guest: %q", got)
		}
		if err := rules.ClearBlockAllEgress(fcGuestIP); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("CIDR allowlist on the guest IP", func(t *testing.T) {
		if err := rules.ApplyEgressPolicy(fcGuestIP, []string{"10.251.0.0/24"}, []string{"0.0.0.0/0"}); err != nil {
			t.Fatal(err)
		}
		if got := fcDial(t, ""); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("outside the allowlist: %q", got)
		}
		if err := rules.ClearEgressPolicy(fcGuestIP, []string{"10.251.0.0/24"}, []string{"0.0.0.0/0"}); err != nil {
			t.Fatal(err)
		}
		if err := rules.ApplyEgressPolicy(fcGuestIP, []string{"10.250.0.0/24"}, []string{"0.0.0.0/0"}); err != nil {
			t.Fatal(err)
		}
		if got := fcDial(t, ""); got != "OK from-"+fcRemHost {
			t.Fatalf("inside the allowlist: %q", got)
		}
		_ = rules.ClearEgressPolicy(fcGuestIP, []string{"10.250.0.0/24"}, []string{"0.0.0.0/0"})
	})
	t.Run("rp_filter drops a forged source", func(t *testing.T) {
		const spoof = "172.31.0.6"
		fcrun(t, "ip", "netns", "exec", fcGuestNS, "ip", "addr", "add", spoof+"/32", "dev", "fck-g0")
		if got := fcDial(t, spoof); got != "OK from-"+fcRemHost {
			t.Logf("before rp_filter: %q (loose path)", got)
		}
		if err := setStrictRPFilter(fcTap); err != nil {
			t.Fatal(err)
		}
		if got := fcDial(t, spoof); !strings.HasPrefix(got, "FAIL") {
			t.Fatalf("a forged source must be dropped: %q", got)
		}
		if got := fcDial(t, ""); got != "OK from-"+fcRemHost {
			t.Fatalf("the guest's own address still works: %q", got)
		}
	})
}
