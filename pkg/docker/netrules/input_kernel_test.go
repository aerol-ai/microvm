//go:build linux && kerneltest

package netrules

// Real-kernel regression test for P0-5, run in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run Kernel
//
// It builds a veth pair into a test netns and proves that once a sandbox IP
// is block-all'd, NEW connections from the sandbox to the host are dropped
// while replies to host-initiated connections (the sandboxd→toolboxd path)
// still flow, and that the clear restores host reachability.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	kNS       = "aerolvm-p05"
	kHostIP   = "10.200.0.1"
	kSandbox  = "10.200.0.2"
	kHostPort = "18080"
	kSbxPort  = "18081"
)

func run(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// TestKernelHelperServe is re-executed inside the netns as a tiny echo server.
func TestKernelHelperServe(t *testing.T) {
	if os.Getenv("AEROLVM_KERNEL_HELPER") != "serve" {
		t.Skip("helper")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(kSandbox, kSbxPort))
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

func sandboxCanDialHost() bool {
	cmd := exec.Command("ip", "netns", "exec", kNS, "timeout", "2", "bash", "-c",
		fmt.Sprintf("exec 3<>/dev/tcp/%s/%s && head -c4 <&3", kHostIP, kHostPort))
	out, err := cmd.CombinedOutput()
	return err == nil && strings.HasPrefix(string(out), "pong")
}

func hostCanDialSandbox() bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(kSandbox, kSbxPort), 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && line == "pong\n"
}

func TestKernelBlockAllGuardsHostInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	_ = exec.Command("ip", "netns", "del", kNS).Run()
	run(t, "ip", "netns", "add", kNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", kNS).Run() })
	_ = exec.Command("ip", "link", "del", "p05h").Run()
	run(t, "ip", "link", "add", "p05h", "type", "veth", "peer", "name", "p05s")
	run(t, "ip", "link", "set", "p05s", "netns", kNS)
	run(t, "ip", "addr", "add", kHostIP+"/24", "dev", "p05h")
	run(t, "ip", "link", "set", "p05h", "up")
	run(t, "ip", "netns", "exec", kNS, "ip", "addr", "add", kSandbox+"/24", "dev", "p05s")
	run(t, "ip", "netns", "exec", kNS, "ip", "link", "set", "p05s", "up")
	run(t, "ip", "netns", "exec", kNS, "ip", "link", "set", "lo", "up")
	// iptables-nft creates the compat filter table and its base chains.
	run(t, "iptables", "-L", "INPUT", "-n")
	_ = exec.Command("iptables", "-N", ChainDockerUser).Run()

	hostLn, err := net.Listen("tcp", net.JoinHostPort(kHostIP, kHostPort))
	if err != nil {
		t.Fatal(err)
	}
	defer hostLn.Close()
	go func() {
		for {
			c, err := hostLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("pong\n"))
			_ = c.Close()
		}
	}()
	srv := exec.Command("ip", "netns", "exec", kNS, os.Args[0], "-test.run=TestKernelHelperServe$")
	srv.Env = append(os.Environ(), "AEROLVM_KERNEL_HELPER=serve")
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); !strings.HasPrefix(line, "READY") {
		t.Fatalf("helper not ready: %q", line)
	}

	for _, backend := range []string{BackendNetlink, BackendExec} {
		t.Run(backend, func(t *testing.T) {
			mgr, err := NewWithOptions(true, backend, ChainDockerUser)
			if err != nil {
				t.Fatal(err)
			}
			if !sandboxCanDialHost() || !hostCanDialSandbox() {
				t.Fatal("baseline connectivity broken before any rule")
			}
			if err := mgr.BlockAllEgress(kSandbox); err != nil {
				t.Fatal(err)
			}
			if sandboxCanDialHost() {
				t.Fatal("block-all sandbox still opened a connection to a host service")
			}
			if !hostCanDialSandbox() {
				t.Fatal("block-all cut replies to a host-initiated connection (toolbox path)")
			}
			if err := mgr.ClearBlockAllEgress(kSandbox); err != nil {
				t.Fatal(err)
			}
			if !sandboxCanDialHost() {
				t.Fatal("clear did not restore host reachability")
			}
		})
	}
}
