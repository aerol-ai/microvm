//go:build linux && kerneltest

package hostnet

// Real-kernel check and cost of the IPv6-off step, in a privileged Linux
// container:
//
//	go test -tags kerneltest -run KernelDisableIPv6 -bench KernelDisableIPv6 ./internal/network/hostnet/

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func kernelNetns(tb testing.TB, name string) string {
	tb.Helper()
	_ = exec.Command("ip", "netns", "del", name).Run()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		tb.Fatalf("ip netns add: %v: %s", err, out)
	}
	tb.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	for _, args := range [][]string{
		{"ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0"},
		{"ip", "-n", name, "link", "set", "lo", "up"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			tb.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	return "/run/netns/" + name
}

// TestKernelDisableIPv6InNetns: lo loses ::1, an interface added afterwards
// (as CNI ADD adds eth0) never gets an IPv6 address, and the caller's own
// namespace is untouched.
func TestKernelDisableIPv6InNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	path := kernelNetns(t, "v6off-k")
	before, _ := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if out, _ := exec.Command("ip", "-n", "v6off-k", "-6", "addr").CombinedOutput(); !strings.Contains(string(out), "::1") {
		t.Fatalf("precondition: lo has ::1 with IPv6 on:\n%s", out)
	}
	if err := DisableIPv6InNetns(path); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ip", "-n", "v6off-k", "link", "add", "eth0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("add eth0: %v: %s", err, out)
	}
	_ = exec.Command("ip", "-n", "v6off-k", "link", "set", "eth0", "up").Run()
	if out, _ := exec.Command("ip", "-n", "v6off-k", "-6", "addr").CombinedOutput(); strings.Contains(string(out), "inet6") {
		t.Fatalf("IPv6 address after DisableIPv6InNetns:\n%s", out)
	}
	for _, c := range []string{"all", "default", "eth0"} {
		out, _ := exec.Command("ip", "netns", "exec", "v6off-k", "cat", "/proc/sys/net/ipv6/conf/"+c+"/disable_ipv6").CombinedOutput()
		if strings.TrimSpace(string(out)) != "1" {
			t.Fatalf("%s disable_ipv6 = %q", c, out)
		}
	}
	after, _ := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if string(before) != string(after) {
		t.Fatalf("the caller's namespace changed: %q -> %q", before, after)
	}
}

// BenchmarkKernelDisableIPv6InNetns is the step's cost on the create path:
// netns.Host.Realize runs it twice per realized slot.
func BenchmarkKernelDisableIPv6InNetns(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root in a privileged container")
	}
	path := kernelNetns(b, "v6off-b")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := DisableIPv6InNetns(path); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHostHasIPv6 is the per-create check the docker and containerd
// paths make before adding the sysctls.
func BenchmarkHostHasIPv6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SandboxIPv6Sysctls()
	}
}
