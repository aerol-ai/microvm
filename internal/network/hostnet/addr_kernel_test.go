//go:build linux && kerneltest

package hostnet

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
)

// Real-kernel check and cost of the address read, in a privileged Linux
// container:
//
//	go test -tags kerneltest -run KernelNetnsIPv4Addrs -bench KernelNetnsIPv4Addrs ./internal/network/hostnet/

// TestKernelNetnsIPv4Addrs reads the address of a real namespace from
// outside it, leaves out loopback, and leaves the caller where it was.
func TestKernelNetnsIPv4Addrs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	path := kernelNetns(t, "addr-k")
	for _, args := range [][]string{
		{"ip", "-n", "addr-k", "link", "add", "eth0", "type", "dummy"},
		{"ip", "-n", "addr-k", "addr", "add", "10.88.0.2/16", "dev", "eth0"},
		{"ip", "-n", "addr-k", "link", "set", "eth0", "up"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	before, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	got, err := NetnsIPv4Addrs(path)
	if err != nil || strings.Join(got, ",") != "10.88.0.2" {
		t.Fatalf("addrs=%v err=%v", got, err)
	}
	after, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if !before.Equal(after) {
		t.Fatal("the caller's thread changed network namespace")
	}
	// A fresh namespace (only lo) holds nothing.
	if got, err := NetnsIPv4Addrs(kernelNetns(t, "addr-k2")); err != nil || len(got) != 0 {
		t.Fatalf("empty netns: addrs=%v err=%v", got, err)
	}
}

// BenchmarkKernelNetnsIPv4Addrs is the cost of the check the netns pool's
// boot reconcile runs once per surviving warm slot.
func BenchmarkKernelNetnsIPv4Addrs(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root in a privileged container")
	}
	path := kernelNetns(b, "addr-kb")
	for _, args := range [][]string{
		{"ip", "-n", "addr-kb", "link", "add", "eth0", "type", "dummy"},
		{"ip", "-n", "addr-kb", "addr", "add", "10.88.0.2/16", "dev", "eth0"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			b.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NetnsIPv4Addrs(path); err != nil {
			b.Fatal(err)
		}
	}
}
