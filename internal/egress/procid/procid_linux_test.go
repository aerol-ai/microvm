//go:build linux

package procid

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// TestMatcherRealSocket traces one of this test's own TCP connections:
// the real /proc, the real cgroup tree and openat2 RESOLVE_IN_ROOT.
func TestMatcherRealSocket(t *testing.T) {
	if b, err := os.ReadFile("/proc/self/cgroup"); err != nil || !strings.HasPrefix(string(b), "0::") {
		t.Skip("needs cgroup v2")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	remote := netip.MustParseAddrPort(c.RemoteAddr().String())
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	is, err := Resolver{}.Matcher(os.Getpid(), local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if !is(exe) || is("/bin/sh") {
		t.Fatalf("is(%s) must be true and is(/bin/sh) false", exe)
	}
}
