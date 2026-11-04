//go:build linux

package procid

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// TestLookupAcrossUsers (review finding 16): the gateway's unprivileged user
// can't read another user's /proc/<pid>/fd, so tracing a sandbox process
// itself finds no owner; asking root over the socket does. Needs root (a
// privileged container); the helper runs as nobody (65534).
func TestLookupAcrossUsers(t *testing.T) {
	if os.Getenv("PROCID_HELPER") == "1" {
		lookupHelper()
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the helper as another user")
	}
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
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A world-readable copy of the test binary, and a socket nobody can use.
	dir, err := os.MkdirTemp("", "procid-xuser")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "helper")
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "procid.sock")
	sl, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Authorize: func(string) (int, []string, error) { return os.Getpid(), []string{exe}, nil }}
	go func() { _ = srv.Serve(sl) }()

	cmd := exec.Command(helper, "-test.run=TestLookupAcrossUsers$")
	cmd.Env = append(os.Environ(), "PROCID_HELPER=1", "PROCID_SOCK="+sock, "PROCID_PID="+strconv.Itoa(os.Getpid()),
		"PROCID_LOCAL="+c.LocalAddr().String(), "PROCID_REMOTE="+c.RemoteAddr().String(), "PROCID_EXE="+exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "DIRECT=refused") || !strings.Contains(string(out), "REMOTE=true") {
		t.Fatalf("helper output:\n%s", out)
	}
}

// lookupHelper runs as nobody: it traces the parent's connection directly,
// then through the socket, and prints both outcomes.
func lookupHelper() {
	local := netip.MustParseAddrPort(os.Getenv("PROCID_LOCAL"))
	remote := netip.MustParseAddrPort(os.Getenv("PROCID_REMOTE"))
	pid, _ := strconv.Atoi(os.Getenv("PROCID_PID"))
	exe := os.Getenv("PROCID_EXE")
	direct := "refused"
	if is, err := (Resolver{}).Matcher(pid, local, remote); err == nil && is(exe) {
		direct = "allowed"
	}
	remoteOK := false
	if is, err := (Client{Path: os.Getenv("PROCID_SOCK")}).Match("sb", local, remote, []string{exe}); err == nil {
		remoteOK = is(exe)
	}
	fmt.Printf("DIRECT=%s REMOTE=%v\n", direct, remoteOK)
	os.Exit(0)
}
