//go:build linux

package hostnet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureForwardingSysctlsWritesBrNetfilter(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "ip_forward"),
		filepath.Join(dir, "bridge-nf-call-iptables"),
		filepath.Join(dir, "bridge-nf-call-ip6tables"),
	}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := sysctlPaths
	sysctlPaths = paths
	defer func() { sysctlPaths = orig }()

	if err := EnsureForwardingSysctls(); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "1" {
			t.Fatalf("%s = %q, want 1", p, body)
		}
	}
}

func TestFlushConntrackForIPInvokesConntrack(t *testing.T) {
	var calls [][]string
	orig := execConntrack
	execConntrack = func(args ...string) error {
		calls = append(calls, append([]string{}, args...))
		return nil
	}
	defer func() { execConntrack = orig }()

	if err := FlushConntrackForIP("10.88.0.5"); err != nil {
		t.Fatal(err)
	}
	// Must flush BOTH directions so a reused IP does not inherit stale ingress
	// conntrack (the -d flush is the blackhole fix).
	var sawSrc, sawDst bool
	for _, c := range calls {
		if len(c) == 3 && c[0] == "-D" && c[2] == "10.88.0.5" {
			switch c[1] {
			case "-s":
				sawSrc = true
			case "-d":
				sawDst = true
			}
		}
	}
	if !sawSrc || !sawDst {
		t.Fatalf("conntrack flush missing a direction (src=%v dst=%v): %#v", sawSrc, sawDst, calls)
	}
}

func TestEnsureForwardingSysctlsModprobesWhenBridgeAbsent(t *testing.T) {
	dir := t.TempDir()
	ipf := filepath.Join(dir, "ip_forward")
	bridge := filepath.Join(dir, "bridge-nf-call-iptables") // absent → triggers modprobe
	if err := os.WriteFile(ipf, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := sysctlPaths
	sysctlPaths = []string{ipf, bridge}
	defer func() { sysctlPaths = orig }()

	loaded := ""
	origMod := execModprobe
	execModprobe = func(module string) error {
		loaded = module
		// Simulate br_netfilter loading, creating the bridge sysctl path.
		return os.WriteFile(bridge, []byte("0"), 0o644)
	}
	defer func() { execModprobe = origMod }()

	if err := EnsureForwardingSysctls(); err != nil {
		t.Fatal(err)
	}
	if loaded != "br_netfilter" {
		t.Fatalf("expected br_netfilter modprobe, got %q", loaded)
	}
}

func TestEnsureForwardingSysctlsFailsLoudWhenBridgeStillAbsent(t *testing.T) {
	dir := t.TempDir()
	ipf := filepath.Join(dir, "ip_forward")
	bridge := filepath.Join(dir, "bridge-nf-call-iptables") // never created
	if err := os.WriteFile(ipf, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := sysctlPaths
	sysctlPaths = []string{ipf, bridge}
	defer func() { sysctlPaths = orig }()

	origMod := execModprobe
	execModprobe = func(string) error { return nil } // modprobe "succeeds" but path stays absent
	defer func() { execModprobe = origMod }()

	if err := EnsureForwardingSysctls(); err == nil {
		t.Fatal("want fail-loud error when br_netfilter never loaded")
	}
}

func TestWriteSysctlMissingPathNoop(t *testing.T) {
	if err := writeSysctl(filepath.Join(t.TempDir(), "missing"), "1"); err != nil {
		t.Fatal(err)
	}
}
