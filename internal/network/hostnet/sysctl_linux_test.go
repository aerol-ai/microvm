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
	var got []string
	orig := execConntrack
	execConntrack = func(args ...string) error {
		got = append([]string{}, args...)
		return nil
	}
	defer func() { execConntrack = orig }()

	if err := FlushConntrackForIP("10.88.0.5"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "-D" || got[1] != "-s" || got[2] != "10.88.0.5" {
		t.Fatalf("conntrack args = %#v", got)
	}
}

func TestWriteSysctlMissingPathNoop(t *testing.T) {
	if err := writeSysctl(filepath.Join(t.TempDir(), "missing"), "1"); err != nil {
		t.Fatal(err)
	}
}
