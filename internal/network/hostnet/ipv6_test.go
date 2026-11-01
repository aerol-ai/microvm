package hostnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIPv6Conf stands a temp dir in for /proc/sys/net/ipv6/conf with the
// given interfaces (all and default always), each at disable_ipv6=0.
func fakeIPv6Conf(t *testing.T, links ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, l := range append([]string{"all", "default"}, links...) {
		if err := os.MkdirAll(filepath.Join(root, l), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, l, "disable_ipv6"), []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := ipv6ConfRoot
	ipv6ConfRoot = root
	t.Cleanup(func() { ipv6ConfRoot = orig })
	return root
}

func noIPv6Conf(t *testing.T) {
	t.Helper()
	orig := ipv6ConfRoot
	ipv6ConfRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { ipv6ConfRoot = orig })
}

func readDisable(t *testing.T, root, link string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, link, "disable_ipv6"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestSandboxIPv6Sysctls(t *testing.T) {
	t.Run("host_with_ipv6", func(t *testing.T) {
		fakeIPv6Conf(t)
		got := SandboxIPv6Sysctls()
		if len(got) != 2 || got[SysctlAllDisableIPv6] != "1" || got[SysctlDefaultDisableIPv6] != "1" {
			t.Fatalf("sysctls = %v", got)
		}
		// Callers merge it into a spec they own: a second call is a fresh map.
		got["x"] = "y"
		if _, ok := SandboxIPv6Sysctls()["x"]; ok {
			t.Fatal("SandboxIPv6Sysctls returned a shared map")
		}
	})
	t.Run("host_without_ipv6", func(t *testing.T) {
		noIPv6Conf(t)
		if HostHasIPv6() {
			t.Fatal("HostHasIPv6 with no ipv6 conf tree")
		}
		// runc fails a create whose sysctl has no /proc/sys entry, so a
		// kernel without IPv6 gets none.
		if got := SandboxIPv6Sysctls(); got != nil {
			t.Fatalf("sysctls on a host without IPv6 = %v", got)
		}
	})
}

func TestDisableIPv6OnLink(t *testing.T) {
	root := fakeIPv6Conf(t, "fctap7")
	if err := DisableIPv6OnLink("fctap7"); err != nil {
		t.Fatal(err)
	}
	if got := readDisable(t, root, "fctap7"); got != "1" {
		t.Fatalf("fctap7 disable_ipv6 = %q", got)
	}
	// Idempotent.
	if err := DisableIPv6OnLink("fctap7"); err != nil {
		t.Fatal(err)
	}
	// The caller just created the link: a missing one is an error, never a
	// silent pass.
	if err := DisableIPv6OnLink("fctap8"); err == nil {
		t.Fatal("missing link must fail")
	}
	for _, bad := range []string{"", ".", "..", "a/b", "../all", "toolonginterface0", "a b"} {
		if err := DisableIPv6OnLink(bad); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
	if got := readDisable(t, root, "all"); got != "0" {
		t.Fatalf("a link write touched all: %q", got)
	}
}

func TestDisableIPv6OnLinkNoIPv6(t *testing.T) {
	noIPv6Conf(t)
	if err := DisableIPv6OnLink("fctap0"); err != nil {
		t.Fatalf("host without IPv6: %v", err)
	}
	if err := DisableIPv6InNetns("/run/netns/x"); err != nil {
		t.Fatalf("host without IPv6: %v", err)
	}
}

func TestDisableIPv6InNetnsEmptyPath(t *testing.T) {
	fakeIPv6Conf(t)
	if err := DisableIPv6InNetns("  "); err == nil {
		t.Fatal("empty netns path must fail")
	}
}

func TestWriteNetnsDisableIPv6(t *testing.T) {
	root := fakeIPv6Conf(t)
	if err := writeNetnsDisableIPv6(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"all", "default"} {
		if got := readDisable(t, root, c); got != "1" {
			t.Fatalf("%s = %q", c, got)
		}
	}
	// A namespace whose default entry is missing fails loud.
	if err := os.Remove(filepath.Join(root, "default", "disable_ipv6")); err != nil {
		t.Fatal(err)
	}
	if err := writeNetnsDisableIPv6(); err == nil {
		t.Fatal("missing default entry must fail")
	}
}

func TestWriteDisableIPv6Errors(t *testing.T) {
	dir := t.TempDir()
	// A directory opens but cannot be written.
	if err := writeDisableIPv6(dir); err == nil {
		t.Fatal("writing a directory must fail")
	}
}
