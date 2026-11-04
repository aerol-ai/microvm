package procid

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a procfs and cgroup tree for one sandbox (init pid 100)
// with a connection 10.0.0.20:40000 → 151.101.0.1:22 held by git (101) and
// pip (102, a python script); 103 holds nothing.
func fakeProc(t *testing.T) (Resolver, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	dir := t.TempDir()
	proc, cg, rootfs := filepath.Join(dir, "proc"), filepath.Join(dir, "cg"), filepath.Join(dir, "rootfs")
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"usr/bin/git", "usr/bin/curl", "usr/local/bin/python3.12", "usr/local/bin/pip"} {
		write(filepath.Join(rootfs, f), f)
	}
	write(filepath.Join(proc, "100/net/tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 1400000A:9C41 01006597:0016 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000\n"+
		"   1: 1400000A:9C40 01006597:0016 01 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000\n"+
		"   2: short line\n")
	write(filepath.Join(proc, "100/cgroup"), "0::/sandbox\n")
	write(filepath.Join(cg, "sandbox/cgroup.procs"), "100\n101\n103\n")
	write(filepath.Join(cg, "sandbox/sub/cgroup.procs"), "102\n")
	link(rootfs, filepath.Join(proc, "100/root"))
	link(filepath.Join(rootfs, "usr/bin/git"), filepath.Join(proc, "101/exe"))
	link("socket:[555]", filepath.Join(proc, "101/fd/3"))
	link("/dev/null", filepath.Join(proc, "101/fd/0"))
	write(filepath.Join(proc, "101/cmdline"), "git\x00clone\x00/tmp/x\x00")
	link(filepath.Join(rootfs, "usr/local/bin/python3.12"), filepath.Join(proc, "102/exe"))
	link("socket:[555]", filepath.Join(proc, "102/fd/4"))
	write(filepath.Join(proc, "102/cmdline"), "/usr/local/bin/python3.12\x00/usr/local/bin/pip\x00install\x00")
	link(filepath.Join(rootfs, "usr/bin/curl"), filepath.Join(proc, "103/exe"))
	link("socket:[999]", filepath.Join(proc, "103/fd/5"))
	r := Resolver{Proc: proc, Cgroup: cg, resolve: func(root, p string) (FileID, error) { return statID(filepath.Join(root, p)) }}
	return r, netip.MustParseAddrPort("10.0.0.20:40000"), netip.MustParseAddrPort("151.101.0.1:22")
}

func TestMatcher(t *testing.T) {
	r, local, remote := fakeProc(t)
	owners, err := r.Owners(100, local, remote)
	if err != nil || len(owners) != 2 || owners[1].Script != "/usr/local/bin/pip" || owners[0].Script != "" {
		t.Fatalf("owners = %+v %v", owners, err)
	}
	is, err := r.Matcher(100, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"/usr/bin/git":       true,
		"/usr/local/bin/pip": true, // the interpreter's script
		"/usr/bin/curl":      false,
		"/usr/bin/missing":   false,
	} {
		if got := is(path); got != want {
			t.Fatalf("is(%s) = %v", path, got)
		}
	}
	if is("/usr/bin/missing") {
		t.Fatal("cached miss")
	}
}

func TestMatcherErrors(t *testing.T) {
	r, local, remote := fakeProc(t)
	if _, err := r.Matcher(0, local, remote); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no pid: %v", err)
	}
	if _, err := r.Matcher(100, local, netip.MustParseAddrPort("1.1.1.1:22")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no socket: %v", err)
	}
	if _, err := r.Matcher(100, netip.MustParseAddrPort("10.0.0.20:40001"), remote); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a TIME_WAIT socket owns nothing: %v", err)
	}
	if _, err := r.Matcher(999, local, remote); err == nil {
		t.Fatal("no such process")
	}
	_ = os.WriteFile(filepath.Join(r.Proc, "100/cgroup"), []byte("1:name=systemd:/x\n"), 0o644)
	if _, err := r.Matcher(100, local, remote); err == nil {
		t.Fatal("cgroup v1 must be refused")
	}
	_ = os.WriteFile(filepath.Join(r.Proc, "100/cgroup"), []byte("0::/gone\n"), 0o644)
	if _, err := r.Matcher(100, local, remote); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty cgroup: %v", err)
	}
	for _, bad := range []string{"0100007F", "ZZ00007F:0050", "0100007F:ZZZZZ", "0100007F00:0050"} {
		if _, err := parseHexAddr(bad); err == nil {
			t.Fatalf("parseHexAddr(%q)", bad)
		}
	}
	var zero Resolver
	if zero.proc() != "/proc" || zero.cgroup() != "/sys/fs/cgroup" {
		t.Fatal("defaults")
	}
}
