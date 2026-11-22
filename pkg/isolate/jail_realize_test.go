package isolate

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// The jail's pure parts — the seccomp program, the chroot tree, the cgroup
// file layout, the shim spec, the path mapping — are tested here on every
// platform. What only a Linux root can do (chroot, mknod, cgroup placement,
// installing the filter) is exercised by the tagged real-host scenario
// (integration-tests, UC-109) and is deliberately thin glue over these.

// fakeSyscallTable is an architecture-neutral table for program tests.
var fakeSyscallTable = map[string]int{
	"read": 0, "write": 1, "close": 3, "mmap": 9, "mprotect": 10, "execve": 59, "exit_group": 231, "openat": 257,
}

// The builder itself is tested in pkg/hostproc; the jail adds only its
// modes, which pick the fall-through result.
func TestSeccompProgramModes(t *testing.T) {
	rules := []SeccompArgRule{{Syscall: "mprotect", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}}}
	for _, tc := range []struct {
		mode string
		want uint32
	}{
		{SeccompEnforce, hostproc.SeccompRetKillProcess},
		{"", hostproc.SeccompRetKillProcess},
		{SeccompAudit, hostproc.SeccompRetLog},
	} {
		prog, unknown, err := buildSeccompProgram(hostproc.AuditArchX86_64, fakeSyscallTable, []string{"read", "nope", "mprotect"}, rules, tc.mode)
		if err != nil {
			t.Fatalf("%q: %v", tc.mode, err)
		}
		if len(unknown) != 1 || unknown[0] != "nope" {
			t.Fatalf("%q: unknown = %v", tc.mode, unknown)
		}
		if last := prog[len(prog)-1]; last.K != tc.want {
			t.Fatalf("%q: default = %#x, want %#x", tc.mode, last.K, tc.want)
		}
		// The mprotect rule refuses with the mode's result too.
		if deny := prog[len(prog)-3]; deny.K != tc.want {
			t.Fatalf("%q: rule deny = %#x, want %#x", tc.mode, deny.K, tc.want)
		}
	}
	if _, _, err := buildSeccompProgram(hostproc.AuditArchX86_64, fakeSyscallTable, []string{"read"}, nil, "sometimes"); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestJailShimSpecRoundTripAndValidation(t *testing.T) {
	spec := jailShimSpec{Chroot: "/srv/j/acme", Cwd: "/run", UID: 1001, GID: 1001, Argv: []string{"/workerd", "serve"}, Env: []string{"HOME=/run"},
		Seccomp: []bpfInsn{{Code: 0x06, K: hostproc.SeccompRetAllow}}}
	raw, err := encodeJailShimSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJailShimSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Chroot != spec.Chroot || got.UID != 1001 || got.Argv[1] != "serve" || len(got.Seccomp) != 1 || got.Seccomp[0].K != hostproc.SeccompRetAllow {
		t.Fatalf("round trip = %+v", got)
	}
	for name, bad := range map[string]jailShimSpec{
		"relative chroot": {Chroot: "srv", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"/w"}},
		"relative cwd":    {Chroot: "/s", Cwd: "run", UID: 1, GID: 1, Argv: []string{"/w"}},
		"root uid":        {Chroot: "/s", Cwd: "/run", UID: 0, GID: 1, Argv: []string{"/w"}},
		"root gid":        {Chroot: "/s", Cwd: "/run", UID: 1, GID: 0, Argv: []string{"/w"}},
		"no argv":         {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1},
		"relative argv":   {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"workerd"}},
		"huge program":    {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"/w"}, Seccomp: make([]bpfInsn, hostproc.MaxSeccompInsns+1)},
	} {
		if _, err := encodeJailShimSpec(bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := decodeJailShimSpec("{nope"); err == nil {
		t.Fatal("malformed spec decoded")
	}
	if _, err := decodeJailShimSpec(`{"chroot":"/s","cwd":"/run","uid":0,"gid":1,"argv":["/w"]}`); err == nil {
		t.Fatal("root spec decoded")
	}
	if runtime.GOOS != "linux" {
		if err := RunJailShim(nil); err == nil {
			t.Fatal("shim ran off linux")
		}
	} else {
		t.Setenv(jailShimSpecEnv, "")
		if err := RunJailShim(nil); err == nil {
			t.Fatal("shim ran without a spec")
		}
		t.Setenv(jailShimSpecEnv, "{bad")
		if err := RunJailShim(nil); err == nil {
			t.Fatal("shim ran with a malformed spec")
		}
	}
}

func TestParseLDD(t *testing.T) {
	out := `	linux-vdso.so.1 (0x00007ffd3b5f2000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f2c3a1c4000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f2c3a0dd000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2c39eb5000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f2c3a1c4000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f2c3a1e0000)
`
	libs, err := parseLDD([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/lib/x86_64-linux-gnu/libdl.so.2", "/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2"}
	if strings.Join(libs, ",") != strings.Join(want, ",") {
		t.Fatalf("libs = %v, want %v", libs, want)
	}
	if libs, err := parseLDD([]byte("\tstatically linked\n")); err != nil || libs != nil {
		t.Fatalf("static = %v %v", libs, err)
	}
	if libs, err := parseLDD([]byte("\tnot a dynamic executable\n")); err != nil || libs != nil {
		t.Fatalf("non-dynamic = %v %v", libs, err)
	}
	if _, err := parseLDD([]byte("\tlibfoo.so.1 => not found\n")); err == nil {
		t.Fatal("missing library accepted")
	}
	if libs, err := parseLDD([]byte("\tlibweird.so => relative/path (0x1)\n")); err != nil || len(libs) != 0 {
		t.Fatalf("relative path = %v %v", libs, err)
	}
}

// writeFakeStaticELF writes a minimal ELF64 header with no program headers:
// enough for debug/elf to open it and report no interpreter (static).
func writeFakeStaticELF(t *testing.T, path string) {
	t.Helper()
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(h[16:], 2)    // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], 0x3e) // x86-64
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64) // ehsize
	binary.LittleEndian.PutUint16(h[54:], 56) // phentsize
	binary.LittleEndian.PutUint16(h[58:], 64) // shentsize
	if err := os.WriteFile(path, h, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSharedLibsAndPrepareJailBase(t *testing.T) {
	dir := t.TempDir()
	notELF := filepath.Join(dir, "script")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSharedLibs(notELF); err == nil {
		t.Fatal("non-ELF accepted")
	}
	static := filepath.Join(dir, "workerd")
	writeFakeStaticELF(t, static)
	libs, err := resolveSharedLibs(static)
	if err != nil || libs != nil {
		t.Fatalf("static binary libs = %v err=%v", libs, err)
	}

	base := filepath.Join(dir, "jail")
	for name, args := range map[string][2]string{
		"relative base":    {"jail", static},
		"relative workerd": {base, "workerd"},
		"missing workerd":  {base, filepath.Join(dir, "missing")},
	} {
		if err := PrepareJailBase(args[0], args[1]); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if JailBasePrepared(base) {
		t.Fatal("prepared before PrepareJailBase")
	}
	if err := PrepareJailBase(base, static); err != nil {
		t.Fatal(err)
	}
	if !JailBasePrepared(base) {
		t.Fatal("base not prepared")
	}
	for _, p := range []string{JailWorkerdPath, "dev", "tmp"} {
		if _, err := os.Stat(filepath.Join(base, jailBaseName, p)); err != nil {
			t.Fatalf("base lacks %s: %v", p, err)
		}
	}
	if st, _ := os.Stat(filepath.Join(base, jailBaseName, "tmp")); st.Mode().Perm()&0o002 != 0 {
		t.Fatalf("tmp still world-writable (execve + 1777 /tmp is the plant-a-binary path): %v", st.Mode())
	}
	// Rebuild in place is idempotent and atomic (no .next / .old left behind).
	if err := PrepareJailBase(base, static); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(base)
	if len(entries) != 1 || entries[0].Name() != jailBaseName {
		t.Fatalf("base dir after rebuild = %v", entries)
	}

	// Group trees are hard links from the base, with a run dir for the jail uid.
	group := filepath.Join(base, "acme")
	uid, gid := os.Getuid(), os.Getgid()
	if err := linkGroupJail(base, group, uid, gid); err != nil {
		t.Fatal(err)
	}
	gw, err := os.Stat(filepath.Join(group, JailWorkerdPath))
	if err != nil {
		t.Fatal(err)
	}
	bw, _ := os.Stat(filepath.Join(base, jailBaseName, JailWorkerdPath))
	if !os.SameFile(gw, bw) {
		t.Fatal("group workerd is not a hard link of the base copy")
	}
	if st, err := os.Stat(filepath.Join(group, JailRunDirName)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("run dir = %v %v", st, err)
	}
	// Re-linking an existing group is idempotent.
	if err := linkGroupJail(base, group, uid, gid); err != nil {
		t.Fatal(err)
	}
	// Refusals: outside the base, the base itself, an unprepared base.
	if err := linkGroupJail(base, filepath.Join(dir, "elsewhere"), uid, gid); err == nil {
		t.Fatal("group outside base accepted")
	}
	if err := linkGroupJail(base, filepath.Join(base, jailBaseName), uid, gid); err == nil {
		t.Fatal("linking the base onto itself accepted")
	}
	if err := linkGroupJail(filepath.Join(dir, "unprepared"), filepath.Join(dir, "unprepared", "g"), uid, gid); err == nil {
		t.Fatal("unprepared base accepted")
	}
	if err := removeGroupJail(base, filepath.Join(base, jailBaseName)); err == nil {
		t.Fatal("removing the base accepted")
	}
	if err := removeGroupJail(base, filepath.Join(dir, "elsewhere")); err == nil {
		t.Fatal("removing outside the base accepted")
	}
	if err := removeGroupJail(base, group); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatal("group not removed")
	}
	if !JailBasePrepared(base) {
		t.Fatal("removing a group touched the base")
	}
}

func TestCgroupFSLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cg")
	cg := cgroupFS{root: root}
	if _, err := cg.ensure("", 1, 1, 0); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := cg.ensure("a/b", 1, 1, 0); err == nil {
		t.Fatal("nested name accepted")
	}
	if _, err := (cgroupFS{root: "cg"}).ensure("x", 1, 1, 0); err == nil {
		t.Fatal("relative root accepted")
	}
	dir, err := cg.ensure("aerolvm-isolate-acme", 1.5, 512, 128)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw))
	}
	if got := read("cpu.max"); got != "150000 100000" {
		t.Fatalf("cpu.max = %q", got)
	}
	if got := read("memory.max"); got != "536870912" {
		t.Fatalf("memory.max = %q", got)
	}
	// pids.max bounds the group's thread/process count: clone/clone3 are in
	// the seccomp allowlist, so an unbounded cgroup lets one tenant exhaust
	// the host PID space.
	if got := read("pids.max"); got != "128" {
		t.Fatalf("pids.max = %q, want 128", got)
	}
	// Zero caps mean unlimited; a warm blank host starts this way.
	if err := cg.applyCaps(dir, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if read("cpu.max") != "max 100000" || read("memory.max") != "max" || read("pids.max") != "max" {
		t.Fatalf("unlimited = %q / %q / %q", read("cpu.max"), read("memory.max"), read("pids.max"))
	}
	if err := cg.applyCaps(dir, -1, 0, 0); err == nil {
		t.Fatal("negative cap accepted")
	}
	if err := cg.applyCaps(dir, 0, 0, -1); err == nil {
		t.Fatal("negative pids cap accepted")
	}
	// With a subtree_control file present (a real cgroupfs), controllers are enabled.
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cg.ensure("aerolvm-isolate-b", 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); !strings.Contains(string(raw), "+memory") {
		t.Fatalf("controllers not enabled: %q", raw)
	}
	if err := cg.remove(filepath.Join(t.TempDir(), "other")); err == nil {
		t.Fatal("removing outside root accepted")
	}
	if err := cg.remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := cg.remove(dir); err != nil {
		t.Fatalf("second remove = %v, want idempotent", err)
	}
	// A realized record tears down cgroup + chroot and tolerates a nil receiver.
	var none *jailRealized
	none.closeFD()
	if err := none.teardown(); err != nil {
		t.Fatal(err)
	}
	if err := none.applyCaps(1, 1, 16); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "jail")
	static := filepath.Join(t.TempDir(), "w")
	writeFakeStaticELF(t, static)
	if err := PrepareJailBase(base, static); err != nil {
		t.Fatal(err)
	}
	group := filepath.Join(base, "g")
	if err := linkGroupJail(base, group, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	cgDir, _ := cg.ensure("aerolvm-isolate-g", 2, 64, 64)
	r := &jailRealized{chrootBase: base, chrootDir: group, cgroup: cg, cgroupDir: cgDir}
	if err := r.applyCaps(1, 32, 16); err != nil {
		t.Fatal(err)
	}
	if err := r.teardown(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatal("chroot survived teardown")
	}
	if _, err := os.Stat(cgDir); !os.IsNotExist(err) {
		t.Fatal("cgroup survived teardown")
	}
}

func TestHostJailPathMappingAndRunDirContract(t *testing.T) {
	chroot := "/srv/isolate-jail/acme"
	h := &Host{cfg: HostConfig{Jail: JailConfig{Require: true, ChrootDir: chroot}}}
	if got := h.inJail(chroot + "/run/control.sock"); got != "/run/control.sock" {
		t.Fatalf("inJail = %q", got)
	}
	if got := h.inJail("/elsewhere/x"); got != "/elsewhere/x" {
		t.Fatalf("outside chroot mapped to %q", got)
	}
	plain := &Host{cfg: HostConfig{Jail: JailConfig{Require: false, ChrootDir: chroot}}}
	if got := plain.inJail(chroot + "/run/x"); got != chroot+"/run/x" {
		t.Fatalf("unjailed host mapped %q", got)
	}
	// A required jail pins the run dir to <chroot>/run.
	if _, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: "/run/sandboxd/isolate/acme", Jail: JailConfig{Require: true, ChrootDir: chroot}}); err == nil || !strings.Contains(err.Error(), "jailed run dir") {
		t.Fatalf("run dir outside chroot accepted: %v", err)
	}
	ok, err := NewHost(HostConfig{WorkerdPath: "/w", GroupKey: "acme", RunDir: chroot + "/run", Jail: JailConfig{Require: true, ChrootDir: chroot}})
	if err != nil {
		t.Fatal(err)
	}
	// The generated config names in-jail paths: workerd binds /run/... inside
	// its root while the Go side dials <chroot>/run/... on the host.
	if !strings.HasPrefix(ok.controlSock, chroot) || ok.inJail(ok.controlSock) != "/run/"+controlSocketName {
		t.Fatalf("control sock host=%q jail=%q", ok.controlSock, ok.inJail(ok.controlSock))
	}
	dir := t.TempDir()
	ok.cfg.RunDir = dir // write the config somewhere real
	ok.controlSock, ok.hostSock, ok.egressDenySock = chroot+"/run/c.sock", chroot+"/run/h.sock", chroot+"/run/d.sock"
	ok.egressSocks = []string{chroot + "/run/e0.sock"}
	if err := ok.writeConfig(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.capnp"))
	for _, want := range []string{`unix:/run/c.sock`, `unix:/run/h.sock`, `unix:/run/d.sock`, `unix:/run/e0.sock`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("config lacks %s:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), chroot) {
		t.Fatalf("config leaks host paths:\n%s", raw)
	}
	// grantJailAccess is a no-op when unjailed and tolerates missing paths.
	if err := plain.grantJailAccess("/nope"); err != nil {
		t.Fatal(err)
	}
	if err := ok.grantJailAccess("", filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}
	// ApplyCaps on an unjailed host is a no-op.
	if err := plain.ApplyCaps(1, 1, 8); err != nil {
		t.Fatal(err)
	}
}

// A required jail still fails closed with the full config on a platform (or
// as a user) that cannot realize it, and never leaves a process behind.
func TestHostStartFailsClosedWithFullJailConfigWhenUnrealizable(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("root on linux can realize the jail; covered by the real-host scenario")
	}
	base := filepath.Join(t.TempDir(), "jail")
	chroot := filepath.Join(base, "g1")
	fake := filepath.Join(t.TempDir(), "workerd")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h, err := NewHost(HostConfig{
		WorkerdPath: fake, GroupKey: "g1", RunDir: filepath.Join(chroot, JailRunDirName),
		Jail: JailConfig{Require: true, ChrootDir: chroot, UID: 1001, GID: 1001, CgroupRoot: filepath.Join(base, "cg"),
			SeccompMode: SeccompEnforce, SeccompAllow: []string{"read"}, ShimPath: "/nonexistent-sandboxd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = h.Start(context.Background())
	if err == nil {
		_ = h.Stop()
		t.Fatal("Start succeeded with an unrealizable required jail")
	}
	if !strings.Contains(err.Error(), "jail") {
		t.Fatalf("err = %v", err)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(chroot); err == nil {
		if runtime.GOOS == "linux" {
			t.Fatal("chroot left behind after a failed spawn")
		}
	}
	_ = errors.Is(err, errNotRoot)
}

func TestMountNoexecTmpfsRejectsRelative(t *testing.T) {
	if err := mountNoexecTmpfs("tmp", 1, 1); err == nil {
		t.Fatal("relative dir accepted")
	}
}
