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

func TestSeccompProgramShape(t *testing.T) {
	prog, unknown, err := buildSeccompProgram(auditArchX86_64, fakeSyscallTable,
		[]string{"read", "write", "write", "nope", "mprotect", "mmap"},
		[]SeccompArgRule{
			{Syscall: "mprotect", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}},
			{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}, {Arg: 3, Mask: 0x20}}},
		}, SeccompEnforce)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "nope" {
		t.Fatalf("unknown = %v, want [nope]", unknown)
	}
	// Header: load arch, compare, kill; load nr; x32 guard (2).
	if prog[0] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArch) || prog[1] != bpfJump(bpfJMP|bpfJEQ|bpfK, auditArchX86_64, 1, 0) || prog[2].K != seccompRetKillProcess {
		t.Fatalf("arch check = %+v", prog[:3])
	}
	if prog[3] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataNR) || prog[4] != bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1) || prog[5].K != seccompRetKillProcess {
		t.Fatalf("x32 guard = %+v", prog[3:6])
	}
	// Plain allows, ascending, deduplicated: read(0), write(1).
	if prog[6] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 0, 1) || prog[7].K != seccompRetAllow || prog[8] != bpfJump(bpfJMP|bpfJEQ|bpfK, 1, 0, 1) || prog[9].K != seccompRetAllow {
		t.Fatalf("plain allows = %+v", prog[6:10])
	}
	// Rules in name order: mmap (2 masks) then mprotect (1 mask).
	i := 10
	if prog[i] != bpfJump(bpfJMP|bpfJEQ|bpfK, 9, 0, 8) {
		t.Fatalf("mmap gate = %+v", prog[i])
	}
	// mask 0: ld arg2; and 0x4; jeq 0 → allow (jt = 3*2-0-2 = 4)
	if prog[i+1] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArgs+16) || prog[i+2] != bpfStmt(bpfALU|bpfAND|bpfK, 0x4) || prog[i+3] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 4, 0) {
		t.Fatalf("mmap check 0 = %+v", prog[i+1:i+4])
	}
	// mask 1: ld arg3; and 0x20; jeq 0 → allow (jt = 1)
	if prog[i+4] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArgs+24) || prog[i+5] != bpfStmt(bpfALU|bpfAND|bpfK, 0x20) || prog[i+6] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 1, 0) {
		t.Fatalf("mmap check 1 = %+v", prog[i+4:i+7])
	}
	if prog[i+7].K != seccompRetKillProcess || prog[i+8].K != seccompRetAllow {
		t.Fatalf("mmap tail = %+v", prog[i+7:i+9])
	}
	// Both jumps land on the same ALLOW: from check0's jeq (i+3) +1+4 = i+8; from check1's jeq (i+6) +1+1 = i+8.
	i += 9
	if prog[i] != bpfJump(bpfJMP|bpfJEQ|bpfK, 10, 0, 5) || prog[i+3] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 1, 0) || prog[i+4].K != seccompRetKillProcess || prog[i+5].K != seccompRetAllow {
		t.Fatalf("mprotect block = %+v", prog[i:i+6])
	}
	if last := prog[len(prog)-1]; last.K != seccompRetKillProcess {
		t.Fatalf("default = %+v", last)
	}
	// Audit mode logs instead of killing, but a foreign arch still dies.
	audit, _, err := buildSeccompProgram(auditArchAARCH64, fakeSyscallTable, []string{"read"}, nil, SeccompAudit)
	if err != nil {
		t.Fatal(err)
	}
	if audit[2].K != seccompRetKillProcess || audit[len(audit)-1].K != seccompRetLog {
		t.Fatalf("audit program = arch-kill %#x default %#x", audit[2].K, audit[len(audit)-1].K)
	}
	// aarch64 has no x32 guard.
	if audit[4] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 0, 1) {
		t.Fatalf("aarch64 first allow = %+v (x32 guard must be absent)", audit[4])
	}
}

func TestSeccompProgramRejectsBadRules(t *testing.T) {
	for name, rules := range map[string][]SeccompArgRule{
		"no masks":       {{Syscall: "read"}},
		"bad arg":        {{Syscall: "read", DenyIfAll: []SeccompArgMask{{Arg: 6, Mask: 1}}}},
		"zero mask":      {{Syscall: "read", DenyIfAll: []SeccompArgMask{{Arg: 0, Mask: 0}}}},
		"duplicate rule": {{Syscall: "read", DenyIfAll: []SeccompArgMask{{Arg: 0, Mask: 1}}}, {Syscall: "read", DenyIfAll: []SeccompArgMask{{Arg: 1, Mask: 1}}}},
		"too many masks": {{Syscall: "read", DenyIfAll: make([]SeccompArgMask, 7)}},
	} {
		if _, _, err := buildSeccompProgram(auditArchX86_64, fakeSyscallTable, []string{"read"}, rules, SeccompEnforce); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, _, err := buildSeccompProgram(auditArchX86_64, fakeSyscallTable, []string{"read"}, nil, "sometimes"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	// A rule for a syscall this arch lacks is reported, not fatal.
	_, unknown, err := buildSeccompProgram(auditArchX86_64, fakeSyscallTable, nil, []SeccompArgRule{{Syscall: "ghost", DenyIfAll: []SeccompArgMask{{Arg: 0, Mask: 1}}}}, SeccompEnforce)
	if err != nil || len(unknown) != 1 || unknown[0] != "ghost" {
		t.Fatalf("ghost rule: unknown=%v err=%v", unknown, err)
	}
	// The kernel's length ceiling.
	big := make(map[string]int, 3000)
	names := make([]string, 0, 3000)
	for i := range 3000 {
		n := "s" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
		big[n] = i
		names = append(names, n)
	}
	if _, _, err := buildSeccompProgram(auditArchX86_64, big, names, nil, SeccompEnforce); err == nil {
		t.Fatal("oversized program accepted")
	}
	nrs, unknown := resolveSyscalls([]string{"close", "read", "read", "zzz"}, fakeSyscallTable)
	if len(nrs) != 2 || nrs[0] != 0 || nrs[1] != 3 || len(unknown) != 1 {
		t.Fatalf("resolve = %v %v", nrs, unknown)
	}
}

// Every name the driver's default profile uses resolves on both Linux
// architectures we ship, except the legacy x86-64-only calls, which must be
// absent on arm64 exactly (not misspelled into oblivion on both).
func TestSeccompSyscallTablesAgree(t *testing.T) {
	if runtime.GOOS != "linux" {
		if seccompSyscallTable() != nil || seccompAuditArch() != 0 {
			t.Fatal("non-linux must have no table")
		}
		t.Skip("architecture tables are compiled on linux only")
	}
	table := seccompSyscallTable()
	if len(table) < 120 {
		t.Fatalf("table has %d entries", len(table))
	}
	for _, must := range []string{"read", "mmap", "mprotect", "clone3", "set_tid_address", "execve", "epoll_pwait", "getrandom", "rseq", "futex", "exit_group"} {
		if _, ok := table[must]; !ok {
			t.Fatalf("%s missing from the %s table", must, runtime.GOARCH)
		}
	}
	legacy := []string{"open", "stat", "poll", "select", "dup2", "pipe", "eventfd", "getdents", "readlink", "access", "epoll_wait", "arch_prctl", "lstat"}
	for _, name := range legacy {
		_, ok := table[name]
		if runtime.GOARCH == "amd64" && !ok {
			t.Fatalf("legacy %s missing on amd64", name)
		}
		if runtime.GOARCH == "arm64" && ok {
			t.Fatalf("legacy %s present on arm64", name)
		}
	}
}

func TestJailShimSpecRoundTripAndValidation(t *testing.T) {
	spec := jailShimSpec{Chroot: "/srv/j/acme", Cwd: "/run", UID: 1001, GID: 1001, Argv: []string{"/workerd", "serve"}, Env: []string{"HOME=/run"},
		Seccomp: []bpfInsn{bpfStmt(bpfRET|bpfK, seccompRetAllow)}}
	raw, err := encodeJailShimSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJailShimSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Chroot != spec.Chroot || got.UID != 1001 || got.Argv[1] != "serve" || len(got.Seccomp) != 1 || got.Seccomp[0].K != seccompRetAllow {
		t.Fatalf("round trip = %+v", got)
	}
	for name, bad := range map[string]jailShimSpec{
		"relative chroot": {Chroot: "srv", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"/w"}},
		"relative cwd":    {Chroot: "/s", Cwd: "run", UID: 1, GID: 1, Argv: []string{"/w"}},
		"root uid":        {Chroot: "/s", Cwd: "/run", UID: 0, GID: 1, Argv: []string{"/w"}},
		"root gid":        {Chroot: "/s", Cwd: "/run", UID: 1, GID: 0, Argv: []string{"/w"}},
		"no argv":         {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1},
		"relative argv":   {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"workerd"}},
		"huge program":    {Chroot: "/s", Cwd: "/run", UID: 1, GID: 1, Argv: []string{"/w"}, Seccomp: make([]bpfInsn, bpfMaxInsns+1)},
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
