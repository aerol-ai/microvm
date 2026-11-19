package hostproc

import (
	"runtime"
	"strings"
	"testing"
)

// The filter builder is pure, so the program tests run on every platform.
// Installing a filter needs Linux (confine_linux_test.go).

// fakeSyscallTable is an architecture-neutral table for program tests.
var fakeSyscallTable = map[string]int{
	"read": 0, "write": 1, "close": 3, "mmap": 9, "mprotect": 10, "execve": 59, "exit_group": 231, "openat": 257,
}

func TestSeccompProgramShape(t *testing.T) {
	prog, unknown, err := BuildSeccomp(AuditArchX86_64, fakeSyscallTable, SeccompPolicy{
		Allow: []string{"read", "write", "write", "nope", "mprotect", "mmap"},
		Rules: []SeccompArgRule{
			{Syscall: "mprotect", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}},
			{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}, {Arg: 3, Mask: 0x20}}},
		}, Default: SeccompRetKillProcess})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "nope" {
		t.Fatalf("unknown = %v, want [nope]", unknown)
	}
	// Header: load arch, compare, kill; load nr; x32 guard (2).
	if prog[0] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArch) || prog[1] != bpfJump(bpfJMP|bpfJEQ|bpfK, AuditArchX86_64, 1, 0) || prog[2].K != SeccompRetKillProcess {
		t.Fatalf("arch check = %+v", prog[:3])
	}
	if prog[3] != bpfStmt(bpfLD|bpfW|bpfABS, seccompDataNR) || prog[4] != bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1) || prog[5].K != SeccompRetKillProcess {
		t.Fatalf("x32 guard = %+v", prog[3:6])
	}
	// Plain allows, ascending, deduplicated: read(0), write(1).
	if prog[6] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 0, 1) || prog[7].K != SeccompRetAllow || prog[8] != bpfJump(bpfJMP|bpfJEQ|bpfK, 1, 0, 1) || prog[9].K != SeccompRetAllow {
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
	if prog[i+7].K != SeccompRetKillProcess || prog[i+8].K != SeccompRetAllow {
		t.Fatalf("mmap tail = %+v", prog[i+7:i+9])
	}
	// Both jumps land on the same ALLOW: from check0's jeq (i+3) +1+4 = i+8; from check1's jeq (i+6) +1+1 = i+8.
	i += 9
	if prog[i] != bpfJump(bpfJMP|bpfJEQ|bpfK, 10, 0, 5) || prog[i+3] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 1, 0) || prog[i+4].K != SeccompRetKillProcess || prog[i+5].K != SeccompRetAllow {
		t.Fatalf("mprotect block = %+v", prog[i:i+6])
	}
	if last := prog[len(prog)-1]; last.K != SeccompRetKillProcess {
		t.Fatalf("default = %+v", last)
	}
	// Audit mode logs instead of killing, but a foreign arch still dies.
	audit, _, err := BuildSeccomp(AuditArchAARCH64, fakeSyscallTable, SeccompPolicy{Allow: []string{"read"}, Default: SeccompRetLog})
	if err != nil {
		t.Fatal(err)
	}
	if audit[2].K != SeccompRetKillProcess || audit[len(audit)-1].K != SeccompRetLog {
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
		if _, _, err := BuildSeccomp(AuditArchX86_64, fakeSyscallTable, SeccompPolicy{Allow: []string{"read"}, Rules: rules, Default: SeccompRetKillProcess}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A rule for a syscall this arch lacks is reported, not fatal.
	_, unknown, err := BuildSeccomp(AuditArchX86_64, fakeSyscallTable, SeccompPolicy{Rules: []SeccompArgRule{{Syscall: "ghost", DenyIfAll: []SeccompArgMask{{Arg: 0, Mask: 1}}}}, Default: SeccompRetKillProcess})
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
	if _, _, err := BuildSeccomp(AuditArchX86_64, big, SeccompPolicy{Allow: names, Default: SeccompRetKillProcess}); err == nil {
		t.Fatal("oversized program accepted")
	}
	nrs, unknown := ResolveSyscalls([]string{"close", "read", "read", "zzz"}, fakeSyscallTable)
	if len(nrs) != 2 || nrs[0] != 0 || nrs[1] != 3 || len(unknown) != 1 {
		t.Fatalf("resolve = %v %v", nrs, unknown)
	}
}

// Every name the isolate driver's default profile uses resolves on both Linux
// architectures we ship, except the legacy x86-64-only calls, which must be
// absent on arm64 exactly (not misspelled into oblivion on both).
func TestSeccompSyscallTablesAgree(t *testing.T) {
	if runtime.GOOS != "linux" {
		if SyscallTable() != nil || SeccompArch() != 0 {
			t.Fatal("non-linux must have no table")
		}
		t.Skip("architecture tables are compiled on linux only")
	}
	table := SyscallTable()
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

// Named actions and the rule's own deny result, as the WASM worker uses
// them: a kill list, clone3 answered ENOSYS, clone refused by flag with a
// kill, and EPERM for everything unnamed.
func TestSeccompPolicyActionsAndRuleDeny(t *testing.T) {
	enosys := SeccompRetErrno(38)
	prog, unknown, err := BuildSeccomp(AuditArchAARCH64, fakeSyscallTable, SeccompPolicy{
		Allow:    []string{"read", "mmap"},
		Actions:  map[string]uint32{"execve": SeccompRetKillProcess, "openat": enosys, "ghost": SeccompRetKillProcess},
		Rules:    []SeccompArgRule{{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}}},
		RuleDeny: SeccompRetKillProcess,
		Default:  SeccompRetErrno(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 1 || unknown[0] != "ghost" {
		t.Fatalf("unknown = %v, want [ghost]", unknown)
	}
	// aarch64: arch check (3), ld nr (1), then read's allow (2).
	if prog[4] != bpfJump(bpfJMP|bpfJEQ|bpfK, 0, 0, 1) || prog[5].K != SeccompRetAllow {
		t.Fatalf("plain allow = %+v", prog[4:6])
	}
	// Actions in name order: execve(59) kill, openat(257) ENOSYS.
	if prog[6] != bpfJump(bpfJMP|bpfJEQ|bpfK, 59, 0, 1) || prog[7].K != SeccompRetKillProcess {
		t.Fatalf("execve action = %+v", prog[6:8])
	}
	if prog[8] != bpfJump(bpfJMP|bpfJEQ|bpfK, 257, 0, 1) || prog[9].K != enosys || enosys != 0x00050026 {
		t.Fatalf("openat action = %+v (%#x)", prog[8:10], enosys)
	}
	// mmap's rule refuses with RuleDeny, not the default.
	if prog[10] != bpfJump(bpfJMP|bpfJEQ|bpfK, 9, 0, 5) || prog[14].K != SeccompRetKillProcess || prog[15].K != SeccompRetAllow {
		t.Fatalf("mmap rule = %+v", prog[10:16])
	}
	if last := prog[len(prog)-1]; last.K != SeccompRetErrno(1) {
		t.Fatalf("default = %#x", last.K)
	}
	// An unset RuleDeny falls back to the default.
	prog, _, err = BuildSeccomp(AuditArchAARCH64, fakeSyscallTable, SeccompPolicy{
		Rules:   []SeccompArgRule{{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}}},
		Default: SeccompRetLog,
	})
	if err != nil || prog[len(prog)-3].K != SeccompRetLog {
		t.Fatalf("rule deny without RuleDeny = %+v, %v", prog, err)
	}
	for name, p := range map[string]SeccompPolicy{
		"allowed and actioned": {Allow: []string{"read"}, Actions: map[string]uint32{"read": SeccompRetKillProcess}},
		"ruled and actioned": {
			Rules:   []SeccompArgRule{{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: 0x4}}}},
			Actions: map[string]uint32{"mmap": SeccompRetKillProcess},
		},
	} {
		if _, _, err := BuildSeccomp(AuditArchX86_64, fakeSyscallTable, p); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Two names for one number act once.
	twins := map[string]int{"a": 1, "b": 1}
	prog, _, err = BuildSeccomp(AuditArchAARCH64, twins, SeccompPolicy{Actions: map[string]uint32{"a": SeccompRetKillProcess, "b": SeccompRetKillProcess}})
	if err != nil || len(prog) != 4+2+1 {
		t.Fatalf("twin actions = %d instructions, %v", len(prog), err)
	}
}
