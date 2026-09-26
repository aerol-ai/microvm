package isolate

import (
	"strings"
	"testing"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// Jail-profile regression tests (plans/isolate-runtime.md §2.1, Phase-1
// deliverable). The seccomp lists are maintained by hand; these tests are the
// invariants that keep a future edit honest.

func TestSanitizeGroupKey(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Empty is the null tenant, not an error: single-tenant self-hosters
		// get one default group with zero config (§2.1).
		{name: "empty_maps_to_default", input: "", want: DefaultGroupKey},
		{name: "whitespace_maps_to_default", input: "   ", want: DefaultGroupKey},
		{name: "simple", input: "acme", want: "acme"},
		{name: "with_separators", input: "acme-corp_prod.eu", want: "acme-corp_prod.eu"},
		{name: "sandbox_id_shape", input: "sb-0123456789abcdef", want: "sb-0123456789abcdef"},
		{name: "max_length_64", input: "a" + strings.Repeat("b", 63), want: "a" + strings.Repeat("b", 63)},
		// The key becomes a chroot directory and a cgroup name: anything
		// path-ambiguous is rejected, never escaped — two keys that
		// normalized to the same directory would merge two tenants into one
		// process (§2.1 forced co-residency, filesystem edition).
		{name: "slash_rejected", input: "acme/../../etc", wantErr: true},
		{name: "dotdot_rejected", input: "a..b", wantErr: true},
		{name: "leading_dash_rejected", input: "-acme", wantErr: true},
		{name: "leading_dot_rejected", input: ".acme", wantErr: true},
		{name: "interior_space_rejected", input: "acme corp", wantErr: true},
		{name: "too_long_rejected", input: strings.Repeat("a", 65), wantErr: true},
		{name: "unicode_rejected", input: "acmé", wantErr: true},
		{name: "null_byte_rejected", input: "acme\x00", wantErr: true},
		// No case normalization: "Acme" and "acme" stay distinct keys.
		{name: "case_preserved", input: "Acme", want: "Acme"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeGroupKey(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildJailSpec(t *testing.T) {
	cfg := Config{
		JailChrootBase: "/srv/isolate-jail",
		JailUID:        1000,
		JailGID:        1000,
	}

	spec, err := BuildJailSpec(cfg, "acme", 2.0, 512)
	if err != nil {
		t.Fatalf("BuildJailSpec: %v", err)
	}
	if spec.ChrootDir != "/srv/isolate-jail/acme" {
		t.Fatalf("ChrootDir = %q", spec.ChrootDir)
	}
	if spec.CgroupName != "aerolvm-isolate-acme" {
		t.Fatalf("CgroupName = %q", spec.CgroupName)
	}
	if spec.CPUQuota != 2.0 || spec.MemoryLimitMB != 512 {
		t.Fatalf("caps = %f/%d, want 2.0/512", spec.CPUQuota, spec.MemoryLimitMB)
	}
	if spec.Jitless {
		t.Fatal("Jitless leaked true from a false config")
	}

	// The null tenant lands in the default group's jail, not an unjailed path.
	spec, err = BuildJailSpec(cfg, "", 0, 0)
	if err != nil {
		t.Fatalf("BuildJailSpec default: %v", err)
	}
	if spec.GroupKey != DefaultGroupKey || spec.ChrootDir != "/srv/isolate-jail/default" {
		t.Fatalf("default spec = %+v", spec)
	}

	// Jitless propagates from config to spec (and from spec to profile).
	jitlessCfg := cfg
	jitlessCfg.Jitless = true
	spec, err = BuildJailSpec(jitlessCfg, "acme", 0, 0)
	if err != nil {
		t.Fatalf("BuildJailSpec jitless: %v", err)
	}
	if !spec.Jitless {
		t.Fatal("Jitless not propagated")
	}
	// Jitless keeps mprotect by name (the loader's RELRO and pthread's guard
	// pages need it) but refuses PROT_EXEC by argument, and refuses anonymous
	// executable mappings; the JIT profile has no argument rules at all.
	rules := spec.SeccompArgRulesFor()
	if len(rules) != 2 || rules[0].Syscall != "mprotect" || rules[1].Syscall != "mmap" {
		t.Fatalf("jitless arg rules = %+v", rules)
	}
	if rules[0].DenyIfAll[0] != (pkgisolate.SeccompArgMask{Arg: 2, Mask: protExec}) {
		t.Fatalf("mprotect rule = %+v", rules[0])
	}
	if len(rules[1].DenyIfAll) != 2 || rules[1].DenyIfAll[1] != (pkgisolate.SeccompArgMask{Arg: 3, Mask: mapAnonymous}) {
		t.Fatalf("mmap rule = %+v", rules[1])
	}
	if got := SeccompArgRules(false); got != nil {
		t.Fatalf("JIT profile has arg rules: %+v", got)
	}
	// The realized fields travel with the spec.
	full := cfg
	full.JailCgroupRoot, full.SeccompMode, full.ShimPath = "/sys/fs/cgroup/x", "audit", "/usr/local/bin/sandboxd"
	spec, err = BuildJailSpec(full, "acme", 1, 64)
	if err != nil || spec.CgroupRoot != "/sys/fs/cgroup/x" || spec.SeccompMode != "audit" || spec.ShimPath != "/usr/local/bin/sandboxd" || spec.CPUQuota != 1 || spec.MemoryLimitMB != 64 {
		t.Fatalf("realized fields = %+v err=%v", spec, err)
	}

	// A hostile group key must fail spec construction, never reach a path.
	if _, err := BuildJailSpec(cfg, "../../etc", 0, 0); err == nil {
		t.Fatal("expected error for traversal group key")
	}

	// Invalid jail uid fails validation inside BuildJailSpec.
	badCfg := cfg
	badCfg.JailUID = 0
	if _, err := BuildJailSpec(badCfg, "acme", 0, 0); err == nil {
		t.Fatal("expected error for root uid in BuildJailSpec")
	}
}

func TestJailSpecValidate(t *testing.T) {
	valid := JailSpec{
		GroupKey:   "acme",
		ChrootDir:  "/srv/isolate-jail/acme",
		CgroupName: "aerolvm-isolate-acme",
		UID:        1000,
		GID:        1000,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*JailSpec)
	}{
		{name: "empty_group_key", mutate: func(s *JailSpec) { s.GroupKey = "" }},
		{name: "relative_chroot", mutate: func(s *JailSpec) { s.ChrootDir = "srv/jail" }},
		{name: "empty_chroot", mutate: func(s *JailSpec) { s.ChrootDir = "" }},
		{name: "root_uid", mutate: func(s *JailSpec) { s.UID = 0 }},
		{name: "root_gid", mutate: func(s *JailSpec) { s.GID = 0 }},
		{name: "negative_uid", mutate: func(s *JailSpec) { s.UID = -1 }},
		{name: "negative_cpu", mutate: func(s *JailSpec) { s.CPUQuota = -1 }},
		{name: "negative_memory", mutate: func(s *JailSpec) { s.MemoryLimitMB = -1 }},
		{name: "invalid_group_key", mutate: func(s *JailSpec) { s.GroupKey = "../../etc" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := valid
			tc.mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestSeccompProfileInvariants(t *testing.T) {
	defaultProfile := SeccompAllowlist(false)
	jitlessProfile := SeccompAllowlist(true)

	toSet := func(names []string) map[string]struct{} {
		set := make(map[string]struct{}, len(names))
		for _, n := range names {
			set[n] = struct{}{}
		}
		return set
	}
	defaultSet := toSet(defaultProfile)
	jitlessSet := toSet(jitlessProfile)

	// No duplicates — a duplicate usually means a JIT syscall was pasted
	// into the base list, silently surviving jitless mode.
	if len(defaultSet) != len(defaultProfile) {
		t.Fatalf("default profile has duplicates: %d names, %d unique", len(defaultProfile), len(defaultSet))
	}
	if len(jitlessSet) != len(jitlessProfile) {
		t.Fatalf("jitless profile has duplicates: %d names, %d unique", len(jitlessProfile), len(jitlessSet))
	}

	// The deny-regardless list is disjoint from EVERY profile variant. This
	// is the invariant that makes the hand-maintained lists safe to edit.
	for _, denied := range SeccompNeverAllow() {
		if _, ok := defaultSet[denied]; ok {
			t.Fatalf("never-allow syscall %q present in default profile", denied)
		}
		if _, ok := jitlessSet[denied]; ok {
			t.Fatalf("never-allow syscall %q present in jitless profile", denied)
		}
	}

	// The JIT group is exactly what jitless removes by name: present by
	// default, absent under --jitless. (mprotect stays in both — the loader
	// needs it — and is narrowed by argument instead; see TestBuildJailSpec.)
	for _, jit := range []string{"memfd_create", "pkey_alloc", "pkey_mprotect", "pkey_free", "process_madvise"} {
		if _, ok := defaultSet[jit]; !ok {
			t.Fatalf("JIT syscall %q missing from default profile (V8 with a JIT cannot run)", jit)
		}
		if _, ok := jitlessSet[jit]; ok {
			t.Fatalf("JIT syscall %q present in jitless profile (defeats --jitless)", jit)
		}
	}

	// Floor of the base profile: without these, no glibc-linked V8 host runs
	// at all — the filter is installed before execve, so the dynamic loader
	// (mprotect for RELRO, set_tid_address) and glibc 2.34+ pthreads (clone3)
	// run under it, and the shim's one execve into workerd must pass.
	for _, base := range []string{"mmap", "mprotect", "futex", "clone", "clone3", "set_tid_address", "epoll_pwait", "read", "write", "accept4", "execve", "getrandom", "rseq"} {
		if _, ok := jitlessSet[base]; !ok {
			t.Fatalf("base syscall %q missing from jitless profile", base)
		}
	}

	// Escape primitives stay pinned on the never list — including the ways
	// a filtered process could change its own filter or identity.
	neverSet := toSet(SeccompNeverAllow())
	for _, escape := range []string{"ptrace", "mount", "setns", "unshare", "bpf", "execveat", "seccomp", "setuid", "setresuid", "capset", "kill", "tkill"} {
		if _, ok := neverSet[escape]; !ok {
			t.Fatalf("escape primitive %q missing from never-allow list", escape)
		}
	}

	// Shared jail uid: kill/tkill must not be on the allowlist even though
	// tgkill stays (pthread). One group must not be able to signal another.
	for _, cross := range []string{"kill", "tkill"} {
		if _, ok := defaultSet[cross]; ok {
			t.Fatalf("%s is on the default allowlist (cross-tenant signal)", cross)
		}
		if _, ok := jitlessSet[cross]; ok {
			t.Fatalf("%s is on the jitless allowlist (cross-tenant signal)", cross)
		}
	}
	if _, ok := defaultSet["tgkill"]; !ok {
		t.Fatal("tgkill missing from default profile (pthread_kill)")
	}

	// SeccompNeverAllow must hand out a copy — a caller mutating the result
	// must not edit the policy.
	got := SeccompNeverAllow()
	got[0] = "read"
	if SeccompNeverAllow()[0] == "read" {
		t.Fatal("SeccompNeverAllow returned the backing slice, not a copy")
	}
}
