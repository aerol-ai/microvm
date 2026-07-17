package isolate

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// The workerd jail (plans/isolate-runtime.md §2.1, Phase-1 deliverable).
//
// Isolates share an OS process, so the process boundary between isolate
// groups is the REQUIRED cross-tenant boundary — upstream workerd itself
// tells self-hosters to wrap possibly-malicious code in "an appropriate
// secure sandbox". This file is the jail's specification: given a group key
// and resource caps, it computes the chroot, cgroup, privilege-drop, and
// seccomp policy a group process must run under. Realization (clone/chroot/
// setuid/seccomp(2) on Linux) lands with the group spawner in Phase 2; the
// spec lives here so its invariants are regression-tested from Phase 1 and
// the spawner can only ever consume a validated spec.
//
// The chroot + cgroups + drop-priv shape reuses the Firecracker jailer's
// pattern. The new work — and the reason this is budgeted as its own
// subproject — is the seccomp allowlist for a JIT-heavy V8 process: V8
// rewrites page protections (W^X flips via mprotect/pkey_mprotect), backs
// code spaces with memfd, and spawns worker threads, none of which a
// conventional network-daemon allowlist permits. --jitless (SB_ISOLATE_JITLESS)
// removes that whole group at a large throughput cost — the honest
// alternative for the per-sandbox paranoid tier if the JIT allowlist proves
// too broad to mean anything.

// JailSpec describes the OS confinement for one workerd group process. Build
// one with BuildJailSpec; a hand-rolled spec must pass Validate before use.
type JailSpec struct {
	// GroupKey is the sanitized isolate-group key (per-tenant granularity:
	// the authorized tenant id; per-sandbox granularity: the sandbox id;
	// empty tenant falls back to DefaultGroupKey).
	GroupKey string
	// ChrootDir is the group's private root: <JailChrootBase>/<GroupKey>.
	ChrootDir string
	// CgroupName is the per-group cgroup that enforces the GROUP-level
	// resource caps (§2.1): OSS workerd has no per-isolate CPU enforcement,
	// so the enforced blast radius is the group.
	CgroupName string
	// UID / GID are the unprivileged identity the process drops to.
	UID int
	GID int
	// CPUQuota / MemoryLimitMB are the group cgroup caps. Zero = unlimited
	// on that axis (the cgroup controller is left unset).
	CPUQuota      float64
	MemoryLimitMB int
	// Jitless selects the reduced seccomp profile (and --jitless on the V8
	// command line when the spawner realizes the spec).
	Jitless bool
}

// DefaultGroupKey is the isolate-group key for the null tenant: creates whose
// group key fell back to an unscoped (operator/PAT) identity share one
// default group, which is the single-tenant self-hoster's zero-config path.
const DefaultGroupKey = "default"

// groupKeyPattern is deliberately strict: the key becomes a chroot directory
// name and a cgroup name, so anything path-ambiguous (separators, dots-only
// segments, leading dashes) is rejected rather than escaped.
var groupKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// SanitizeGroupKey validates a group key for use in host paths and cgroup
// names. Empty maps to DefaultGroupKey; anything else must match
// groupKeyPattern exactly — no normalization, because two keys that
// normalize to the same directory would silently merge two tenants into one
// process (§2.1's forced-co-residency attack, at the filesystem layer).
func SanitizeGroupKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return DefaultGroupKey, nil
	}
	if !groupKeyPattern.MatchString(key) {
		return "", fmt.Errorf("isolate group key %q: must match %s", key, groupKeyPattern.String())
	}
	if strings.Contains(key, "..") {
		return "", fmt.Errorf("isolate group key %q: must not contain '..'", key)
	}
	return key, nil
}

// BuildJailSpec computes the jail for one group under the driver config.
// cpu / memoryMB are the GROUP-level caps (map CreateSandboxRequest.CPU /
// MemoryMB onto them at create time — Phase 4 owns the exact mapping).
func BuildJailSpec(cfg Config, groupKey string, cpu float64, memoryMB int) (JailSpec, error) {
	key, err := SanitizeGroupKey(groupKey)
	if err != nil {
		return JailSpec{}, err
	}
	spec := JailSpec{
		GroupKey:      key,
		ChrootDir:     filepath.Join(cfg.JailChrootBase, key),
		CgroupName:    "aerolvm-isolate-" + key,
		UID:           cfg.JailUID,
		GID:           cfg.JailGID,
		CPUQuota:      cpu,
		MemoryLimitMB: memoryMB,
		Jitless:       cfg.Jitless,
	}
	if err := spec.Validate(); err != nil {
		return JailSpec{}, err
	}
	return spec, nil
}

// Validate enforces the spec's invariants. It exists separately from
// BuildJailSpec so the spawner can re-assert them at realization time — the
// spec may have crossed a channel or been rehydrated from the store by then.
func (s JailSpec) Validate() error {
	if _, err := SanitizeGroupKey(s.GroupKey); err != nil {
		return err
	}
	if s.GroupKey == "" {
		return fmt.Errorf("isolate jail: empty group key")
	}
	if s.ChrootDir == "" || !filepath.IsAbs(s.ChrootDir) {
		return fmt.Errorf("isolate jail: chroot dir %q must be absolute", s.ChrootDir)
	}
	// A jailed-but-root workerd defeats the point of the jail.
	if s.UID <= 0 || s.GID <= 0 {
		return fmt.Errorf("isolate jail: uid/gid must be non-root (> 0), got %d/%d", s.UID, s.GID)
	}
	if s.CPUQuota < 0 {
		return fmt.Errorf("isolate jail: cpu quota must be >= 0, got %f", s.CPUQuota)
	}
	if s.MemoryLimitMB < 0 {
		return fmt.Errorf("isolate jail: memory limit must be >= 0, got %d", s.MemoryLimitMB)
	}
	return nil
}

// seccompBaseAllow is the syscall allowlist every workerd group process gets:
// event loop + UDS IPC + anonymous memory + threads. Names are Linux
// (x86-64/arm64 shared); argument-level constraints noted inline are enforced
// at realization (Phase 2) — the names alone are the spec's floor, and the
// regression test pins them so an accidental broadening shows up in review.
var seccompBaseAllow = []string{
	// I/O + event loop.
	"read", "write", "readv", "writev", "pread64", "pwrite64",
	"close", "lseek", "fstat", "newfstatat", "statx", "fstatfs",
	"epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "pipe2",
	"dup", "dup3", "fcntl", "ioctl", // ioctl: FIONBIO/FIOCLEX only
	// UDS only — the jail's socket surface is the per-group IPC socket and
	// the per-sandbox egress endpoints; AF_INET never appears because all
	// network egress goes through the host proxy on the other side of a UDS.
	"socket", "socketpair", "connect", "bind", "listen", "accept4",
	"sendmsg", "recvmsg", "sendto", "recvfrom", "shutdown",
	"getsockname", "getsockopt", "setsockopt",
	// Anonymous memory (no PROT_EXEC in the base set).
	"mmap", "munmap", "mremap", "madvise", "brk", "membarrier",
	// Threads + synchronization. clone: thread flags only (CLONE_VM|CLONE_THREAD...),
	// never a new namespace.
	"clone", "futex", "set_robust_list", "rseq", "sched_yield",
	"sched_getaffinity", "getpid", "gettid", "tgkill",
	// Signals.
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
	// Time + entropy.
	"clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday", "getrandom",
	// Chroot-relative file access for the bundle + capnp config.
	"openat", "getdents64", "getcwd", "faccessat2", "ftruncate",
	// Process bookkeeping + orderly exit.
	"prctl", "arch_prctl", "exit", "exit_group", "uname", "setpriority",
}

// seccompJITAllow is the V8-JIT extension: W^X page flips, memfd-backed code
// spaces, and the memory-protection-key calls V8 uses where the hardware has
// them. Dropped entirely in jitless mode — this group is the risk the
// --jitless trade exists to remove.
var seccompJITAllow = []string{
	"mprotect",        // W^X flips on code pages (mmap gains PROT_EXEC here too)
	"memfd_create",    // anonymous code-space backing
	"pkey_alloc",      // V8 memory protection keys
	"pkey_mprotect",   //
	"pkey_free",       //
	"process_madvise", // code-space reclaim
}

// seccompNeverAllow is the deny-regardless list: syscalls that must not
// appear in any profile variant because each one is a jail-escape or
// host-takeover primitive. The regression test asserts this list is disjoint
// from every allowlist — the lists are maintained by hand, and this is the
// invariant that keeps a future edit honest.
var seccompNeverAllow = []string{
	"ptrace", "process_vm_readv", "process_vm_writev",
	"mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
	"init_module", "finit_module", "delete_module", "kexec_load",
	"open_by_handle_at", "perf_event_open", "bpf", "userfaultfd",
	"keyctl", "add_key", "request_key",
	"reboot", "swapon", "swapoff", "sethostname", "setdomainname",
	"iopl", "ioperm", "quotactl",
	"fsopen", "fsconfig", "fsmount", "move_mount",
	"execve", "execveat", // workerd never re-execs inside the jail
}

// SeccompAllowlist returns the syscall names a group process may make.
// jitless=false is the default profile (base + JIT extension); jitless=true
// is the reduced paranoid-tier profile.
func SeccompAllowlist(jitless bool) []string {
	out := make([]string, 0, len(seccompBaseAllow)+len(seccompJITAllow))
	out = append(out, seccompBaseAllow...)
	if !jitless {
		out = append(out, seccompJITAllow...)
	}
	return out
}

// SeccompNeverAllow returns the deny-regardless list (see seccompNeverAllow).
func SeccompNeverAllow() []string {
	out := make([]string, len(seccompNeverAllow))
	copy(out, seccompNeverAllow)
	return out
}

// SeccompAllowlistFor returns the profile matching the spec's Jitless flag.
func (s JailSpec) SeccompAllowlistFor() []string {
	return SeccompAllowlist(s.Jitless)
}
