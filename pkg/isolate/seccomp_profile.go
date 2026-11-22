package isolate

// The seccomp profile of a workerd group process (plans/isolate-runtime.md
// §2.1). It lives here, beside the filter builder, so the isolate driver
// (internal/runtime/isolate, privilege mode single) and the root helper
// (internal/rootd, privilege mode split) build one filter from one list.

// seccompBaseAllow is the syscall allowlist every workerd group process gets:
// what a glibc-linked V8 host needs from the dynamic loader onward — event
// loop, UDS IPC, anonymous memory, threads, signals, time — and the few
// legacy x86-64 names glibc still calls directly (skipped on arm64, which
// does not have them). The filter is installed before execve, so the loader
// runs under it too: that is why mprotect (RELRO, thread guard pages),
// set_tid_address, clone3 (pthread_create since glibc 2.34) and execve (the
// one exec, from the shim into workerd, with no_new_privs already set) are
// here. Argument-level constraints live in SeccompArgRules; the regression
// test pins these names so an accidental broadening shows up in review.
var seccompBaseAllow = []string{
	// I/O + event loop.
	"read", "write", "readv", "writev", "pread64", "pwrite64",
	"close", "close_range", "lseek", "fstat", "newfstatat", "statx", "fstatfs", "statfs",
	"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2", "epoll_wait", "eventfd2", "eventfd", "pipe2", "pipe",
	"poll", "ppoll", "select", "pselect6", "signalfd4",
	"timerfd_create", "timerfd_settime", "timerfd_gettime",
	"dup", "dup2", "dup3", "fcntl", "ioctl", // ioctl: FIONBIO/FIOCLEX only
	// UDS only — the jail's socket surface is the per-group IPC socket and
	// the per-sandbox egress endpoints; AF_INET never appears because all
	// network egress goes through the host proxy on the other side of a UDS.
	"socket", "socketpair", "connect", "bind", "listen", "accept4",
	"sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "sendto", "recvfrom", "shutdown",
	"getsockname", "getpeername", "getsockopt", "setsockopt",
	// Memory. mprotect is here because the loader and pthread need it; the
	// PROT_EXEC flips V8's JIT makes are what --jitless removes, by argument
	// rule (SeccompArgRules), not by name.
	"mmap", "munmap", "mremap", "mprotect", "madvise", "brk", "membarrier",
	"msync", "mincore", "mlock", "munlock",
	// Threads + synchronization. clone: thread flags only (CLONE_VM|CLONE_THREAD...),
	// never a new namespace.
	"clone", "clone3", "futex", "set_robust_list", "set_tid_address", "rseq", "sched_yield",
	"sched_getaffinity", "sched_setaffinity", "sched_getparam", "sched_getscheduler",
	"sched_get_priority_max", "sched_get_priority_min", "getcpu",
	"getpid", "gettid", "getppid", "getpgrp", "tgkill", "wait4",
	"getuid", "geteuid", "getgid", "getegid", "getgroups", "capget", "umask",
	// Signals.
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait", "rt_sigsuspend", "rt_sigpending",
	"sigaltstack", "pause", "restart_syscall",
	// Time + entropy.
	"clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep", "gettimeofday", "getrandom",
	"times", "getrusage", "getitimer", "setitimer",
	// Chroot-relative file access for the bundle + capnp config (+ the
	// loader's library lookups).
	"openat", "open", "getdents64", "getdents", "getcwd", "chdir", "fchdir",
	"faccessat2", "faccessat", "access", "readlink", "readlinkat", "stat", "lstat",
	"ftruncate", "truncate", "fallocate", "fsync", "fdatasync", "flock",
	"mkdirat", "unlinkat", "renameat", "renameat2", "utimensat",
	// Process bookkeeping + orderly exit.
	"prctl", "arch_prctl", "exit", "exit_group", "uname", "sysinfo",
	"setpriority", "getpriority", "prlimit64", "getrlimit",
	// Bootstrap: the shim's exec into workerd. no_new_privs is already set,
	// the chroot holds one binary, writable dirs are noexec tmpfs, and
	// execveat stays denied.
	"execve",
}

// seccompJITAllow is the V8-JIT extension: memfd-backed code spaces and the
// memory-protection-key calls V8 uses where the hardware has them. Dropped
// entirely in jitless mode, where PROT_EXEC flips are also refused by
// argument rule — this group is the risk the --jitless trade exists to remove.
var seccompJITAllow = []string{
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
	"execveat", "seccomp", "setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid", "capset",
	// Shared jail uid + host PID namespace would make these cross-tenant
	// kills. They stay off the allowlist even with a per-group PID
	// namespace (CLONE_NEWPID): pthread uses tgkill, and kill(-1)/tkill
	// are how one group would harvest every other group on the node.
	"kill", "tkill",
}

// Argument masks the jitless rules test (Linux ABI values, identical on
// x86-64 and arm64).
const (
	SeccompProtExec     = 0x4
	SeccompMapAnonymous = 0x20
)

// SeccompArgRules returns the argument-level narrowing for a profile. The
// JIT profile has none: V8 must flip code pages. Jitless refuses any
// PROT_EXEC on mprotect and any anonymous PROT_EXEC mapping, which leaves
// the loader free to map library text (file-backed) and RELRO (PROT_READ).
func SeccompArgRules(jitless bool) []SeccompArgRule {
	if !jitless {
		return nil
	}
	return []SeccompArgRule{
		{Syscall: "mprotect", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: SeccompProtExec}}},
		{Syscall: "mmap", DenyIfAll: []SeccompArgMask{{Arg: 2, Mask: SeccompProtExec}, {Arg: 3, Mask: SeccompMapAnonymous}}},
	}
}

// SeccompAllowlist returns the syscall names a group process may make.
// jitless=false is the default profile (base + JIT extension); jitless=true
// is the reduced paranoid-tier profile (base only, plus SeccompArgRules).
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
