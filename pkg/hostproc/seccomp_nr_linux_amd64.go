//go:build linux && amd64

package hostproc

import "golang.org/x/sys/unix"

// SeccompArch is the audit architecture BuildSeccomp checks on this host.
func SeccompArch() uint32 { return AuditArchX86_64 }

// SyscallTable maps the names the seccomp policies may use onto x86-64
// numbers. Names are resolved at spawn, so a name missing here is
// reported once and skipped rather than failing the build; a name present
// here but absent from the kernel headers is a compile error, which is the
// point of spelling them as unix.SYS_* constants.
func SyscallTable() map[string]int {
	return map[string]int{
		"read": unix.SYS_READ, "write": unix.SYS_WRITE, "readv": unix.SYS_READV, "writev": unix.SYS_WRITEV,
		"pread64": unix.SYS_PREAD64, "pwrite64": unix.SYS_PWRITE64, "close": unix.SYS_CLOSE, "lseek": unix.SYS_LSEEK,
		"fstat": unix.SYS_FSTAT, "newfstatat": unix.SYS_NEWFSTATAT, "statx": unix.SYS_STATX, "fstatfs": unix.SYS_FSTATFS,
		"statfs": unix.SYS_STATFS, "stat": unix.SYS_STAT, "lstat": unix.SYS_LSTAT,
		"epoll_create1": unix.SYS_EPOLL_CREATE1, "epoll_ctl": unix.SYS_EPOLL_CTL, "epoll_pwait": unix.SYS_EPOLL_PWAIT,
		"epoll_pwait2": unix.SYS_EPOLL_PWAIT2, "epoll_wait": unix.SYS_EPOLL_WAIT,
		"eventfd2": unix.SYS_EVENTFD2, "eventfd": unix.SYS_EVENTFD, "pipe2": unix.SYS_PIPE2, "pipe": unix.SYS_PIPE,
		"dup": unix.SYS_DUP, "dup2": unix.SYS_DUP2, "dup3": unix.SYS_DUP3, "fcntl": unix.SYS_FCNTL, "ioctl": unix.SYS_IOCTL,
		"socket": unix.SYS_SOCKET, "socketpair": unix.SYS_SOCKETPAIR, "connect": unix.SYS_CONNECT, "bind": unix.SYS_BIND,
		"listen": unix.SYS_LISTEN, "accept4": unix.SYS_ACCEPT4, "sendmsg": unix.SYS_SENDMSG, "recvmsg": unix.SYS_RECVMSG,
		"sendmmsg": unix.SYS_SENDMMSG, "recvmmsg": unix.SYS_RECVMMSG,
		"sendto": unix.SYS_SENDTO, "recvfrom": unix.SYS_RECVFROM, "shutdown": unix.SYS_SHUTDOWN,
		"getsockname": unix.SYS_GETSOCKNAME, "getpeername": unix.SYS_GETPEERNAME,
		"getsockopt": unix.SYS_GETSOCKOPT, "setsockopt": unix.SYS_SETSOCKOPT,
		"mmap": unix.SYS_MMAP, "munmap": unix.SYS_MUNMAP, "mremap": unix.SYS_MREMAP, "madvise": unix.SYS_MADVISE,
		"brk": unix.SYS_BRK, "membarrier": unix.SYS_MEMBARRIER, "mprotect": unix.SYS_MPROTECT,
		"msync": unix.SYS_MSYNC, "mincore": unix.SYS_MINCORE, "mlock": unix.SYS_MLOCK, "munlock": unix.SYS_MUNLOCK,
		"memfd_create": unix.SYS_MEMFD_CREATE, "pkey_alloc": unix.SYS_PKEY_ALLOC, "pkey_mprotect": unix.SYS_PKEY_MPROTECT,
		"pkey_free": unix.SYS_PKEY_FREE, "process_madvise": unix.SYS_PROCESS_MADVISE,
		"clone": unix.SYS_CLONE, "clone3": unix.SYS_CLONE3, "futex": unix.SYS_FUTEX, "set_robust_list": unix.SYS_SET_ROBUST_LIST,
		"set_tid_address": unix.SYS_SET_TID_ADDRESS, "rseq": unix.SYS_RSEQ, "sched_yield": unix.SYS_SCHED_YIELD,
		"sched_getaffinity": unix.SYS_SCHED_GETAFFINITY, "sched_setaffinity": unix.SYS_SCHED_SETAFFINITY,
		"sched_getparam": unix.SYS_SCHED_GETPARAM, "sched_getscheduler": unix.SYS_SCHED_GETSCHEDULER,
		"sched_get_priority_max": unix.SYS_SCHED_GET_PRIORITY_MAX, "sched_get_priority_min": unix.SYS_SCHED_GET_PRIORITY_MIN,
		"getpid": unix.SYS_GETPID, "gettid": unix.SYS_GETTID, "getppid": unix.SYS_GETPPID, "getpgrp": unix.SYS_GETPGRP,
		"tgkill": unix.SYS_TGKILL, "tkill": unix.SYS_TKILL, "kill": unix.SYS_KILL, "wait4": unix.SYS_WAIT4,
		"getuid": unix.SYS_GETUID, "geteuid": unix.SYS_GETEUID, "getgid": unix.SYS_GETGID, "getegid": unix.SYS_GETEGID,
		"getgroups": unix.SYS_GETGROUPS, "capget": unix.SYS_CAPGET, "umask": unix.SYS_UMASK,
		"rt_sigaction": unix.SYS_RT_SIGACTION, "rt_sigprocmask": unix.SYS_RT_SIGPROCMASK, "rt_sigreturn": unix.SYS_RT_SIGRETURN,
		"rt_sigtimedwait": unix.SYS_RT_SIGTIMEDWAIT, "rt_sigsuspend": unix.SYS_RT_SIGSUSPEND, "rt_sigpending": unix.SYS_RT_SIGPENDING,
		"sigaltstack": unix.SYS_SIGALTSTACK, "signalfd4": unix.SYS_SIGNALFD4, "pause": unix.SYS_PAUSE,
		"restart_syscall": unix.SYS_RESTART_SYSCALL,
		"clock_gettime":   unix.SYS_CLOCK_GETTIME, "clock_getres": unix.SYS_CLOCK_GETRES, "clock_nanosleep": unix.SYS_CLOCK_NANOSLEEP,
		"nanosleep": unix.SYS_NANOSLEEP, "gettimeofday": unix.SYS_GETTIMEOFDAY, "getrandom": unix.SYS_GETRANDOM,
		"times": unix.SYS_TIMES, "getrusage": unix.SYS_GETRUSAGE, "getitimer": unix.SYS_GETITIMER, "setitimer": unix.SYS_SETITIMER,
		"timerfd_create": unix.SYS_TIMERFD_CREATE, "timerfd_settime": unix.SYS_TIMERFD_SETTIME, "timerfd_gettime": unix.SYS_TIMERFD_GETTIME,
		"poll": unix.SYS_POLL, "ppoll": unix.SYS_PPOLL, "select": unix.SYS_SELECT, "pselect6": unix.SYS_PSELECT6,
		"openat": unix.SYS_OPENAT, "open": unix.SYS_OPEN, "getdents64": unix.SYS_GETDENTS64, "getdents": unix.SYS_GETDENTS,
		"getcwd": unix.SYS_GETCWD, "chdir": unix.SYS_CHDIR, "fchdir": unix.SYS_FCHDIR,
		"faccessat2": unix.SYS_FACCESSAT2, "faccessat": unix.SYS_FACCESSAT, "access": unix.SYS_ACCESS,
		"readlink": unix.SYS_READLINK, "readlinkat": unix.SYS_READLINKAT,
		"ftruncate": unix.SYS_FTRUNCATE, "truncate": unix.SYS_TRUNCATE, "fallocate": unix.SYS_FALLOCATE,
		"fsync": unix.SYS_FSYNC, "fdatasync": unix.SYS_FDATASYNC, "flock": unix.SYS_FLOCK,
		"mkdirat": unix.SYS_MKDIRAT, "unlinkat": unix.SYS_UNLINKAT, "renameat": unix.SYS_RENAMEAT, "renameat2": unix.SYS_RENAMEAT2,
		"utimensat": unix.SYS_UTIMENSAT, "close_range": unix.SYS_CLOSE_RANGE,
		"prctl": unix.SYS_PRCTL, "arch_prctl": unix.SYS_ARCH_PRCTL, "exit": unix.SYS_EXIT, "exit_group": unix.SYS_EXIT_GROUP,
		"uname": unix.SYS_UNAME, "sysinfo": unix.SYS_SYSINFO, "setpriority": unix.SYS_SETPRIORITY, "getpriority": unix.SYS_GETPRIORITY,
		"prlimit64": unix.SYS_PRLIMIT64, "getrlimit": unix.SYS_GETRLIMIT, "getcpu": unix.SYS_GETCPU,
		"execve": unix.SYS_EXECVE,
		// The WASM worker's extras: Go's file copies and links, and the
		// legacy names its *at calls replace (same operations, never more).
		"accept": unix.SYS_ACCEPT, "copy_file_range": unix.SYS_COPY_FILE_RANGE,
		"sendfile": unix.SYS_SENDFILE, "splice": unix.SYS_SPLICE, "tee": unix.SYS_TEE,
		"linkat": unix.SYS_LINKAT, "symlinkat": unix.SYS_SYMLINKAT, "fchmod": unix.SYS_FCHMOD, "fchmodat": unix.SYS_FCHMODAT,
		"openat2": unix.SYS_OPENAT2, "unlink": unix.SYS_UNLINK, "rmdir": unix.SYS_RMDIR, "rename": unix.SYS_RENAME,
		"mkdir": unix.SYS_MKDIR, "link": unix.SYS_LINK, "symlink": unix.SYS_SYMLINK, "chmod": unix.SYS_CHMOD,
		// Named only to be refused (kill lists and fallbacks).
		"ptrace": unix.SYS_PTRACE, "process_vm_readv": unix.SYS_PROCESS_VM_READV, "process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
		"mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2, "pivot_root": unix.SYS_PIVOT_ROOT, "chroot": unix.SYS_CHROOT,
		"setns": unix.SYS_SETNS, "unshare": unix.SYS_UNSHARE, "init_module": unix.SYS_INIT_MODULE,
		"finit_module": unix.SYS_FINIT_MODULE, "delete_module": unix.SYS_DELETE_MODULE, "kexec_load": unix.SYS_KEXEC_LOAD,
		"kexec_file_load": unix.SYS_KEXEC_FILE_LOAD, "open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
		"name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT, "perf_event_open": unix.SYS_PERF_EVENT_OPEN, "bpf": unix.SYS_BPF,
		"userfaultfd": unix.SYS_USERFAULTFD, "keyctl": unix.SYS_KEYCTL, "add_key": unix.SYS_ADD_KEY,
		"request_key": unix.SYS_REQUEST_KEY, "reboot": unix.SYS_REBOOT, "swapon": unix.SYS_SWAPON, "swapoff": unix.SYS_SWAPOFF,
		"sethostname": unix.SYS_SETHOSTNAME, "setdomainname": unix.SYS_SETDOMAINNAME, "iopl": unix.SYS_IOPL,
		"ioperm": unix.SYS_IOPERM, "quotactl": unix.SYS_QUOTACTL, "fsopen": unix.SYS_FSOPEN, "fsconfig": unix.SYS_FSCONFIG,
		"fsmount": unix.SYS_FSMOUNT, "fspick": unix.SYS_FSPICK, "move_mount": unix.SYS_MOVE_MOUNT, "open_tree": unix.SYS_OPEN_TREE,
		"mount_setattr": unix.SYS_MOUNT_SETATTR, "execveat": unix.SYS_EXECVEAT, "setuid": unix.SYS_SETUID,
		"setgid": unix.SYS_SETGID, "setresuid": unix.SYS_SETRESUID, "setresgid": unix.SYS_SETRESGID,
		"setreuid": unix.SYS_SETREUID, "setregid": unix.SYS_SETREGID, "setgroups": unix.SYS_SETGROUPS,
		"setfsuid": unix.SYS_SETFSUID, "setfsgid": unix.SYS_SETFSGID, "capset": unix.SYS_CAPSET,
		"io_uring_setup": unix.SYS_IO_URING_SETUP, "io_uring_enter": unix.SYS_IO_URING_ENTER,
		"io_uring_register": unix.SYS_IO_URING_REGISTER, "acct": unix.SYS_ACCT, "settimeofday": unix.SYS_SETTIMEOFDAY,
		"clock_settime": unix.SYS_CLOCK_SETTIME, "clock_adjtime": unix.SYS_CLOCK_ADJTIME, "adjtimex": unix.SYS_ADJTIMEX,
		"pidfd_getfd": unix.SYS_PIDFD_GETFD, "seccomp": unix.SYS_SECCOMP, "syslog": unix.SYS_SYSLOG,
		"mknod": unix.SYS_MKNOD, "mknodat": unix.SYS_MKNODAT,
	}
}
