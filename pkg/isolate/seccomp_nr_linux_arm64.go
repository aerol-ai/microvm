//go:build linux && arm64

package isolate

import "golang.org/x/sys/unix"

func seccompAuditArch() uint32 { return auditArchAARCH64 }

// seccompSyscallTable is the aarch64 table. The legacy x86-64-only entries
// (open, stat, poll, select, dup2, pipe, eventfd, getdents, readlink, access,
// epoll_wait, arch_prctl, ...) do not exist on this ABI and are absent here;
// resolveSyscalls skips them, which narrows nothing because glibc cannot call
// what the kernel does not have.
func seccompSyscallTable() map[string]int {
	return map[string]int{
		"read": unix.SYS_READ, "write": unix.SYS_WRITE, "readv": unix.SYS_READV, "writev": unix.SYS_WRITEV,
		"pread64": unix.SYS_PREAD64, "pwrite64": unix.SYS_PWRITE64, "close": unix.SYS_CLOSE, "lseek": unix.SYS_LSEEK,
		"fstat": unix.SYS_FSTAT, "newfstatat": unix.SYS_NEWFSTATAT, "statx": unix.SYS_STATX, "fstatfs": unix.SYS_FSTATFS,
		"statfs":        unix.SYS_STATFS,
		"epoll_create1": unix.SYS_EPOLL_CREATE1, "epoll_ctl": unix.SYS_EPOLL_CTL, "epoll_pwait": unix.SYS_EPOLL_PWAIT,
		"epoll_pwait2": unix.SYS_EPOLL_PWAIT2,
		"eventfd2":     unix.SYS_EVENTFD2, "pipe2": unix.SYS_PIPE2,
		"dup": unix.SYS_DUP, "dup3": unix.SYS_DUP3, "fcntl": unix.SYS_FCNTL, "ioctl": unix.SYS_IOCTL,
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
		"getpid": unix.SYS_GETPID, "gettid": unix.SYS_GETTID, "getppid": unix.SYS_GETPPID,
		"tgkill": unix.SYS_TGKILL, "tkill": unix.SYS_TKILL, "kill": unix.SYS_KILL, "wait4": unix.SYS_WAIT4,
		"getuid": unix.SYS_GETUID, "geteuid": unix.SYS_GETEUID, "getgid": unix.SYS_GETGID, "getegid": unix.SYS_GETEGID,
		"getgroups": unix.SYS_GETGROUPS, "capget": unix.SYS_CAPGET, "umask": unix.SYS_UMASK,
		"rt_sigaction": unix.SYS_RT_SIGACTION, "rt_sigprocmask": unix.SYS_RT_SIGPROCMASK, "rt_sigreturn": unix.SYS_RT_SIGRETURN,
		"rt_sigtimedwait": unix.SYS_RT_SIGTIMEDWAIT, "rt_sigsuspend": unix.SYS_RT_SIGSUSPEND, "rt_sigpending": unix.SYS_RT_SIGPENDING,
		"sigaltstack": unix.SYS_SIGALTSTACK, "signalfd4": unix.SYS_SIGNALFD4,
		"restart_syscall": unix.SYS_RESTART_SYSCALL,
		"clock_gettime":   unix.SYS_CLOCK_GETTIME, "clock_getres": unix.SYS_CLOCK_GETRES, "clock_nanosleep": unix.SYS_CLOCK_NANOSLEEP,
		"nanosleep": unix.SYS_NANOSLEEP, "gettimeofday": unix.SYS_GETTIMEOFDAY, "getrandom": unix.SYS_GETRANDOM,
		"times": unix.SYS_TIMES, "getrusage": unix.SYS_GETRUSAGE, "getitimer": unix.SYS_GETITIMER, "setitimer": unix.SYS_SETITIMER,
		"timerfd_create": unix.SYS_TIMERFD_CREATE, "timerfd_settime": unix.SYS_TIMERFD_SETTIME, "timerfd_gettime": unix.SYS_TIMERFD_GETTIME,
		"ppoll": unix.SYS_PPOLL, "pselect6": unix.SYS_PSELECT6,
		"openat": unix.SYS_OPENAT, "getdents64": unix.SYS_GETDENTS64,
		"getcwd": unix.SYS_GETCWD, "chdir": unix.SYS_CHDIR, "fchdir": unix.SYS_FCHDIR,
		"faccessat2": unix.SYS_FACCESSAT2, "faccessat": unix.SYS_FACCESSAT,
		"readlinkat": unix.SYS_READLINKAT,
		"ftruncate":  unix.SYS_FTRUNCATE, "truncate": unix.SYS_TRUNCATE, "fallocate": unix.SYS_FALLOCATE,
		"fsync": unix.SYS_FSYNC, "fdatasync": unix.SYS_FDATASYNC, "flock": unix.SYS_FLOCK,
		"mkdirat": unix.SYS_MKDIRAT, "unlinkat": unix.SYS_UNLINKAT, "renameat": unix.SYS_RENAMEAT, "renameat2": unix.SYS_RENAMEAT2,
		"utimensat": unix.SYS_UTIMENSAT, "close_range": unix.SYS_CLOSE_RANGE,
		"prctl": unix.SYS_PRCTL, "exit": unix.SYS_EXIT, "exit_group": unix.SYS_EXIT_GROUP,
		"uname": unix.SYS_UNAME, "sysinfo": unix.SYS_SYSINFO, "setpriority": unix.SYS_SETPRIORITY, "getpriority": unix.SYS_GETPRIORITY,
		"prlimit64": unix.SYS_PRLIMIT64, "getrlimit": unix.SYS_GETRLIMIT, "getcpu": unix.SYS_GETCPU,
		"execve": unix.SYS_EXECVE,
	}
}
