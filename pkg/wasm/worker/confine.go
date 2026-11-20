package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// A WASM worker runs tenant modules, so an escape from the engine must not
// be root on the host. sandboxd starts each worker as root (it must: the
// worker joins its cgroup and opens what only root may), and the worker
// then, before it reads a single message:
//
//  1. reads the egress floor file and the operator file (and the upstream
//     proxy's credentials) while it still may, and keeps the floor file
//     open to re-read it later;
//  2. listens on its socket, so the socket is root's in a root-only
//     directory and no other worker can connect to it;
//  3. opens its compile cache and its audit spill folder, which it reaches
//     through those descriptors from then on (wasmengine.GrantHostPath has
//     the same reasoning for everything sandboxd passes it later);
//  4. drops to the worker uid/gid with no groups, no_new_privs and not
//     dumpable (hostproc.DropPrivileges), and installs workerSeccompPolicy.
//
// sandboxd starts it in a PID namespace of its own (Confine), so the kill
// and tgkill the Go runtime needs reach nothing but the worker itself, even
// though every worker shares one uid.

// Environment the spawner sets for the worker.
const (
	// confineEnv is "uid:gid": drop to them before serving.
	confineEnv = "AEROL_WASM_WORKER_CONFINE"
	// cacheDirEnv is the compile cache of the owner whose code the worker
	// runs (WithCompileCache).
	cacheDirEnv = "AEROL_WASM_WORKER_CACHE_DIR"
)

// Confinement is the uid/gid workers drop to. The zero value confines
// nothing: workers then run as sandboxd does (SB_WASM_WORKER_DROP_PRIVS=false,
// or a sandboxd that is not root).
type Confinement struct {
	UID int
	GID int
}

// Enabled reports whether workers drop to c.
func (c Confinement) Enabled() bool { return c.UID > 0 && c.GID > 0 }

// Confine makes spawn's workers drop to c before they serve, each in a PID
// namespace of its own and with an audit spill folder of its own. A
// disabled c returns spawn unchanged, and so does a start marked
// WithoutConfinement. A worker that would drop is not started while the
// confine gate (SetConfineGate) refuses.
func Confine(spawn Spawner, c Confinement) Spawner {
	if spawn == nil || !c.Enabled() {
		return spawn
	}
	return func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		spec := specFrom(ctx)
		if !spec.rootOnly {
			if gate := confineGate.Load(); gate != nil {
				if err := (*gate)(); err != nil {
					return nil, fmt.Errorf("wasm worker not started: %w", err)
				}
			}
		}
		cmd, err := spawn(ctx, socketPath)
		if err != nil {
			return nil, err
		}
		if spec.rootOnly {
			return cmd, nil
		}
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(privateSpill(cmd.Env, spillLabel(spec, socketPath), c), fmt.Sprintf("%s=%d:%d", confineEnv, c.UID, c.GID))
		setOwnPIDNamespace(cmd)
		return cmd, nil
	}
}

// confineGate is asked before every worker that drops is started.
var confineGate atomic.Pointer[func() error]

// SetConfineGate makes every worker start that would drop ask gate first,
// and fail with its error: the drop is only worth what the node keeps the
// worker uid from reaching, so a worker is not started dropped while that
// is not in place (pkg/daemon: the WASM worker fence). nil removes it.
// Workers kept root (WithoutConfinement) are not asked.
func SetConfineGate(gate func() error) {
	if gate == nil {
		confineGate.Store(nil)
		return
	}
	confineGate.Store(&gate)
}

// spawnSpec is what sandboxd decides about one worker beyond its socket.
// The supervisor keeps it with the slot, so a respawn after a crash gets
// the same.
type spawnSpec struct {
	// cacheDir is the owner's compile cache (WithCompileCache).
	cacheDir string
	// spillLabel names the worker's audit spill folder (WithSpillLabel).
	spillLabel string
	// rootOnly keeps the worker root (WithoutConfinement).
	rootOnly bool
}

type spawnSpecKey struct{}

func specFrom(ctx context.Context) spawnSpec {
	if ctx == nil {
		return spawnSpec{}
	}
	s, _ := ctx.Value(spawnSpecKey{}).(spawnSpec)
	return s
}

func withSpec(ctx context.Context, s spawnSpec) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, spawnSpecKey{}, s)
}

// WithCompileCache tells the spawner which compile cache the worker it
// starts may use: the one of the owner whose code that worker will run
// (dir is made and owned for the worker by sandboxd). A worker started
// without one compiles without a cache: it must not write a cache another
// owner's worker reads.
func WithCompileCache(ctx context.Context, dir string) context.Context {
	s := specFrom(ctx)
	s.cacheDir = strings.TrimSpace(dir)
	return withSpec(ctx, s)
}

// WithSpillLabel names the audit spill folder of the worker started under
// ctx: "sb-<sandbox id>" for a sandbox's own worker, which is what the
// drain stamps its records with. A worker without one gets a folder named
// after its socket.
func WithSpillLabel(ctx context.Context, label string) context.Context {
	s := specFrom(ctx)
	s.spillLabel = label
	return withSpec(ctx, s)
}

// WithoutConfinement starts the worker as root despite Confine: a sandbox
// whose s3 or rclone mounts were started for root before workers dropped
// (mounts.ContainerBind.RootOnly) keeps a root worker until it is
// recreated, because its mounts may not be restarted under it.
func WithoutConfinement(ctx context.Context) context.Context {
	s := specFrom(ctx)
	s.rootOnly = true
	return withSpec(ctx, s)
}

// KeepsRoot reports whether a worker started under ctx stays root
// (WithoutConfinement).
func KeepsRoot(ctx context.Context) bool { return specFrom(ctx).rootOnly }

// CompileCacheOf is the cache WithCompileCache put on ctx, "" for none.
func CompileCacheOf(ctx context.Context) string { return compileCacheFrom(ctx) }

// compileCacheFrom is the cache WithCompileCache put on ctx, "" for none.
func compileCacheFrom(ctx context.Context) string { return specFrom(ctx).cacheDir }

// spillLabel is the name of a worker's own spill folder.
func spillLabel(s spawnSpec, socketPath string) string {
	if validSpillLabel(s.spillLabel) {
		return s.spillLabel
	}
	sum := sha256.Sum256([]byte(socketPath))
	return "w-" + hex.EncodeToString(sum[:8])
}

func validSpillLabel(label string) bool {
	if label == "" || len(label) > 128 || label == "." || label == ".." {
		return false
	}
	for _, c := range label {
		if !(c == '-' || c == '_' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// spillEnv names the audit spill folder in a worker's environment.
const spillEnv = "SB_AUDIT_SPILL_DIR"

// privateSpill points a confined worker at a spill folder of its own, made
// under the folder sandboxd named and owned by the worker uid: no worker
// can read, change or remove another's spilled records. When the folder
// cannot be made the worker gets none (its spills are counted as drops),
// never the shared one.
func privateSpill(env []string, label string, c Confinement) []string {
	out := make([]string, 0, len(env))
	root := ""
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, spillEnv+"="); ok {
			root = strings.TrimSpace(v)
			continue
		}
		out = append(out, e)
	}
	if root == "" {
		return out
	}
	dir := filepath.Join(root, label)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return out
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return out
	}
	if err := os.Lchown(dir, c.UID, c.GID); err != nil {
		return out
	}
	return append(out, spillEnv+"="+dir)
}

// RemoveSpillFolder removes a worker's own spill folder once the worker is
// gone. Records still in it stay for the drain: the folder is renamed
// (auditlog.WorkerSpillRetiredPrefix) and the drain removes it after.
func RemoveSpillFolder(label string) {
	root := strings.TrimSpace(os.Getenv(spillEnv))
	if root == "" || !validSpillLabel(label) {
		return
	}
	dir := filepath.Join(root, label)
	if _, err := os.Lstat(filepath.Join(dir, auditlog.SpillFileName)); err == nil {
		_ = os.Rename(dir, filepath.Join(root, auditlog.WorkerSpillRetiredPrefix+label))
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		return
	}
	_ = os.Remove(filepath.Join(dir, auditlog.LockFileName))
	_ = os.Remove(dir)
}

// PrecompileFlag runs sandboxd as the trusted compile step
// (RunPrecompileCLI).
const PrecompileFlag = "--wasm-precompile"

// RunPrecompileCLI is `--wasm-precompile <cache-dir> <module>`: compile an
// operator module into the shared compile cache (pkg/wasm.PrecompileModule)
// and exit. It runs no tenant code and reads only a module the resolver
// says the operator staged; sandboxd then makes what it wrote read-only.
func RunPrecompileCLI(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: %s <cache-dir> <module>", PrecompileFlag)
	}
	return wasmengine.PrecompileModule(context.Background(), args[0], args[1])
}

// Precompile runs RunPrecompileCLI in a process of its own: the compile's
// memory is returned when it ends, not kept by sandboxd.
func Precompile(ctx context.Context, cacheDir, modulePath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, exe, PrecompileFlag, cacheDir, modulePath)
	cmd.Env = workerEnvironment(context.Background())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("precompile %s: %w: %s", modulePath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseConfinement reads confineEnv's "uid:gid".
func parseConfinement(raw string) (Confinement, error) {
	u, g, ok := strings.Cut(strings.TrimSpace(raw), ":")
	uid, uerr := strconv.Atoi(u)
	gid, gerr := strconv.Atoi(g)
	c := Confinement{UID: uid, GID: gid}
	if !ok || uerr != nil || gerr != nil || !c.Enabled() {
		return Confinement{}, fmt.Errorf("wasm worker: %s=%q is not a non-root uid:gid", confineEnv, raw)
	}
	return c, nil
}

// spillDirOverride is the audit spill folder as the worker reaches it after
// the drop (through the descriptor it opened before). nil: the path.
var spillDirOverride atomic.Pointer[string]

// workerServer is what both worker kinds share for start-up.
type workerServer interface {
	Serve(net.Conn) error
	close()
	// prepare builds what the worker reads before it drops: the dial
	// mediator, which reads the operator file and its credentials.
	prepare()
}

func (s *Server) prepare() {
	s.mu.Lock()
	s.mediator()
	s.mu.Unlock()
}

func (s *ResidentServer) prepare() { s.mediator() }

// runWorker is RunCLI and RunCLIResident: the start-up above, then serve.
func runWorker(socketPath string, srv workerServer) error {
	if err := loadWorkerGuards(); err != nil {
		return err
	}
	ln, err := listenWorker(socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer srv.close()
	// The worker resolves the names guests dial (the mediator dials by
	// name). Go's own resolver keeps the C library's name-service modules,
	// which load code at run time, out of a process under a syscall filter.
	net.DefaultResolver.PreferGo = true
	openWorkerDirs()
	srv.prepare()
	if err := confineFromEnv(); err != nil {
		return err
	}
	return serveListener(ln, srv)
}

// listenWorker binds the worker's socket. A var so tests can end a
// runWorker by closing its listener.
var listenWorker = func(socketPath string) (net.Listener, error) {
	_ = os.Remove(socketPath)
	return net.Listen("unix", socketPath)
}

// openWorkerDirs opens the compile cache and the spill folder before the
// drop and points the worker at them through the descriptors, which it
// keeps for its life. A folder that cannot be opened costs only what it
// is for: compiles without a cache, spills that are counted as drops.
func openWorkerDirs() {
	// Never the node-wide cache, should it be in the environment: a worker
	// compiles into its owner's cache or into none.
	_ = os.Unsetenv("AEROL_WASM_COMPILE_CACHE_DIR")
	if via := heldDir(strings.TrimSpace(os.Getenv(cacheDirEnv))); via != "" {
		wasmengine.SetCompileCacheDir(via)
	}
	if spill := workerEgressSpillDir(); spill != "" {
		if via := heldDir(spill); via != "" {
			spillDirOverride.Store(&via)
		}
	}
}

// heldDir opens dir for the rest of the worker's life and returns the path
// that reaches it through the descriptor ("" when it cannot be opened). Off
// Linux there is no such path, and nothing drops, so dir itself is used.
func heldDir(dir string) string {
	if dir == "" {
		return ""
	}
	f, err := os.Open(dir)
	if err != nil {
		return ""
	}
	if st, err := f.Stat(); err != nil || !st.IsDir() {
		_ = f.Close()
		return ""
	}
	via := hostproc.ConfinedProcFD(f.Fd())
	if via == "" {
		_ = f.Close()
		return dir
	}
	// f must stay open, and referenced: an *os.File nothing refers to is
	// closed by its finalizer at the next garbage collection, and the
	// descriptor number then names nothing, or another file.
	heldDirs.Lock()
	heldDirs.files = append(heldDirs.files, f)
	heldDirs.Unlock()
	return via
}

// heldDirs keeps the folders heldDir opened for the worker's life.
var heldDirs struct {
	sync.Mutex
	files []*os.File
}

// confineFromEnv drops the worker's privileges when the spawner asked for
// it. Any failure stops the worker: one that was asked to drop must not
// serve as root.
func confineFromEnv() error {
	raw := os.Getenv(confineEnv)
	if raw == "" {
		return nil
	}
	c, err := parseConfinement(raw)
	if err != nil {
		return err
	}
	if err := applyConfinement(c); err != nil {
		return err
	}
	confined.Store(true)
	return nil
}

// confined is set once the worker has dropped its privileges: from then on
// it opens no connection to its guest's listeners (the fence would drop
// it), and takes the ones sandboxd opens.
var confined atomic.Bool

func workerConfined() bool { return confined.Load() }

// serveListener serves each connection on ln with srv until ln fails.
func serveListener(ln net.Listener, srv workerServer) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = srv.Serve(c)
		}(conn)
	}
}

// workerSeccompAllow is what a worker may call: the Go runtime (and the C
// library under cgo: threads, the resolver), the wazero compiler (W^X code
// pages), WASI file access through the granted descriptors, the guest's
// mediated sockets and the worker's own socket. Legacy x86-64 names are
// skipped on arm64, which has none of them.
var workerSeccompAllow = []string{
	// I/O + event loop.
	"read", "write", "readv", "writev", "pread64", "pwrite64",
	"close", "close_range", "lseek", "fstat", "newfstatat", "statx", "fstatfs", "statfs",
	"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2", "epoll_wait", "eventfd2", "eventfd", "pipe2", "pipe",
	"poll", "ppoll", "select", "pselect6", "signalfd4",
	"timerfd_create", "timerfd_settime", "timerfd_gettime",
	"dup", "dup2", "dup3", "fcntl", "ioctl",
	"copy_file_range", "sendfile", "splice", "tee",
	// Sockets: the worker's own, the guest's mediated ones, DNS, and the
	// audit ingest on loopback. socket is narrowed by family
	// (workerSocketFamilies).
	"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
	"sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "sendto", "recvfrom", "shutdown",
	"getsockname", "getpeername", "getsockopt", "setsockopt",
	// Memory, including the compiler's executable pages.
	"mmap", "munmap", "mremap", "mprotect", "madvise", "brk", "membarrier",
	"msync", "mincore", "mlock", "munlock",
	// Threads + synchronization. clone is ruled by flag (no namespaces).
	"futex", "set_robust_list", "set_tid_address", "rseq", "sched_yield",
	"sched_getaffinity", "sched_setaffinity", "sched_getparam", "sched_getscheduler",
	"sched_get_priority_max", "sched_get_priority_min", "getcpu",
	"getpid", "gettid", "getppid", "getpgrp", "wait4",
	"getuid", "geteuid", "getgid", "getegid", "getgroups", "capget", "umask",
	// Signals. kill and tgkill reach only the worker: it is alone in its
	// PID namespace.
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait", "rt_sigsuspend", "rt_sigpending",
	"sigaltstack", "pause", "restart_syscall", "kill", "tgkill",
	// Time + entropy.
	"clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep", "gettimeofday", "getrandom",
	"times", "getrusage", "getitimer", "setitimer",
	// Files (the guest's /work and mounts, snapshots, the cache).
	"openat", "openat2", "open", "getdents64", "getdents", "getcwd", "chdir", "fchdir",
	"faccessat2", "faccessat", "access", "readlink", "readlinkat", "stat", "lstat",
	"ftruncate", "truncate", "fallocate", "fsync", "fdatasync", "flock",
	"mkdirat", "unlinkat", "renameat", "renameat2", "linkat", "symlinkat", "utimensat",
	"fchmod", "fchmodat", "mkdir", "rmdir", "unlink", "rename", "link", "symlink", "chmod",
	// Process bookkeeping + orderly exit.
	"prctl", "arch_prctl", "exit", "exit_group", "uname", "sysinfo",
	"setpriority", "getpriority", "prlimit64", "getrlimit",
}

// workerSeccompKill are escape and host-takeover primitives: no worker has
// a reason to call one, so a call is an attack and ends the worker. The
// rest of what is not allowed fails with EPERM, which the Go runtime and
// the C library handle (Docker's default profile does the same).
var workerSeccompKill = []string{
	"ptrace", "process_vm_readv", "process_vm_writev",
	"mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
	"init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load",
	"open_by_handle_at", "name_to_handle_at", "perf_event_open", "bpf", "userfaultfd",
	"keyctl", "add_key", "request_key",
	"reboot", "swapon", "swapoff", "sethostname", "setdomainname",
	"iopl", "ioperm", "quotactl", "acct", "syslog",
	"fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "mount_setattr",
	"execve", "execveat", "seccomp",
	"setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid", "setgroups", "setfsuid", "setfsgid", "capset",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
	"pidfd_getfd", "mknod", "mknodat",
}

// cloneNamespaceFlags are CLONE_NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER,
// NEWPID and NEWNET (the same on x86-64 and arm64). clone's flags are its
// first argument on both.
const cloneNamespaceFlags = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000

// Errnos the filter answers with.
const (
	errnoEPERM        = 1
	errnoENOSYS       = 38
	errnoEAFNOSUPPORT = 97
)

// Linux address families and the netlink protocol the socket rule names
// (the same on every Linux architecture; x/sys/unix would give the build
// platform's values).
const (
	linuxAFInet       = 2
	linuxAFInet6      = 10
	linuxAFNetlink    = 16
	linuxNetlinkRoute = 0
)

// workerSocketFamilies are the sockets a worker may make once it has
// dropped: IPv4 and IPv6 for the guests' mediated connections, DNS and the
// audit ingest, and a route netlink socket, which Go's net package opens to
// list the node's own addresses (the egress node guard refuses dials to
// them). Every other family (AF_UNIX, AF_NETLINK for any other protocol,
// AF_PACKET, AF_ALG, AF_VSOCK...) fails with EAFNOSUPPORT: a worker binds
// its own Unix socket before it drops and makes none after, and the rest
// are kernel code no worker needs. With AF_UNIX gone a worker cannot reach
// the abstract Unix sockets of the node's network namespace either.
var workerSocketFamilies = [][]hostproc.SeccompArgEq{
	{{Arg: 0, Value: linuxAFInet}},
	{{Arg: 0, Value: linuxAFInet6}},
	{{Arg: 0, Value: linuxAFNetlink}, {Arg: 2, Value: linuxNetlinkRoute}},
}

// workerSeccompPolicy is the worker's filter. clone3 takes its flags in
// memory the filter cannot read, so it answers ENOSYS and the C library
// falls back to clone, whose flags it can.
func workerSeccompPolicy() hostproc.SeccompPolicy {
	actions := make(map[string]uint32, len(workerSeccompKill)+1)
	for _, name := range workerSeccompKill {
		actions[name] = hostproc.SeccompRetKillProcess
	}
	actions["clone3"] = hostproc.SeccompRetErrno(errnoENOSYS)
	return hostproc.SeccompPolicy{
		Allow:   append(append([]string(nil), workerSeccompAllow...), "clone"),
		Actions: actions,
		Rules: []hostproc.SeccompArgRule{
			{Syscall: "clone", DenyIfAll: []hostproc.SeccompArgMask{{Arg: 0, Mask: cloneNamespaceFlags}}},
			{Syscall: "socket", AllowIfAny: workerSocketFamilies, Deny: hostproc.SeccompRetErrno(errnoEAFNOSUPPORT)},
		},
		RuleDeny: hostproc.SeccompRetKillProcess,
		Default:  hostproc.SeccompRetErrno(errnoEPERM),
	}
}

// ConfinementFor is the confinement sandboxd applies to its workers: the
// configured uid/gid when the drop is on and sandboxd is root on Linux.
// Anywhere else there is none: a sandboxd that is not root has no root for
// its workers to lose, and could not switch them to another uid.
func ConfinementFor(drop bool, uid, gid int) Confinement {
	if !drop || !confinementSupported || geteuid() != 0 {
		return Confinement{}
	}
	return Confinement{UID: uid, GID: gid}
}

// geteuid is os.Geteuid; tests stand in a root sandboxd.
var geteuid = os.Geteuid
