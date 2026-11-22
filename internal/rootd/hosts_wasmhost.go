package rootd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// wasmHosts are the WASM workers and resident hosts (kinds wasm_worker and
// wasm_resident), started as sandboxd starts them in privilege mode single
// (pkg/wasm/worker Confine), from the helper's own settings:
//
//   - the binary is the helper's own (aerolvm-rootd --wasm-worker), the
//     signed helper, never a path the agent names. It starts as root,
//     opens what it is handed, then drops to the worker user with no
//     groups, no_new_privs, not dumpable and its seccomp filter, as Q1
//     made every worker do, before it reads a message;
//   - in a PID namespace and a cgroup of its own, outside the helper's;
//   - serving a socket the helper binds in a folder of its own for the
//     agent's group alone (rootfolder.Listen): no worker can reach another
//     worker's socket, and the agent dials it by the name both work out
//     (rootpolicy.WasmHostSocket);
//   - with its compile cache handed as an open folder, found under the
//     agent's cache root with no link followed and checked to be the
//     agent's;
//   - sharing what its guest writes with its group (worker.ShareGroupEnv),
//     which the agent is in: the agent serves the sandbox's files and
//     removes its /work, and is not root;
//   - behind the worker user's fence (workerfence), which the helper keeps
//     in place, and without which no worker starts.
type wasmHosts struct {
	cfg   *WasmHostsConfig
	kind  rootpolicy.HostKind
	flag  string
	fence *wasmFence
	log   string

	// ready holds each started command's ready pipe until started reads
	// it.
	ready sync.Map // *exec.Cmd -> *os.File
	// listen and openCache stand in for the kernel in tests.
	listen    func(path string, gid int) (*os.File, error)
	openCache func(dir string, agent uint32) (*os.File, error)
}

// WasmHostsConfig is the WASM hosts' settings.
type WasmHostsConfig struct {
	// Binary runs every host: the helper's own.
	Binary string
	// UID and GID are the worker user (SB_WASM_WORKER_UID/GID).
	UID, GID int
	// SocketDir is a folder of the helper's for the hosts' sockets
	// (SB_ROOTD_WASM_SOCKET_DIR); SocketGID, the agent's group, may
	// connect to them.
	SocketDir string
	SocketGID int
	// CacheRoot is the agent's compile cache root, as sandboxd works it
	// out (SB_WASM_COMPILE_CACHE_DIR, or SB_WASM_CACHE_DIR or
	// SB_WASM_MODULES_DIR/cache, then wazero-compile); "" for none.
	CacheRoot string
	AgentUID  uint32
	// Env are the hosts' fixed settings, NAME=value, from the helper's own
	// environment: the operator's files, which the host reads as root
	// before it drops, and the process's locale.
	Env []string
	// ReadyWait bounds how long a started host has to say it serves.
	ReadyWait time.Duration
	// Fence keeps the worker user's fence in place
	// (SB_ENABLE_NETWORK_RULES or SB_ENTERPRISE_MODE). OperatorFile names
	// the upstream proxy the fence lets through; NodePorts the ports
	// guests may reach on the node.
	Fence        bool
	OperatorFile string
	NodePorts    []uint16
}

// wasmAgentEnv are the worker settings the agent may pass, by name: what
// sandboxd computes at run time (pkg/wasm/worker workerEnvironment). None
// is a path; each is parsed by the worker before it drops, as in single
// mode, and loosens nothing the fence holds.
var wasmAgentEnv = map[string]bool{
	"SB_AUDIT_INGEST_PORT": true, "SB_EGRESS_ATTRIBUTION_ENABLED": true, "SB_NODE_ID": true,
	worker.ListenFallbackEnv:      true,
	egresspolicy.NodePortsEnv:     true,
	egresspolicy.BlockPrivateEnv:  true,
	egresspolicy.DenyFloorEnv:     true,
	egresspolicy.PrivateRangesEnv: true,
}

// maxWasmEnvValue bounds one setting the agent passes.
const maxWasmEnvValue = 4096

func newWasmHosts(cfg *WasmHostsConfig, kind rootpolicy.HostKind, fence *wasmFence, logPath string) *wasmHosts {
	flag := worker.WorkerFlag
	if kind == rootpolicy.HostWasmResident {
		flag = worker.ResidentHostFlag
	}
	return &wasmHosts{cfg: cfg, kind: kind, flag: flag, fence: fence, log: logPath, listen: listenHostSocket, openCache: openAgentFolder}
}

// checkWasmEnv refuses a setting not on the list, a repeat, and a value
// that is too long or holds a NUL.
func checkWasmEnv(env []string) error {
	seen := map[string]bool{}
	for _, e := range env {
		name, value, ok := strings.Cut(e, "=")
		switch {
		case !ok || !wasmAgentEnv[name]:
			return badRequest("root helper: WASM host setting %q is not one the agent may pass", name)
		case seen[name]:
			return badRequest("root helper: WASM host setting %s is passed twice", name)
		case len(value) > maxWasmEnvValue || strings.ContainsRune(value, 0):
			return badRequest("root helper: WASM host setting %s is too long or holds a NUL", name)
		}
		seen[name] = true
	}
	return nil
}

func (w *wasmHosts) prepare(string, bool) (*rootdpb.PrepareHostResponse, error) {
	return &rootdpb.PrepareHostResponse{}, nil
}

func (w *wasmHosts) socket(id string) string {
	p, _ := rootpolicy.WasmHostSocket(w.cfg.SocketDir, w.kind, id)
	return p
}

func (w *wasmHosts) limits(l rootpolicy.HostLimits) (rootpolicy.HostLimits, bool) { return l, false }

func (w *wasmHosts) command(_ context.Context, id string, req *rootdpb.SpawnHostRequest) (*exec.Cmd, func(), error) {
	spec := req.GetWasm()
	if err := rootpolicy.CheckWasmCache(spec.GetCache()); err != nil {
		return nil, nil, refusedRule(codes.InvalidArgument, err)
	}
	if err := checkWasmEnv(spec.GetEnv()); err != nil {
		return nil, nil, err
	}
	sock, err := rootpolicy.WasmHostSocket(w.cfg.SocketDir, w.kind, id)
	if err != nil {
		return nil, nil, refusedRule(codes.InvalidArgument, err)
	}
	if err := w.fence.ensure(spec.GetEnv()); err != nil {
		return nil, nil, &fileError{code: codes.Unavailable, msg: "root helper: the WASM worker fence is not in place, so no worker starts: " + err.Error()}
	}
	var files []*os.File
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	ln, err := w.listen(sock, w.cfg.SocketGID)
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: WASM host socket %s: %w", sock, err)
	}
	files = append(files, ln)
	r, pw, err := os.Pipe()
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	files = append(files, pw)
	env := append(slices.Clone(w.cfg.Env), spec.GetEnv()...)
	env = append(env, worker.ListenFDEnv+"=3", worker.ReadyFDEnv+"=4", worker.ShareGroupEnv+"=1",
		fmt.Sprintf("%s=%d:%d", worker.ConfineEnv, w.cfg.UID, w.cfg.GID))
	if c := spec.GetCache(); c != "" && w.cfg.CacheRoot != "" {
		if dir, err := w.openCache(filepath.Join(w.cfg.CacheRoot, wasmCachePath(c)), w.cfg.AgentUID); err == nil {
			files = append(files, dir)
			env = append(env, worker.CacheDirEnv+"=/proc/self/fd/5")
		} else {
			slog.Warn("root helper: WASM host compiles without its cache", "kind", w.kind, "id", id, "cache", c, "error", err)
		}
	}
	out, err := hostLog(w.log)
	if err != nil {
		_ = r.Close()
		closeAll()
		return nil, nil, fmt.Errorf("root helper: hosts' log %s: %w", w.log, err)
	}
	files = append(files, out)
	cmd := exec.Command(w.cfg.Binary, w.flag, sock)
	cmd.Env = env
	cmd.ExtraFiles = files[:len(files)-1]
	cmd.Stdout, cmd.Stderr = out, out
	setOwnPIDNamespace(cmd)
	w.ready.Store(cmd, r)
	return cmd, closeAll, nil
}

// wasmCachePath is a cache name's folder under the cache root, as the WASM
// driver lays them out (compileCacheNamed, SlotCompileCache).
func wasmCachePath(name string) string {
	if strings.HasPrefix(name, "slots/") {
		return name
	}
	return filepath.Join("owners", name)
}

// started waits for the host to say it serves, on its ready pipe: once it
// has dropped, installed its filter and listens.
func (w *wasmHosts) started(ctx context.Context, cmd *exec.Cmd) error {
	v, ok := w.ready.LoadAndDelete(cmd)
	if !ok {
		return nil
	}
	r := v.(*os.File)
	defer r.Close()
	wait := w.cfg.ReadyWait
	if d, ok := ctx.Deadline(); ok && time.Until(d) < wait {
		wait = time.Until(d)
	}
	_ = r.SetReadDeadline(time.Now().Add(wait))
	var b [1]byte
	if n, err := r.Read(b[:]); n == 1 {
		return nil
	} else if errors.Is(err, io.EOF) {
		return fmt.Errorf("root helper: WASM host exited before it served (its output is in %s)", w.log)
	} else {
		return fmt.Errorf("root helper: WASM host did not serve within %s: %w", wait, err)
	}
}

// teardown removes the host's socket, through the helper's own folder.
func (w *wasmHosts) teardown(id string) error {
	sock, err := rootpolicy.WasmHostSocket(w.cfg.SocketDir, w.kind, id)
	if err != nil {
		return err
	}
	dfd, err := openFolder(filepath.Dir(sock))
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	name := filepath.Base(sock)
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("root helper: %s is not a socket", sock)
	}
	return unix.Unlinkat(dfd, name, 0)
}

// present lists the hosts whose sockets are still in the folder.
func (w *wasmHosts) present() ([]string, error) {
	entries, err := os.ReadDir(w.cfg.SocketDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := "w-"
	if w.kind == rootpolicy.HostWasmResident {
		prefix = "r-"
	}
	var out []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(strings.TrimPrefix(e.Name(), prefix), ".sock"); ok && strings.HasPrefix(e.Name(), prefix) &&
			rootpolicy.CheckHostID(w.kind, id) == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// listenHostSocket binds a host's socket in the helper's folder, 0660 to
// gid (rootfolder.Listen), and answers it as a file to hand over.
func listenHostSocket(path string, gid int) (*os.File, error) {
	ln, _, err := rootfolder.Listen(path, gid)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.File()
}

// openAgentFolder opens a folder of the agent's (a compile cache) with no
// link followed on the way, and refuses one that is not the agent's: the
// host gets it open, as root opened it.
func openAgentFolder(dir string, agent uint32) (*os.File, error) {
	fd, err := rootfolder.WalkFolder(dir, false, func(at string, st *unix.Stat_t, last bool) error {
		if last && st.Uid != agent {
			return fmt.Errorf("%s belongs to uid %d, not the agent's", at, st.Uid)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), dir), nil
}

// wasmFence keeps the worker user's fence in place for the WASM hosts
// (internal/network/workerfence), as sandboxd does in single mode
// (pkg/daemon wireWasmWorkerFence): built from the helper's own settings
// and the audit port the agent last passed.
type wasmFence struct {
	cfg       *WasmHostsConfig
	fence     *workerfence.Fence
	auditPort atomic.Uint32
	once      sync.Once
	stop      context.CancelFunc
	// read stand in for the node's files in tests.
	readResolv func() ([]byte, error)
}

// wasmFenceTick is how often the helper checks the fence is still there.
var wasmFenceTick = 10 * time.Second

func newWasmFence(cfg *WasmHostsConfig, be workerfence.Backend, log *slog.Logger) *wasmFence {
	// The node's extra deny floor (SB_EGRESS_DENY_FLOOR_CIDRS), from the
	// helper's own environment, as sandboxd loads it from its own.
	if err := egresspolicy.LoadRangesFromEnv(); err != nil {
		log.Warn("root helper: the node's extra deny floor did not load; the WASM worker fence fails closed", "error", err)
	}
	f := &wasmFence{cfg: cfg, readResolv: func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") }}
	if cfg.Fence {
		f.fence = workerfence.New(be, f.spec, log)
	}
	return f
}

func (f *wasmFence) spec() (workerfence.Spec, error) {
	in := workerfence.NodeInputs{UID: f.cfg.UID, NodePorts: f.cfg.NodePorts, AuditPort: uint16(f.auditPort.Load()),
		Local: workerfence.LocalAddrs(net.InterfaceAddrs)}
	if raw, err := f.readResolv(); err == nil {
		in.ResolvConf = raw
	}
	var op *operator.Operator
	if f.cfg.OperatorFile != "" {
		if loaded, err := operator.Load(f.cfg.OperatorFile); err == nil {
			op = loaded
			if up := op.Upstream(); up != nil {
				in.Upstream = up.URL
			}
		}
	}
	in.Floor = append(op.DenyFloor(), egresspolicy.ExtraDenyFloor()...)
	if path := os.Getenv(egresspolicy.FloorFileEnv); path != "" {
		floor, err := egresspolicy.ReadFloorFile(path)
		if err != nil {
			// An unreadable floor fails closed: no fence, no worker.
			return workerfence.Spec{}, err
		}
		in.Floor = append(in.Floor, floor...)
	}
	return workerfence.NodeSpec(in), nil
}

// ensure takes the agent's audit port from a spawn's settings, makes sure
// the fence holds, and starts its repair loop once.
func (f *wasmFence) ensure(env []string) error {
	if f == nil || f.fence == nil {
		return nil
	}
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "SB_AUDIT_INGEST_PORT="); ok {
			if p, err := strconv.ParseUint(v, 10, 16); err == nil && uint32(p) != f.auditPort.Swap(uint32(p)) {
				_ = f.fence.Sync()
			}
		}
	}
	if err := f.fence.Ensure(); err != nil {
		return err
	}
	f.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		f.stop = cancel
		go f.fence.Run(ctx, wasmFenceTick)
	})
	return nil
}

func (f *wasmFence) close() {
	if f != nil && f.stop != nil {
		f.stop()
	}
}
