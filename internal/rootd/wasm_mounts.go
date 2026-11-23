package rootd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// GrantWasmMounts (M1 PR 15; plans/security-gaps-m1-m4.md §3.3 "Mounts"):
// a WASM guest reaches an external mount through its mount point, which
// its worker is handed as an open folder. In privilege mode single
// sandboxd opens it as root and passes it with each message. In split the
// helper keeps the mount points (mounts.go), in a folder only root can
// enter, and its WASM hosts run in its own mount namespace, where those
// mounts are: so the helper lends them, on the agent's word but on its own
// checks.
//
//   - The agent names the sandbox and the host that serves it. No path:
//     the mount points are the ones the helper's own Manager holds for
//     that sandbox, each <mounts folder>/<sandbox>/<index>
//     (rootpolicy.CheckMountBind), and the host's socket is the one the
//     helper serves it on (rootpolicy.WasmHostSocket).
//   - The host must run, and must say it holds that sandbox: a per-sandbox
//     worker names the one sandbox it holds, a resident host whether it
//     holds this one. A host that names another sandbox is a broken
//     agent's request, refused and reported. A host that holds none (its
//     instance not yet made, or gone) is answered FailedPrecondition.
//   - Each mount point is opened with no link followed, through the
//     sandbox's folder of the helper's, for its handle alone (O_PATH): the
//     helper never enters the mount, so no file the tenant's storage
//     serves is ever opened by root, and a stalled mount tool cannot hold
//     the helper. The worker opens what it needs below it, as itself.
//   - The worker is not trusted: its replies are read bounded, with a
//     deadline (pkg/wasm/worker LendFolders).
//
// It runs under the sandbox's mounts lock, so a mount's set-up or removal
// never runs beside a loan of the same sandbox's mounts.

// ReasonWasmMountHost: the host the agent named holds another sandbox.
const ReasonWasmMountHost = "wasm_mount_host"

// wasmLendTimeout bounds a loan's talk with the host when the agent's call
// has no deadline.
const wasmLendTimeout = 5 * time.Second

// wasmMountCalls serves GrantWasmMounts; nil unless the helper serves both
// external mounts and WASM hosts.
type wasmMountCalls struct {
	mounts  *mountCalls
	hosts   *hostCalls
	root    string // the mounts folder
	sockets string // the WASM hosts' socket folder
	log     *slog.Logger
	// openPoint and lend stand in for the kernel and the host in tests.
	openPoint func(root, sandboxID string, index int) (*os.File, error)
	lend      func(ctx context.Context, socket, sandboxID string, paths []string, files []*os.File) error
}

func newWasmMountCalls(cfg Config, opts Options, mc *mountCalls, hc *hostCalls, log *slog.Logger) *wasmMountCalls {
	// The mounts folder is the policy's (ConfigFromEnv sets both).
	root := cfg.Policy.MountsRoot
	if mc == nil || hc == nil || cfg.Hosts.Wasm == nil || root == "" {
		return nil
	}
	if _, ok := hc.launcher[rootpolicy.HostWasmWorker]; !ok {
		return nil
	}
	c := &wasmMountCalls{mounts: mc, hosts: hc, root: filepath.Clean(root), sockets: cfg.Hosts.Wasm.SocketDir,
		log: log, openPoint: openMountPoint, lend: lendToHost}
	if opts.wasmOpenPoint != nil {
		c.openPoint = opts.wasmOpenPoint
	}
	if opts.wasmLend != nil {
		c.lend = opts.wasmLend
	}
	return c
}

func (c *wasmMountCalls) grant(ctx context.Context, req *rootdpb.GrantWasmMountsRequest) (*rootdpb.GrantWasmMountsResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	id := req.GetSandboxId()
	if err := rootpolicy.CheckMountSandboxID(id); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	if k := req.GetKind(); k != rootdpb.HostKind_HOST_KIND_WASM_WORKER && k != rootdpb.HostKind_HOST_KIND_WASM_RESIDENT {
		return nil, &fileError{code: codes.InvalidArgument, reason: ReasonHostKind,
			msg: fmt.Sprintf("root helper: mounts are lent to WASM hosts only, not to %v", k)}
	}
	kind, _, err := c.hosts.check(req.GetKind(), req.GetHostId())
	if err != nil {
		return nil, err
	}
	sock, err := rootpolicy.WasmHostSocket(c.sockets, kind, req.GetHostId())
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	unlock, err := c.mounts.locks.lock(ctx, mountKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	binds := c.mounts.mgr.HostBindsFor(id)
	if len(binds) == 0 {
		return &rootdpb.GrantWasmMountsResponse{}, nil
	}
	if pid, _, err := c.hosts.running(rootpolicy.HostGroup(kind, req.GetHostId())); err != nil {
		return nil, err
	} else if pid == 0 {
		return nil, &fileError{code: codes.NotFound, msg: fmt.Sprintf("root helper: %s host %s does not run", kind, req.GetHostId())}
	}
	paths := make([]string, 0, len(binds))
	files := make([]*os.File, 0, len(binds))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, b := range binds {
		index, err := c.mountIndex(id, b.HostPath)
		if err != nil {
			return nil, err
		}
		f, err := c.openPoint(c.root, id, index)
		if err != nil {
			return nil, fmt.Errorf("root helper: open mount point %s: %w", b.HostPath, err)
		}
		files = append(files, f)
		paths = append(paths, b.HostPath)
	}
	lctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		lctx, cancel = context.WithTimeout(ctx, wasmLendTimeout)
		defer cancel()
	}
	switch err := c.lend(lctx, sock, id, paths, files); {
	case err == nil:
	case errors.Is(err, worker.ErrLendForeign):
		return nil, &fileError{code: codes.PermissionDenied, reason: ReasonWasmMountHost,
			msg: fmt.Sprintf("root helper: %s host %s holds another sandbox than %s", kind, req.GetHostId(), id)}
	case errors.Is(err, worker.ErrLendNotHeld):
		return nil, &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: %s host %s does not hold sandbox %s", kind, req.GetHostId(), id)}
	case lctx.Err() != nil:
		return nil, &fileError{code: codes.DeadlineExceeded, msg: fmt.Sprintf("root helper: %s host %s did not answer in time", kind, req.GetHostId())}
	default:
		return nil, &fileError{code: codes.Unavailable, msg: fmt.Sprintf("root helper: lend to %s host %s: %v", kind, req.GetHostId(), err)}
	}
	c.log.Debug("root helper: lent mounts to a WASM host", "sandbox_id", id, "kind", kind, "host", req.GetHostId(), "mounts", len(files))
	return &rootdpb.GrantWasmMountsResponse{Granted: uint32(len(files))}, nil
}

// mountIndex reads a mount point's index back from the path the helper's
// Manager holds for it: it must be <mounts folder>/<sandbox>/<index>. Any
// other is the helper's own fault, never lent.
func (c *wasmMountCalls) mountIndex(id, hostPath string) (int, error) {
	if err := rootpolicy.CheckMountBind(c.root, id, hostPath); err != nil {
		return 0, fmt.Errorf("root helper: a mount point of sandbox %s outside its folder: %w", id, err)
	}
	index, err := strconv.ParseUint(filepath.Base(hostPath), 10, 16)
	if err != nil || index >= models.MaxMountsPerSandbox {
		return 0, fmt.Errorf("root helper: mount point %s has no index", hostPath)
	}
	return int(index), nil
}

// openMountPoint opens mount index of sandboxID for its handle alone: the
// sandbox's folder from / one name at a time with no link followed, each
// folder root's and closed to others, then the mount point in it, again
// with no link followed. On Linux the handle is O_PATH, so the mount itself
// is never entered.
func openMountPoint(root, sandboxID string, index int) (*os.File, error) {
	// Cleaned, inside the mounts folder and one name below it: the check
	// code scanning counts (go/path-injection), on top of the id's rule.
	root = filepath.Clean(root)
	dir := filepath.Clean(filepath.Join(root, sandboxID))
	if !strings.HasPrefix(dir, root+string(filepath.Separator)) || filepath.Dir(dir) != root {
		return nil, fmt.Errorf("%s is not a sandbox's folder in %s", dir, root)
	}
	owner := uint32(os.Geteuid())
	dfd, err := walkFolder(dir, false, func(at string, st *unix.Stat_t, last bool) error {
		return rootfolder.CheckFolder(at, uint32(st.Mode), st.Uid, owner, !last)
	})
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	name := strconv.Itoa(index)
	fd, err := unix.Openat(dfd, name, rootfolder.FolderFlags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir, name)), nil
}

// lendToHost connects to the host's socket and lends it the folders
// (worker.LendFolders). The socket is in the helper's own folder, which no
// one else can write, so its name is the socket the helper bound.
func lendToHost(ctx context.Context, socket, sandboxID string, paths []string, files []*os.File) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%s is not a Unix socket", socket)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(deadline)
	}
	return worker.LendFolders(uc, sandboxID, paths, files)
}
