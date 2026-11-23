package gatewayd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/dnsfilter"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// Subcommand is how sandboxd is invoked to run the gateway.
const Subcommand = "egress-gateway"

// Run is the production entry: real nftables, conntrack, SO_PEERCRED and a
// socket from systemd activation (or the configured path).
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := hardenProcess(); err != nil {
		return fmt.Errorf("egress gateway: harden process: %w", err)
	}
	if len(cfg.DNSUpstreams) == 0 {
		cfg.DNSUpstreams = dnsfilter.DefaultUpstreams("/etc/resolv.conf")
	}
	// The operator file is watched like sandboxd's (poll and SIGHUP): a
	// reload reaches the running filter and proxy (review finding 7). An
	// invalid file at start still refuses to start; an invalid reload keeps
	// the last good one.
	var d *Daemon
	w := operator.NewWatcher(cfg.OperatorFile, log, func(op *operator.Operator) {
		if d != nil {
			d.SetOperator(op)
		}
	})
	guard, upstream, err := fromOperator(cfg.OperatorFile, w)
	if err != nil {
		return err
	}
	// Tracing is best-effort: a bad collector endpoint must not keep the
	// gateway, and with it hostname-filtered egress, from starting.
	if shutdown, err := observability.StartOTELTraces(ctx, log, cfg.Traces); err != nil {
		log.Warn("egress gateway: trace exporter not started", "error", err)
	} else if shutdown != nil {
		defer func() { _ = shutdown(context.WithoutCancel(ctx)) }()
	}
	be, ct := productionKernel()
	d, err = New(cfg, Deps{
		Backend:     be,
		Conntrack:   ct,
		OriginalDst: proxy.OriginalDst,
		Peer:        egress.UnixPeerCheck(cfg.PeerUIDs, cfg.PeerCgroup),
		Guard:       guard,
		Upstream:    upstream,
	}, log)
	if err != nil {
		return fmt.Errorf("egress gateway: %w", err)
	}
	if op := w.Current(); op != nil {
		d.opMu.Lock()
		d.opHash = op.Hash()
		d.opMu.Unlock()
	}
	go w.Run(ctx, operatorPoll)
	go reloadOnHUP(ctx, w)
	// The deny-floor file (review R4), which RunCLI read at start: its
	// addresses can change while the gateway runs.
	if path := os.Getenv(egresspolicy.FloorFileEnv); path != "" {
		go egresspolicy.WatchFloorFile(ctx, path, operatorPoll, log, func() { d.RefreshFloor(w.Current()) })
	}
	ln, err := socketListener(cfg.SocketPath, cfg.PeerUIDs...)
	if err != nil {
		return err
	}
	log.Info("egress gateway serving", "socket", cfg.SocketPath, "dns_port", cfg.DNSPort, "proxy_port", cfg.ProxyPort)
	return d.Serve(ctx, ln)
}

// socketListener prefers a systemd-activated socket (the unit creates it
// root-owned 0600, which the unprivileged gateway can't do itself, S5) and
// falls back to creating one at path, with socketMode(peers).
func socketListener(path string, peers ...uint32) (net.Listener, error) {
	if pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID")); pid == os.Getpid() {
		if n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS")); n >= 1 {
			f := os.NewFile(3, "aerolvm-egress.socket")
			ln, err := net.FileListener(f)
			_ = f.Close()
			if err != nil {
				return nil, fmt.Errorf("egress gateway: activated socket: %w", err)
			}
			return ln, nil
		}
	}
	if path == "" {
		return nil, errNoSocket
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	mode := socketMode(peers)
	if mode != 0o600 {
		if err := ownFolder(filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	_ = os.Remove(path)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("egress gateway: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// ownFolder checks the folder for a socket open to every user: a real
// folder, not a link, owned by this user or root, that no one else can
// write. The gateway removes, binds and sets the mode of its socket by
// name, and the user it opens the socket for (sandboxd's, in privilege
// mode split) must not be able to put another file at that name in
// between. The chart gives a split worker's gateway a folder of its own
// for this (/run/aerolvm-egress), which the agent mounts read only.
func ownFolder(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("egress gateway: socket folder: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return fmt.Errorf("egress gateway: socket folder %s is not a folder", dir)
	case !ok || (sys.Uid != 0 && sys.Uid != uint32(os.Getuid())):
		return fmt.Errorf("egress gateway: socket folder %s belongs to another user", dir)
	case st.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("egress gateway: other users can write socket folder %s (mode %o); the socket it opens to them needs a folder they cannot write", dir, st.Mode().Perm())
	}
	return nil
}

// socketMode is the mode of a socket the gateway makes itself: 0600, which
// only its own user and root can open, unless the peers it answers
// (SB_EGRESS_PEER_UIDS) include another user. In privilege mode split
// sandboxd is not root (uid 65531 in the worker pod), and the gateway, not
// root either, cannot give the socket to that user. The socket is then open
// to every local user, and the peer check, which answers the listed uids
// alone, keeps the others out, as sandboxd's own executable-lookup socket
// does in split (pkg/daemon startEgressProcid). On a VM systemd makes the
// socket for sandboxd's user, and this path is not taken.
func socketMode(peers []uint32) os.FileMode {
	self := uint32(os.Getuid())
	for _, p := range peers {
		if p != 0 && p != self {
			return 0o666
		}
	}
	return 0o600
}

// RunCLI is the `sandboxd egress-gateway` entrypoint.
func RunCLI(ctx context.Context, log *slog.Logger) error {
	cfg, err := FromEnv()
	if err != nil {
		return err
	}
	// sandboxd's extra deny floor and private ranges (C24), from this
	// process's own environment: the gateway dials for container sandboxes
	// from the pod or host itself, past the host firewall's copy, so it
	// must refuse them too. Before the guard is built from the operator
	// file, whose floor carries them. A list it cannot read stops the
	// gateway rather than run it without a floor entry.
	if err := egresspolicy.LoadRangesFromEnv(); err != nil {
		return fmt.Errorf("egress gateway: %w", err)
	}
	return Run(ctx, cfg, log)
}
