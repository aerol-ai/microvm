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
	ln, err := socketListener(cfg.SocketPath)
	if err != nil {
		return err
	}
	log.Info("egress gateway serving", "socket", cfg.SocketPath, "dns_port", cfg.DNSPort, "proxy_port", cfg.ProxyPort)
	return d.Serve(ctx, ln)
}

// socketListener prefers a systemd-activated socket (the unit creates it
// root-owned 0600, which the unprivileged gateway can't do itself, S5) and
// falls back to creating one at path.
func socketListener(path string) (net.Listener, error) {
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
	_ = os.Remove(path)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("egress gateway: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// RunCLI is the `sandboxd egress-gateway` entrypoint.
func RunCLI(ctx context.Context, log *slog.Logger) error {
	cfg, err := FromEnv()
	if err != nil {
		return err
	}
	return Run(ctx, cfg, log)
}
