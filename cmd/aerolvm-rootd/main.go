// Command aerolvm-rootd is the root helper (plans/security-gaps-m1-m4.md
// §3.3, M1). It runs as root beside sandboxd, which runs as a user with no
// rights, and serves one socket: the helper's own calls and, behind the
// gate, containerd's API. On Kubernetes the supervisor starts it in the
// runtime container; on VMs it is its own unit. Neither runs it yet: the
// agent switches to it in task T4.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/gate"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// shutdownGrace is how long calls in flight get to finish on SIGTERM.
const shutdownGrace = 5 * time.Second

// containerdRetry spaces the start-up namespace check while containerd is
// not up yet (the supervisor starts both), and containerdWait bounds each
// try, so a containerd that accepts and never answers cannot hold the
// helper; tests shorten them.
var containerdRetry, containerdWait = time.Second, 5 * time.Second

func main() { os.Exit(mainCode(os.Getenv, os.Stderr)) }

// mainCode runs the helper until SIGTERM or SIGINT and returns the exit
// code.
func mainCode(getenv func(string) string, stderr io.Writer) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, getenv, log); err != nil {
		log.Error("root helper: cannot run", "error", err)
		return 1
	}
	return 0
}

// run serves until ctx ends. The policy the gate checks comes from the
// helper's own environment, here, and from nowhere else.
func run(ctx context.Context, getenv func(string) string, log *slog.Logger) error {
	cfg, err := rootd.ConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	return serve(ctx, cfg, rootd.Options{}, log)
}

// serve wires the gate into the helper's server. Of opts, only Peer is
// the caller's (tests set it); the rest is set here.
func serve(ctx context.Context, cfg rootd.Config, opts rootd.Options, log *slog.Logger) error {
	// gRPC's reconnect backoff grows to two minutes. containerd restarted
	// by the supervisor is back in seconds, and no sandbox call works
	// until the gate reaches it again, so retry at least every second.
	bc := backoff.DefaultConfig
	bc.BaseDelay, bc.MaxDelay = 100*time.Millisecond, time.Second
	upstream, err := grpc.NewClient("unix://"+cfg.ContainerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: bc, MinConnectTimeout: containerdWait}))
	if err != nil {
		return fmt.Errorf("containerd at %s: %w", cfg.ContainerdSocket, err)
	}
	defer func() { _ = upstream.Close() }()
	// One callback hears the gate's refusals and the peer check's.
	refused := rootd.LogRefusal(log)
	g, err := gate.New(gate.Config{
		Policy:   cfg.Policy,
		Upstream: upstream,
		OnRefusal: func(ctx context.Context, r gate.Refusal) {
			refused(ctx, rootd.Refusal(r))
		},
	})
	if err != nil {
		return err
	}
	// The socket comes first so a bad path or platform fails at once, not
	// after containerd is up. Until Serve, an agent's handshake waits and
	// times out (503), which is true: there is no containerd yet.
	opts.Containerd, opts.ServerOptions, opts.OnRefusal = g.Handle, g.ServerOptions(), refused
	srv, err := rootd.New(cfg, opts, log)
	if err != nil {
		return err
	}
	stop := func() {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		srv.Shutdown(sctx)
	}
	if err := verifyNamespace(ctx, g, log); err != nil || ctx.Err() != nil {
		stop()
		return err // a stop while containerd was still starting is no error
	}
	go func() {
		<-ctx.Done()
		stop()
	}()
	log.Info("root helper serving", "socket", cfg.Socket, "containerd", cfg.ContainerdSocket, "namespace", cfg.Policy.Namespace)
	return srv.Serve()
}

// verifyNamespace refuses to serve over a containerd namespace whose
// default labels change what every create runs (gate.VerifyNamespace). It
// waits for containerd to answer first, since both start together, and
// gives up quietly when ctx ends; a namespace that breaks the rule stops
// the helper.
func verifyNamespace(ctx context.Context, g *gate.Gate, log *slog.Logger) error {
	for waited := false; ; waited = true {
		actx, cancel := context.WithTimeout(ctx, containerdWait)
		err := g.VerifyNamespace(actx)
		cancel()
		if err == nil || rootpolicy.RuleOf(err) != "" {
			return err
		}
		if !waited {
			log.Warn("root helper: waiting for containerd", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(containerdRetry):
		}
	}
}
