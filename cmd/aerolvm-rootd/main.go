// Command aerolvm-rootd is the root helper (plans/security-gaps-m1-m4.md
// §3.3, M1). It runs as root beside sandboxd, which runs as a user with no
// rights, and serves one socket: the helper's own calls and, behind the
// gate, containerd's API. On Kubernetes the supervisor starts it in the
// runtime container; on VMs it is its own unit. Neither runs it yet: the
// agent switches to it in task T4.
//
// Under the supervisor it serves the socket the supervisor passed it and
// says when it serves (internal/rootswap: the signed swap, eng review D4);
// on its own it makes the socket itself. `aerolvm-rootd --version` prints
// the version and API level a release signs for it.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/gate"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/rootswap"
	"github.com/aerol-ai/microvm/internal/version"
)

// shutdownGrace is how long calls in flight get to finish on SIGTERM.
const shutdownGrace = 5 * time.Second

// containerdRetry spaces the start-up namespace check while containerd is
// not up yet (the supervisor starts both), and containerdWait bounds each
// try, so a containerd that accepts and never answers cannot hold the
// helper; tests shorten them.
var containerdRetry, containerdWait = time.Second, 5 * time.Second

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(versionLine())
		return
	}
	os.Exit(mainCode(os.Getenv, os.Stderr))
}

// versionLine is what --version prints: the build's version and API level,
// which the release's signing tool checks against the manifest it signs
// (cmd/aerolvm-rootd-sign).
func versionLine() string {
	return fmt.Sprintf("aerolvm-rootd %s (API %d)", version.Version, rootdpb.APIVersion)
}

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
// helper's own environment, here, and from nowhere else; so does the
// socket the supervisor passed, if it passed one.
func run(ctx context.Context, getenv func(string) string, log *slog.Logger) error {
	cfg, err := rootd.ConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	ln, err := rootswap.InheritedListener(getenv)
	if err != nil {
		return err
	}
	ready := func() {
		// A supervisor that stopped listening has given up on this helper
		// and stops it; serving until then does no harm.
		if err := rootswap.NotifyReady(getenv); err != nil {
			log.Warn("root helper: could not tell the supervisor it serves", "error", err)
		}
	}
	return serve(ctx, cfg, rootd.Options{Listener: ln}, ready, log)
}

// serve wires the gate into the helper's server and calls ready just
// before it serves. Of opts, only Peer and Listener are the caller's; the
// rest is set here.
func serve(ctx context.Context, cfg rootd.Config, opts rootd.Options, ready func(), log *slog.Logger) error {
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
	binding := &netnsBinding{}
	g, err := gate.New(gate.Config{
		Policy:   cfg.Policy,
		Upstream: upstream,
		OnRefusal: func(ctx context.Context, r gate.Refusal) {
			refused(ctx, rootd.Refusal(r))
		},
		NetnsBinding: binding,
	})
	if err != nil {
		return err
	}
	// The socket comes first so a bad path or platform fails at once, not
	// after containerd is up. Until Serve, an agent's handshake waits and
	// times out (503), which is true: there is no containerd yet.
	opts.Containerd, opts.ServerOptions, opts.OnRefusal = g.Handle, g.ServerOptions(), refused
	if opts.Containers == nil {
		opts.Containers = containerdContainers{c: containersapi.NewContainersClient(upstream), ns: cfg.Policy.Namespace}
	}
	if opts.Snapshots == nil {
		// The container's parts that read its snapshot (image_user,
		// disk_quota) read it from containerd here, in the helper's own
		// namespace and under its own snapshotter.
		opts.Snapshots = rootd.ContainerdSnapshots(upstream, cfg.Policy.Namespace, cfg.Policy.Snapshotter)
	}
	srv, err := rootd.New(cfg, opts, log)
	if err != nil {
		return err
	}
	binding.srv.Store(srv)
	stop := func() {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		srv.Shutdown(sctx)
	}
	if err := verifyNamespace(ctx, g, log); err != nil || ctx.Err() != nil {
		stop()
		return err // a stop while containerd was still starting is no error
	}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		stop()
		close(stopped)
	}()
	log.Info("root helper serving", "version", version.Version, "socket", cfg.Socket, "inherited", opts.Listener != nil,
		"containerd", cfg.ContainerdSocket, "namespace", cfg.Policy.Namespace)
	if ready != nil {
		ready()
	}
	err = srv.Serve()
	if ctx.Err() != nil {
		// Serve returns as soon as the stop begins. Return only once it
		// has ended, so the socket is gone and no call is running when
		// the process exits.
		<-stopped
	}
	return err
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

// containerdContainers lists containerd's containers in the helper's
// namespace, for the sweep of gone containers' files (rootd sweep.go). It
// streams the list: a node's specs together can pass a message's size.
type containerdContainers struct {
	c  containersapi.ContainersClient
	ns string
}

func (l containerdContainers) ContainerIDs(ctx context.Context) (map[string]bool, error) {
	stream, err := l.c.ListStream(namespaces.WithNamespace(ctx, l.ns), &containersapi.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return ids, nil
		}
		if err != nil {
			return nil, err
		}
		ids[m.GetContainer().GetID()] = true
	}
}

// netnsBinding is the gate's namespace check, which the server answers
// (rootd.Server.NetnsBound). The server is built around the gate's
// handler, so the gate is made first and pointed at the server once it
// exists; no call reaches the gate before Serve.
type netnsBinding struct{ srv atomic.Pointer[rootd.Server] }

func (b *netnsBinding) Bound(ctx context.Context, name, containerID string) (bool, error) {
	s := b.srv.Load()
	if s == nil {
		return false, errors.New("the root helper is still starting")
	}
	return s.NetnsBound(ctx, name, containerID)
}
