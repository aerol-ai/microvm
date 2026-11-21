package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/service"
)

// TestHostPortForwarderForSplit (M1 PR 5b): in privilege mode split the
// forwarder is the root helper's, once the handshake says the helper
// forwards host ports; a helper that does not (one release back), or none
// at all, gives no forwarder, so the routing engage is refused and the
// node keeps per-sandbox Caddy routes. Single mode is unchanged.
func TestHostPortForwarderForSplit(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), IngressProxyRouting: true}
	sock := filepath.Join(dir, "sock", "root.sock")
	splitHelper(t, sock)
	helper := rootclient.New(rootclient.Config{Socket: sock, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = helper.Close() })
	rec := &levelRecorder{}
	fwd := hostPortForwarderFor(context.Background(), cfg, helper, slog.New(rec))
	if _, ok := fwd.(*rootclient.HostPortForwarder); !ok {
		t.Fatalf("split forwarder = %T, want the helper's", fwd)
	}
	// The flag off and no marker: nothing is built, nothing asked.
	if fwd := hostPortForwarderFor(context.Background(), config.Config{DBPath: cfg.DBPath}, helper, slog.New(rec)); fwd != nil {
		t.Fatalf("flag off: %T", fwd)
	}
	// A helper that is not there: no forwarder, and the operator is told.
	gone := rootclient.New(rootclient.Config{Socket: filepath.Join(dir, "none.sock"), HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = gone.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), hostPortRequireTimeout)
	defer cancel()
	if fwd := hostPortForwarderFor(ctx, cfg, gone, slog.New(rec)); fwd != nil {
		t.Fatalf("no helper: %T", fwd)
	}
	warns := rec.at(slog.LevelWarn)
	if len(warns) != 1 || !strings.Contains(warns[0], "does not forward host ports") {
		t.Fatalf("warnings %q", warns)
	}
}

// rollbackService is the service's rollback as it treats the forwarder:
// the kernel's host-port rules go only through a forwarder it was given,
// and a failure to remove them fails the rollback.
type rollbackService struct {
	fakeRoutingService
	kernelRulesRemoved bool
}

func (s *rollbackService) RollbackIngressProxyRouting(_ context.Context, fwd service.HostPortForwarder) error {
	s.calls = append(s.calls, "rollback")
	if fwd != nil {
		if err := fwd.Reconcile(nil); err != nil {
			return err
		}
		s.kernelRulesRemoved = true
	}
	return nil
}

// TestSplitRollbackStaysDueWithoutHostPorts (PR 5b review): a split node
// whose helper does not forward host ports (one release back, or not
// answering in time) after a boot that engaged routing never records the
// rollback as done while that boot's kernel rules may remain: the marker
// stays, the next boot retries, and routing is never engaged without a
// forwarder.
func TestSplitRollbackStaysDueWithoutHostPorts(t *testing.T) {
	for _, flagOn := range []bool{false, true} {
		dir, err := os.MkdirTemp("/tmp", "rb")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if dir, err = filepath.EvalSymlinks(dir); err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "sock", "root.sock")
		olderHelper(t, sock)
		helper := rootclient.New(rootclient.Config{Socket: sock, HelperUID: uint32(os.Getuid())})
		t.Cleanup(func() { _ = helper.Close() })
		cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), IngressProxyRouting: flagOn}
		marker := ingressRoutingMarkerPath(cfg)
		if err := os.WriteFile(marker, []byte("true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := &levelRecorder{}
		fwd := hostPortForwarderFor(context.Background(), cfg, helper, slog.New(rec))
		svc := &rollbackService{}
		svc.startErr = errors.New("ingress proxy routing needs kernel host-port forwarding (iptables), unavailable on this host")
		b := startIngressRouting(context.Background(), cfg, svc, fwd, slog.New(rec))
		if !readBypassMarker(marker) || svc.kernelRulesRemoved || b.engaged() {
			t.Fatalf("flag=%v: marker %v, rules removed %v, engaged %v; want the rollback still due", flagOn,
				readBypassMarker(marker), svc.kernelRulesRemoved, b.engaged())
		}
		if !slices.Contains(svc.calls, "rollback") {
			t.Fatalf("flag=%v: calls %v, want a rollback attempt", flagOn, svc.calls)
		}
		if flagOn && svc.gotOpts.Forwarder != nil {
			t.Fatalf("routing was offered a forwarder the helper does not serve: %T", svc.gotOpts.Forwarder)
		}
		if errs := rec.at(slog.LevelError); len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), "will retry next boot") {
			t.Fatalf("flag=%v: errors %q", flagOn, errs)
		}
	}
	// With no earlier engage, nothing can be in the kernel: no forwarder.
	dir, err := os.MkdirTemp("/tmp", "rb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock", "root.sock")
	olderHelper(t, sock)
	helper := rootclient.New(rootclient.Config{Socket: sock, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = helper.Close() })
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), IngressProxyRouting: true}
	if fwd := hostPortForwarderFor(context.Background(), cfg, helper, slog.New(&levelRecorder{})); fwd != nil {
		t.Fatalf("no earlier engage: %T", fwd)
	}
}

// olderHelper serves the helper's real server with no network, so its
// handshake lists no HostPort, as a helper one release back.
func olderHelper(t *testing.T, sock string) {
	t.Helper()
	base := filepath.Dir(filepath.Dir(sock))
	cfg := rootd.Config{
		Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()),
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: filepath.Join(base, "moves"), FIFODir: filepath.Join(base, "run", "fifo"),
			Limits: rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
		Files: rootd.FileDirs{Hosts: filepath.Join(base, "state", "hosts"), Ready: filepath.Join(base, "run", "ready"),
			Runsc: filepath.Join(base, "state", "runsc"), AgentReady: filepath.Join(base, "agent", "ready")},
	}
	cfg.Policy.HelperFileRoots = []string{cfg.Files.Hosts, cfg.Files.Ready}
	cfg.Policy.RunscConfigPaths = []string{filepath.Join(cfg.Files.Runsc, "config.toml"), filepath.Join(cfg.Files.Runsc, "restore.toml")}
	srv, err := rootd.New(cfg, rootd.Options{
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
		Containerd: func(_ any, _ grpc.ServerStream) error { return status.Error(codes.Unavailable, "none") },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
}
