package gate

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/version"
)

// socketRig is newRig with the agent moved onto the root helper's real
// socket: the agent's client (internal/rootclient) shakes hands with the
// helper's server (internal/rootd), and containerd's API goes through that
// same socket and its peer check to this gate, then to the fake
// containerd. The peer check is egress.UnixPeerCheck for this uid: the
// real SO_PEERCRED one on Linux.
func socketRig(t *testing.T, p rootpolicy.Policy, opts ...func(*Config)) (*rig, *rootclient.Client) {
	t.Helper()
	r := newRig(t, p, opts...)
	dir, err := os.MkdirTemp("", "gs") // short enough for sun_path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// The helper follows no link to its socket (macOS: /var is one).
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "root.sock")
	srv, err := rootd.New(
		helperConfig(rootd.Config{Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Policy: p}, dir),
		rootd.Options{
			Containerd:    r.gate.Handle,
			ServerOptions: r.gate.ServerOptions(),
			Peer:          egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	agent := rootclient.New(rootclient.Config{Socket: sock, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = agent.Close() })
	r.dial = agent.DialContainerd
	r.conn = bufConn(t, r.dial)
	return r, agent
}

// helperConfig lays the helper's own folders out under base, as
// rootd.ConfigFromEnv lays them out under its state and run folders, and
// adds them to the helper's copy of the policy.
func helperConfig(c rootd.Config, base string) rootd.Config {
	c.Files = rootd.FileDirs{
		Hosts:      filepath.Join(base, "state", "hosts"),
		Ready:      filepath.Join(base, "run", "ready"),
		Runsc:      filepath.Join(base, "state", "runsc"),
		AgentReady: filepath.Join(base, "agent", "ready"),
	}
	p := c.Policy
	p.FIFODir = filepath.Join(base, "run", "fifo")
	p.BindRoots = append(slices.Clone(p.BindRoots), c.Files.Hosts, c.Files.Ready)
	p.RunscConfigPaths = []string{filepath.Join(c.Files.Runsc, "config.toml"), filepath.Join(c.Files.Runsc, "restore.toml")}
	c.Policy = p
	return c
}

func newSocketRig(t *testing.T, p rootpolicy.Policy, opts ...func(*Config)) *rig {
	r, _ := socketRig(t, p, opts...)
	return r
}

// TestAgentFlowsThroughTheHelperSocket runs the containerd client
// library's own flows for the agent (TestAgentFlowsThroughTheGate) through
// the helper's socket: one listener, one peer check, the gate behind it.
func TestAgentFlowsThroughTheHelperSocket(t *testing.T) { agentFlows(t, newSocketRig) }

// TestAgentRefusalsThroughTheHelperSocket: hostile calls through the
// socket are refused by the gate, as in memory.
func TestAgentRefusalsThroughTheHelperSocket(t *testing.T) { agentRefusals(t, newSocketRig) }

// TestHelperSocketCarriesBoth: the agent's first containerd call shook
// hands with the helper first, on the same socket.
func TestHelperSocketCarriesBoth(t *testing.T) {
	r, agent := socketRig(t, testPolicy())
	statefulContainerd(r)
	client, ctx := agentClient(t, r)
	if _, err := client.Version(ctx); err != nil {
		t.Fatal(err)
	}
	info, ok := agent.Info()
	if !ok || info.HelperVersion != version.Version || info.API != rootdpb.APIVersion {
		t.Fatalf("handshake %+v, %v", info, ok)
	}
}
