package gate

import (
	"context"
	"os"
	"path/filepath"
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
	sock := filepath.Join(dir, "root.sock")
	srv, err := rootd.New(
		rootd.Config{Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Policy: p},
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
	agent := rootclient.New(rootclient.Config{Socket: sock})
	t.Cleanup(func() { _ = agent.Close() })
	r.dial = agent.DialContainerd
	r.conn = bufConn(t, r.dial)
	return r, agent
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
