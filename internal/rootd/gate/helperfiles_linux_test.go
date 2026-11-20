//go:build linux

package gate

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// helperFiles is a root helper on its real socket, and what its calls made
// for testID: host files, FIFOs, the runsc config and the ready socket's
// name. The helper runs as this test's user, which the gate's checks trust
// in place of root.
type helperFiles struct {
	cfg    rootd.Config
	hosts  *rootdpb.EnsureHostFilesResponse
	fifos  *rootdpb.EnsureTaskFIFOsResponse
	runsc  string
	ready  string
	policy rootpolicy.Policy
}

func makeHelperFiles(t *testing.T) helperFiles {
	t.Helper()
	dir, err := os.MkdirTemp("", "gh") // short enough for sun_path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := testPolicy()
	p.BindFiles = nil // no toolbox on this machine to walk
	cfg := helperConfig(rootd.Config{Socket: filepath.Join(dir, "sock", "root.sock"), SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Policy: p}, dir)
	srv, err := rootd.New(cfg, rootd.Options{
		Containerd: func(any, grpc.ServerStream) error { return nil },
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
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
	agent := rootclient.New(rootclient.Config{Socket: cfg.Socket, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = agent.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := helperFiles{cfg: cfg, policy: cfg.Policy}
	if h.hosts, err = agent.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: testID, Hostname: testID,
		Hosts: []*rootdpb.HostEntry{{Address: "127.0.0.1", Names: []string{"localhost"}}}, Nameservers: []string{"10.0.0.2"}}); err != nil {
		t.Fatal(err)
	}
	if h.fifos, err = agent.EnsureTaskFIFOs(ctx, testID); err != nil {
		t.Fatal(err)
	}
	if h.runsc, err = agent.EnsureRunscConfig(ctx, rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.Files.AgentReady, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(cfg.Files.AgentReady, testID+".ab.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if h.ready, err = agent.EnsureReadySocket(ctx, testID, "ab"); err != nil {
		t.Fatal(err)
	}
	return h
}

// container is a gVisor container whose spec binds the given host files
// and ready socket and whose shim config is runsc.
func (h helperFiles) container(t *testing.T, resolv, hosts, ready, runsc string) *containersapi.Container {
	t.Helper()
	s := goodSpec(t)
	s.Annotations = map[string]string{rootpolicy.CRIContainerTypeAnnotation: rootpolicy.CRIContainerTypeSandbox}
	s.Mounts = []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Type: "bind", Source: resolv, Destination: "/etc/resolv.conf", Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: hosts, Destination: "/etc/hosts", Options: []string{"rbind", "ro"}},
		{Type: "bind", Source: ready, Destination: "/run/aerol/ready.sock", Options: []string{"rbind"}},
	}
	c := goodContainer(t)
	c.Spec = specAny(t, s)
	c.Runtime = &containersapi.Container_Runtime{
		Name:    rootpolicy.RuntimeRunsc,
		Options: protoAny(t, "runtimeoptions.v1.Options", &runtimeoptions.Options{TypeUrl: rootpolicy.RunscOptionsTypeURL, ConfigPath: runsc}),
	}
	return c
}

// gateRig is the gate with the helper's own policy and the real on-disk
// checks, for this test's user in place of root.
func (h helperFiles) gateRig(t *testing.T, p rootpolicy.Policy) *rig {
	c := hostPaths{owner: uint32(os.Getuid())}
	return newRig(t, p, func(cfg *Config) { cfg.Binds, cfg.Reads, cfg.Stdio = c, c, c })
}

// TestGateAcceptsTheHelpersFiles: a container and task built from exactly
// what the helper's calls answered pass the gate, its on-disk checks
// included: binds of the host files and the ready socket's name, the
// runsc config, and the stdio FIFOs.
func TestGateAcceptsTheHelpersFiles(t *testing.T) {
	h := makeHelperFiles(t)
	r := h.gateRig(t, h.policy)
	c := h.container(t, h.hosts.GetResolvConfPath(), h.hosts.GetHostsPath(), h.ready, h.runsc)
	if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c}); err != nil {
		t.Fatalf("the helper's own files refused: %v", err)
	}
	r.storedContainer(c)
	if _, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(),
		Stdout: h.fifos.GetStdoutPath(), Stderr: h.fifos.GetStderrPath()}); err != nil {
		t.Fatalf("the helper's own FIFOs refused: %v", err)
	}
}

// TestGateRefusesAgentPlantedFiles: the same names, made by the agent in
// a folder of its own (the containerd driver's run dir, where it writes
// them today), are refused, each by the rule for what root would open.
// The agent can swap anything in its own folder for a link after the
// check, so a name there is never trusted.
func TestGateRefusesAgentPlantedFiles(t *testing.T) {
	h := makeHelperFiles(t)
	agentDir := t.TempDir() // the agent's own run dir
	plant := func(rel string, body string) string {
		p := filepath.Join(agentDir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	resolv := plant("hosts/"+testID+"/resolv.conf", "nameserver 10.0.0.2\n")
	hosts := plant("hosts/"+testID+"/hosts", "127.0.0.1 localhost\n")
	runsc := plant("runsc/config.toml", "[runsc_config]\n  host-uds = \"open\"\n")
	agentReady := filepath.Join(h.cfg.Files.AgentReady, testID+".ab.sock") // the agent's own socket
	fifo := filepath.Join(agentDir, "fifo", testID+"-stdout")
	if err := os.MkdirAll(filepath.Dir(fifo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mkfifo(fifo); err != nil {
		t.Fatal(err)
	}

	good := func() (string, string, string, string) {
		return h.hosts.GetResolvConfPath(), h.hosts.GetHostsPath(), h.ready, h.runsc
	}
	for _, tc := range []struct {
		name   string
		mutate func(resolv, hosts, ready, runsc *string)
		rule   rootpolicy.Rule
	}{
		{"the agent's resolv.conf", func(r, _, _, _ *string) { *r = resolv }, rootpolicy.RuleMount},
		{"the agent's hosts file", func(_, ho, _, _ *string) { *ho = hosts }, rootpolicy.RuleMount},
		{"the agent's own ready socket", func(_, _, re, _ *string) { *re = agentReady }, rootpolicy.RuleMount},
		{"the agent's runsc config", func(_, _, _, ru *string) { *ru = runsc }, rootpolicy.RuleRuntimeOptions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := h.gateRig(t, h.policy)
			res, ho, re, ru := good()
			tc.mutate(&res, &ho, &re, &ru)
			_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: h.container(t, res, ho, re, ru)})
			r.wantRefused(err, cCreate, string(tc.rule))
		})
	}
	t.Run("the agent's FIFO", func(t *testing.T) {
		r := h.gateRig(t, h.policy)
		res, ho, re, ru := good()
		r.storedContainer(h.container(t, res, ho, re, ru))
		_, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(), Stdout: fifo})
		r.wantRefused(err, tCreate, string(rootpolicy.RuleTaskIO))
	})

	// Even under the policy T2 shipped, which still named the agent's run
	// dir as a bind root, the on-disk check refuses a file there once the
	// agent can write the folder: it could swap it after the check.
	t.Run("the agent's folder as a bind root", func(t *testing.T) {
		p := h.policy
		p.BindRoots = append(append([]string(nil), p.BindRoots...), filepath.Join(agentDir, "hosts"))
		if err := os.Chmod(filepath.Join(agentDir, "hosts", testID), 0o777); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			// As root the agent's own uid owns it, as on a node.
			if err := os.Lchown(filepath.Join(agentDir, "hosts", testID), agentUID, agentUID); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(agentDir, "hosts", testID), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		r := h.gateRig(t, p)
		_, _, re, ru := good()
		_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: h.container(t, resolv, h.hosts.GetHostsPath(), re, ru)})
		r.wantRefused(err, cCreate, string(rootpolicy.RuleMount))
	})

	// A link the agent leaves in its ready folder never becomes a name
	// the helper hands out: EnsureReadySocket refuses it (rootd tests), so
	// the only names in the helper's ready folder are sockets.
	t.Run("a link where the helper's ready name goes", func(t *testing.T) {
		p := filepath.Join(h.cfg.Files.Ready, testID, "cd.sock")
		if err := os.Symlink("/", p); err != nil {
			t.Fatal(err)
		}
		r := h.gateRig(t, h.policy)
		res, ho, _, ru := good()
		_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: h.container(t, res, ho, p, ru)})
		r.wantRefused(err, cCreate, string(rootpolicy.RuleMount))
	})
}
