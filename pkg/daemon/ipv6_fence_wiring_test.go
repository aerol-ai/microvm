package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fenceBackendStub struct {
	mu    sync.Mutex
	rules []ipv6fence.Rule
	err   error
}

func (f *fenceBackendStub) Apply(rules []ipv6fence.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rules = append([]ipv6fence.Rule(nil), rules...)
	return nil
}

func (f *fenceBackendStub) Check(rules []ipv6fence.Rule) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rules) == len(rules), f.err
}

func (f *fenceBackendStub) names() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, r := range f.rules {
		if !seen[r.Name] {
			seen[r.Name] = true
			out = append(out, r.Name)
		}
	}
	return strings.Join(out, ",")
}

type bridgeStub struct {
	net docker.SandboxNetwork
	err error
}

func (b bridgeStub) SandboxBridge(context.Context) (docker.SandboxNetwork, error) {
	return b.net, b.err
}

func onLinuxWith(t *testing.T, be ipv6fence.Backend) {
	t.Helper()
	origGOOS, origBE := ipv6FenceGOOS, newIPv6FenceBackend
	ipv6FenceGOOS = "linux"
	newIPv6FenceBackend = func() ipv6fence.Backend { return be }
	t.Cleanup(func() { ipv6FenceGOOS, newIPv6FenceBackend = origGOOS, origBE })
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestWireIPv6FenceInstallsBeforeServing: on a Linux worker the fence is in
// the kernel and the create gate wired when wireIPv6Fence returns, for the
// engine's bridge and every Firecracker TAP.
func TestWireIPv6FenceInstallsBeforeServing(t *testing.T) {
	be := &fenceBackendStub{}
	onLinuxWith(t, be)
	conf := filepath.Join(t.TempDir(), "aerolvm.conflist")
	if err := cni.EnsureBridgeConflist(conf, cni.ConflistOptions{Bridge: "cni0"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{ContainerEngine: models.ContainerEngineContainerd, ContainerdCNIConfPath: conf, ContainerdNativeNetnsPoolEnabled: true, EnableFirecracker: true, EnableNetworkRules: true}
	svc := service.New(cfg, quietLogger(), nil, nil, nil, nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup := wireIPv6Fence(ctx, cfg, svc, nil, quietLogger())
	if sup == nil {
		t.Fatal("a Linux worker must get the fence")
	}
	if got := be.names(); got != "cni0,fctap*" {
		t.Fatalf("fenced = %q, want the conflist's bridge and every TAP", got)
	}
	for _, rt := range []string{models.ContainerEngineContainerd, models.RuntimeFirecracker} {
		if err := sup.Ready(rt); err != nil {
			t.Fatalf("Ready(%s) = %v", rt, err)
		}
	}
}

func TestWireIPv6FenceInstallFailureRefusesCreates(t *testing.T) {
	be := &fenceBackendStub{err: errors.New("nf_tables: operation not supported")}
	onLinuxWith(t, be)
	cfg := config.Config{ContainerEngine: models.ContainerEngineDocker, EnableNetworkRules: true}
	svc := service.New(cfg, quietLogger(), nil, nil, nil, nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup := wireIPv6Fence(ctx, cfg, svc, bridgeStub{net: docker.SandboxNetwork{Name: "docker0"}}, quietLogger())
	if err := sup.Ready(models.ContainerEngineDocker); err == nil {
		t.Fatal("a fence that cannot be installed must refuse docker creates")
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"}); !errors.Is(err, service.ErrIPv6FenceNotReady) {
		t.Fatalf("create = %v, want ErrIPv6FenceNotReady", err)
	}
}

func TestWireIPv6FenceSkips(t *testing.T) {
	be := &fenceBackendStub{}
	onLinuxWith(t, be)
	svc := service.New(config.Config{}, quietLogger(), nil, nil, nil, nil, nil, nil, nil)
	if wireIPv6Fence(context.Background(), config.Config{NodeRole: config.NodeRoleServer, EnableNetworkRules: true}, svc, nil, quietLogger()) != nil {
		t.Fatal("a node that owns no sandboxes needs no fence")
	}
	if wireIPv6Fence(context.Background(), config.Config{EnableNetworkRules: true}, nil, nil, quietLogger()) != nil {
		t.Fatal("no service, no gate")
	}
	// A docker-engine worker whose docker client is absent, no Firecracker:
	// nothing to fence.
	if wireIPv6Fence(context.Background(), config.Config{ContainerEngine: models.ContainerEngineDocker, EnableNetworkRules: true}, svc, nil, quietLogger()) != nil {
		t.Fatal("no source, no supervisor")
	}
	// Host firewall off (local mode): no fence, and creates are not
	// refused for the lack of one.
	if wireIPv6Fence(context.Background(), config.Config{EnableFirecracker: true}, svc, nil, quietLogger()) != nil {
		t.Fatal("SB_ENABLE_NETWORK_RULES=false must not get a fence")
	}
	if be.names() != "" {
		t.Fatalf("nothing may be installed with the host firewall off: %q", be.names())
	}
	// Enterprise mode gets it whatever SB_ENABLE_NETWORK_RULES says.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if wireIPv6Fence(ctx, config.Config{EnableFirecracker: true, EnterpriseMode: true}, svc, nil, quietLogger()) == nil {
		t.Fatal("enterprise mode must get the fence")
	}
	ipv6FenceGOOS = "darwin"
	if wireIPv6Fence(context.Background(), config.Config{EnableFirecracker: true, EnableNetworkRules: true}, svc, nil, quietLogger()) != nil {
		t.Fatal("no fence off Linux")
	}
}

func TestIPv6FenceSources(t *testing.T) {
	src := ipv6FenceSources(config.Config{ContainerEngine: models.ContainerEngineDocker, EnableFirecracker: true}, bridgeStub{net: docker.SandboxNetwork{Name: "br-0123456789ab"}})
	if len(src) != 2 || src[0].Runtime != models.ContainerEngineDocker || src[1].Runtime != models.RuntimeFirecracker {
		t.Fatalf("sources = %+v", src)
	}
	spec, err := src[0].Spec(context.Background())
	if err != nil || len(spec.Bridges) != 1 || spec.Bridges[0] != "br-0123456789ab" {
		t.Fatalf("docker spec = %+v, %v", spec, err)
	}
	spec, err = src[1].Spec(context.Background())
	if err != nil || len(spec.Links) != 1 || spec.Links[0] != "fctap*" {
		t.Fatalf("firecracker spec = %+v, %v", spec, err)
	}
}

func TestDockerFenceSpec(t *testing.T) {
	// A network without an IPv4 gateway still names a bridge to fence.
	spec, err := dockerFenceSpec(bridgeStub{net: docker.SandboxNetwork{Name: "docker0"}, err: errors.New("docker network bridge has no IPv4 gateway")})(context.Background())
	if err != nil || spec.Bridges[0] != "docker0" {
		t.Fatalf("spec = %+v, %v", spec, err)
	}
	if _, err := dockerFenceSpec(bridgeStub{err: errors.New("connection refused")})(context.Background()); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("unreachable dockerd = %v", err)
	}
	if _, err := dockerFenceSpec(bridgeStub{})(context.Background()); err == nil {
		t.Fatal("a network with no bridge name must fail")
	}
}

func TestContainerdFenceSpec(t *testing.T) {
	dir := t.TempDir()
	stock := filepath.Join(dir, "10-containerd-net.conflist")
	if err := os.WriteFile(stock, []byte(`{"cniVersion":"1.0.0","name":"containerd-net","plugins":[{"type":"bridge","bridge":"cni0"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := containerdFenceSpec(config.Config{ContainerdCNIConfPath: stock, ContainerdNativeNetnsPoolEnabled: true})(context.Background())
	if err != nil || spec.Bridges[0] != "cni0" {
		t.Fatalf("stock conflist = %+v, %v", spec, err)
	}
	missing := filepath.Join(dir, "absent.conflist")
	if _, err := containerdFenceSpec(config.Config{ContainerdCNIConfPath: missing, ContainerdNativeNetnsPoolEnabled: true})(context.Background()); err == nil {
		t.Fatal("the pool's conflist must be readable: its bridge is what sandboxes sit on")
	}
	// Without the pool a containerd sandbox has no network; the generated
	// bridge name stands in.
	spec, err = containerdFenceSpec(config.Config{ContainerdCNIConfPath: missing})(context.Background())
	if err != nil || spec.Bridges[0] != cni.DefaultBridgeName {
		t.Fatalf("no pool = %+v, %v", spec, err)
	}
}
