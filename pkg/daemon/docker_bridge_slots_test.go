package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func dockerNet(driver, subnet, ipRange string) docker.SandboxNetwork {
	sn := docker.SandboxNetwork{Name: "docker0", Driver: driver}
	if subnet != "" {
		sn.Subnet = netip.MustParsePrefix(subnet)
	}
	if ipRange != "" {
		sn.IPRange = netip.MustParsePrefix(ipRange)
	}
	return sn
}

func TestSizeDockerBridgeSlots(t *testing.T) {
	cases := []struct {
		name       string
		cfg        config.Config
		net        docker.SandboxNetwork
		err        error
		wantTotal  int
		wantLimit  int
		wantNoPool bool
	}{
		// docker0 on a stock dockerd: the bridge (1,023), not the /16
		// (65,533 addresses), is the limit.
		{name: "docker0 /16", net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 1000, wantLimit: 1023},
		{name: "user bridge /20", net: dockerNet("bridge", "172.18.0.0/20", ""), wantTotal: 1000, wantLimit: 1023},
		// A smaller subnet is the smaller limit: 256 - network - broadcast - gateway.
		{name: "user bridge /24", net: dockerNet("bridge", "10.9.0.0/24", ""), wantTotal: 230, wantLimit: 253},
		// dockerd's fixed-cidr narrows what IPAM hands out.
		{name: "fixed-cidr /23", net: dockerNet("bridge", "172.17.0.0/16", "172.17.4.0/23"), wantTotal: 486, wantLimit: 509},
		// Free pause slots each hold a port and an address with no reservation.
		{name: "pause-netns pool on", cfg: config.Config{DockerNetnsPoolEnabled: true, DockerNetnsPoolDepth: 4}, net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 996, wantLimit: 1023},
		{name: "pause-netns pool off ignores its depth", cfg: config.Config{DockerNetnsPoolDepth: 4}, net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 1000, wantLimit: 1023},
		// An operator setting replaces the headroom, never the hard limit.
		{name: "operator lower", cfg: config.Config{DockerBridgeSlots: 600}, net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 600, wantLimit: 1023},
		{name: "operator at the limit", cfg: config.Config{DockerBridgeSlots: 1023}, net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 1023, wantLimit: 1023},
		{name: "operator past the limit is clamped", cfg: config.Config{DockerBridgeSlots: 5000, DockerNetnsPoolEnabled: true, DockerNetnsPoolDepth: 4}, net: dockerNet("bridge", "172.17.0.0/16", ""), wantTotal: 1019, wantLimit: 1023},
		// Not inspected (dockerd not up yet): assume one Linux bridge.
		{name: "inspect failed", err: errors.New("dial unix /var/run/docker.sock: connect: no such file"), wantTotal: 1000, wantLimit: 1023},
		// No bridge: only the subnet bounds it, and without one nothing does.
		{name: "macvlan /22", net: dockerNet("macvlan", "192.168.0.0/22", ""), wantTotal: 998, wantLimit: 1021},
		{name: "macvlan /16", net: dockerNet("macvlan", "192.168.0.0/16", ""), wantTotal: 65510, wantLimit: 65533},
		{name: "ipvlan no subnet", net: dockerNet("ipvlan", "", ""), wantNoPool: true},
		// A network smaller than the headroom still takes one sandbox.
		{name: "tiny subnet", net: dockerNet("bridge", "10.9.0.0/28", ""), wantTotal: 1, wantLimit: 13},
		{name: "huge subnet stays in range", net: dockerNet("macvlan", "10.0.0.0/8", ""), wantTotal: (1 << maxHostBits) - 3 - dockerBridgeSlotHeadroom, wantLimit: (1 << maxHostBits) - 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, limit := sizeDockerBridgeSlots(tc.cfg, tc.net, tc.err)
			if tc.wantNoPool {
				if total != 0 {
					t.Fatalf("total = %d, want no pool", total)
				}
				return
			}
			if total != tc.wantTotal || limit != tc.wantLimit {
				t.Fatalf("sizeDockerBridgeSlots = (%d, %d), want (%d, %d)", total, limit, tc.wantTotal, tc.wantLimit)
			}
		})
	}
	if _, ok := usableIPv4Addresses(netip.MustParsePrefix("fd00::/64")); ok {
		t.Fatal("an IPv6 prefix sized the IPv4 pool")
	}
}

func TestWireDockerBridgeSlots(t *testing.T) {
	docker0 := bridgeStub{net: dockerNet("bridge", "172.17.0.0/16", "")}
	worker := config.Config{ContainerEngine: models.ContainerEngineDocker, DockerNetwork: "bridge"}
	cases := []struct {
		name      string
		cfg       config.Config
		net       bridgeSource
		wantTotal int // 0 = no pool
		wantLog   string
	}{
		{name: "docker engine worker", cfg: worker, net: docker0, wantTotal: 1000, wantLog: "docker bridge slot pool configured"},
		{name: "engine unset means docker", cfg: config.Config{DockerNetwork: "bridge"}, net: docker0, wantTotal: 1000},
		{name: "inspect failed", cfg: worker, net: bridgeStub{err: errors.New("dockerd down")}, wantTotal: 1000, wantLog: "sandbox network not inspected"},
		{name: "no docker client", cfg: worker, wantTotal: 1000, wantLog: "no docker client"},
		{name: "operator value clamped", cfg: config.Config{ContainerEngine: models.ContainerEngineDocker, DockerNetwork: "bridge", DockerBridgeSlots: 4000}, net: docker0, wantTotal: 1023, wantLog: "SB_DOCKER_BRIDGE_SLOTS is more than the sandbox network holds"},
		{name: "containerd engine counts aerolvm0 in its netns pool", cfg: config.Config{ContainerEngine: models.ContainerEngineContainerd}, net: docker0},
		{name: "host network", cfg: config.Config{ContainerEngine: models.ContainerEngineDocker, DockerNetwork: "host"}, net: docker0},
		{name: "server-only node owns no sandboxes", cfg: config.Config{ContainerEngine: models.ContainerEngineDocker, NodeRole: config.NodeRoleServer}, net: docker0},
		{name: "unbounded network", cfg: worker, net: bridgeStub{net: dockerNet("ipvlan", "", "")}, wantLog: "docker bridge slot pool off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			a := capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 4096}, capacity.Limits{}, nil)
			wireDockerBridgeSlots(context.Background(), tc.cfg, logger, tc.net, a)
			p, ok := a.SlotPool()
			if tc.wantTotal == 0 {
				if ok {
					t.Fatalf("pool %+v set, want none", p)
				}
			} else if !ok || p.Total != tc.wantTotal || p.Name != capacity.SlotPoolDockerBridge || !p.Serves(models.RuntimeDocker) || !p.Serves(models.RuntimeGvisor) || p.Serves(models.RuntimeFirecracker) {
				t.Fatalf("pool = %+v %t, want docker_bridge of %d for docker and gvisor", p, ok, tc.wantTotal)
			}
			if tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog) {
				t.Fatalf("log %q missing %q", buf.String(), tc.wantLog)
			}
		})
	}
	// A nil admitter (tests, tools) is left alone.
	wireDockerBridgeSlots(context.Background(), worker, testLogger(), docker0, nil)
}

// The pool refuses exactly at its size with the docker bridge pool's
// capacity error, the same error the store-backed pools return.
func TestDockerBridgeSlotPoolRefusesAtItsSize(t *testing.T) {
	a := capacity.New(capacity.HostInfo{CPUCores: 96, MemoryTotalMB: 384 * 1024}, capacity.Limits{}, nil)
	wireDockerBridgeSlots(context.Background(), config.Config{DockerNetwork: "bridge"}, testLogger(), bridgeStub{net: dockerNet("bridge", "172.17.0.0/16", "")}, a)
	for i := 0; i < 1000; i++ {
		if err := a.Admit(fmt.Sprintf("sb-%d", i), capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker}); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	err := a.Admit("sb-1000", capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeDocker})
	if pool, ok := capacity.SlotPoolExhausted(err); !ok || pool != capacity.DockerBridgePool || !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("1001st admit = %v, want the docker bridge pool's capacity refusal", err)
	}
}
