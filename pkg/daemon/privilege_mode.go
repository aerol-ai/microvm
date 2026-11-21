package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Privilege mode (internal/privmode, plans/security-gaps-m1-m4.md D5, D22).
// single, the default and the mode when the setting is absent, is today's:
// nothing here runs. split runs sandboxd with no rights; the root helper
// does its root work, which is built one step at a time (M1 PRs 4 to 9).
// So far the helper does the containerd engine's network: namespaces, CNI,
// the forwarding sysctls and the CNI config. Root work it does not do yet
// is refused by name, at start for what sandboxd does at boot, at the call
// for the rest, and never done as root instead.

// checkPrivilegeMode refuses, at start, a split-mode node this build cannot
// run. Two needs last: split is the containerd engine only (Docker's
// socket is as good as root, and Docker has no gate), and the netns pool,
// whose namespaces the helper makes. The rest are steps the helper does
// not do yet, each named.
func checkPrivilegeMode(cfg config.Config) error {
	if cfg.PrivilegeMode != privmode.Split {
		return nil
	}
	if cfg.ContainerEngine != models.ContainerEngineContainerd {
		return errors.New("SB_PRIVILEGE_MODE=split needs SB_CONTAINER_ENGINE=containerd: the Docker engine's socket " +
			"is as good as root and has no gate in front of it, so a Docker node runs in privilege mode single")
	}
	if !cfg.ContainerdNativeNetnsPoolEnabled {
		return errors.New("SB_PRIVILEGE_MODE=split needs SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true: " +
			"the root helper makes every sandbox's network namespace for the pool")
	}
	var gaps []privmode.Step
	if cfg.EnableNetworkRules || cfg.EgressFQDNEnabled || cfg.EnterpriseMode {
		gaps = append(gaps, privmode.StepFirewall)
	}
	if cfg.ContainerdPoolEnabled {
		gaps = append(gaps, privmode.StepWarmPool)
	}
	if cfg.EnableWasm || cfg.EnableIsolate || cfg.EnableFirecracker {
		gaps = append(gaps, privmode.StepHostProcesses)
	}
	if cfg.GvisorCheckpointMoves {
		gaps = append(gaps, privmode.StepMoves)
	}
	if cfg.IngressProxyRouting || readBypassMarker(ingressRoutingMarkerPath(cfg)) {
		// The kernel forwarder writes iptables rules at boot, and again to
		// roll back after a boot that engaged it (hostPortForwarderFor).
		gaps = append(gaps, privmode.StepHostPorts)
	}
	return privmode.NotYet("start sandboxd", gaps...)
}

// mountsOffFor is why this node refuses external storage, or "". In split
// mode the helper does not mount yet, so every create with a mount is
// refused with that reason (501 mounts_unavailable), and the node serves
// the rest.
func mountsOffFor(cfg config.Config) string {
	if cfg.PrivilegeMode == privmode.Split {
		return privmode.NotYet("mount external storage", privmode.StepMounts).Error()
	}
	return mountsOffReason(cfg)
}

// newRootHelper is the agent's client of the helper in split mode, nil in
// single. It dials nothing until its first call (the lazy bootstrap,
// rootclient: an atomic latch and a single flight, like
// Service.EnsureLayer4Ready), and every refusal it is answered with is
// audited through the service (eng review D9).
func newRootHelper(cfg config.Config, svc *service.Service) *rootclient.Client {
	if cfg.PrivilegeMode != privmode.Split {
		return nil
	}
	c := rootclient.Config{Socket: cfg.RootdSocket, HelperUID: rootHelperUID}
	if svc != nil {
		c.OnRefusal = svc.RecordRootRefusal
	}
	return rootclient.New(c)
}

// rootHelperUID is the uid that must serve the helper's socket: root. Tests,
// whose own process serves it, set their uid.
var rootHelperUID uint32

// helperBootWait bounds how long sandboxd waits at start for the helper:
// the supervisor starts it beside sandboxd, and it may still be coming up.
// Past it the start fails, and the kubelet or systemd tries again.
var helperBootWait, helperBootRetry = time.Minute, time.Second

// hostNetwork is the helper's boot call (*rootclient.Client).
type hostNetwork interface {
	EnsureHostNetwork(ctx context.Context) (string, error)
}

// resolveSplitBridgeSubnet has the helper set the host up for sandbox
// networks (forwarding sysctls, its CNI config) and takes the sandboxes'
// range from it: the helper's CNI config is what hands addresses out now.
// It waits for a helper that is not up yet; a set SB_CONTAINERD_BRIDGE_SUBNET
// must name the same range.
func resolveSplitBridgeSubnet(ctx context.Context, cfg config.Config, h hostNetwork, logger *slog.Logger) (string, error) {
	deadline := time.Now().Add(helperBootWait)
	var subnet string
	for logged := false; ; logged = true {
		var err error
		if subnet, err = h.EnsureHostNetwork(ctx); err == nil {
			break
		}
		if !errors.Is(err, rootclient.ErrUnavailable) || time.Now().Add(helperBootRetry).After(deadline) {
			return "", fmt.Errorf("root helper: set the host up for sandbox networks: %w", err)
		}
		if !logged {
			logger.Warn("privilege mode split: waiting for the root helper", "socket", cfg.RootdSocket, "error", err, "for", helperBootWait)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(helperBootRetry):
		}
	}
	if want := cfg.ContainerdBridgeSubnet; want != "" && want != subnet {
		return "", fmt.Errorf("SB_CONTAINERD_BRIDGE_SUBNET is %s, but the root helper's CNI config hands out %s; "+
			"set the same range for both", want, subnet)
	}
	logger.Info("privilege mode split: the root helper does the network work", "socket", cfg.RootdSocket, "subnet", subnet)
	return subnet, nil
}

// netnsHelper is the helper's network calls the pool uses
// (*rootclient.Client).
type netnsHelper interface {
	RealizeNetns(ctx context.Context, name string) (string, string, error)
	RemoveNetns(ctx context.Context, name, ip string) error
	DisableNetnsIPv6(ctx context.Context, name string) error
	NetnsAddrs(ctx context.Context, name string) (bool, []string, error)
}

// helperNetnsHost is the netns pool's HostManager in split mode: each step
// one helper call, the namespace named by the same identity the in-process
// Host keys it by (netns.Slot.NetnsName). It also answers the pool's two
// optional steps, DisableIPv6 and IPv4Addrs, and its exists check.
type helperNetnsHost struct {
	h      netnsHelper
	subnet netip.Prefix
	log    *slog.Logger
}

func newHelperNetnsHost(h netnsHelper, subnet string, log *slog.Logger) *helperNetnsHost {
	p, _ := netip.ParsePrefix(subnet)
	return &helperNetnsHost{h: h, subnet: p.Masked(), log: log}
}

func (n *helperNetnsHost) Realize(ctx context.Context, slot netns.Slot) (string, string, error) {
	if strings.TrimSpace(slot.SandboxID) == "" {
		return "", "", errors.New("netns host: sandbox_id is required")
	}
	return n.h.RealizeNetns(ctx, slot.NetnsName())
}

// Remove sends the address the pool recorded only when it is a sandbox
// address in the range: the helper refuses any other, and a refusal is a
// security event, which a stale row (a backup from another machine) is
// not. Without it the helper still removes the namespace, its attachment
// and its lease; only that address's connection tracking is left.
func (n *helperNetnsHost) Remove(ctx context.Context, slot netns.Slot) error {
	name := slot.NetnsName()
	if name == "" {
		return nil
	}
	ip := strings.TrimSpace(slot.ContainerIP)
	if ip != "" {
		if _, err := rootpolicy.CheckSandboxAddress(n.subnet, ip); err != nil {
			n.log.Warn("containerd netns teardown: the recorded address is not one of this node's sandbox addresses; not sending it to the root helper",
				"slot_id", slot.SlotID, "netns", name, "container_ip", ip, "subnet", n.subnet)
			ip = ""
		}
	}
	return n.h.RemoveNetns(ctx, name, ip)
}

func (n *helperNetnsHost) DisableIPv6(ctx context.Context, slot netns.Slot) error {
	if strings.TrimSpace(slot.NetnsPath) == "" {
		return errors.New("netns host: slot has no netns path")
	}
	return n.h.DisableNetnsIPv6(ctx, slot.NetnsName())
}

func (n *helperNetnsHost) IPv4Addrs(ctx context.Context, slot netns.Slot) ([]string, error) {
	if strings.TrimSpace(slot.NetnsPath) == "" {
		return nil, errors.New("netns host: slot has no netns path")
	}
	_, addrs, err := n.h.NetnsAddrs(ctx, slot.NetnsName())
	return addrs, err
}

// exists is the pool's boot check of a recorded namespace path, asked of
// the helper: sandboxd cannot see the helper's netns folder. A helper that
// cannot answer keeps the slot: the address check that follows rebuilds a
// warm slot it cannot vouch for.
func (n *helperNetnsHost) exists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	ok, _, err := n.h.NetnsAddrs(context.Background(), filepath.Base(path))
	return ok || err != nil
}
