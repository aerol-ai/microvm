//go:build linux

package rootd

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// fenceRuntime is the IPv6 fence source the helper keeps: the containerd
// engine's bridge (split mode is the containerd engine only).
const fenceRuntime = "containerd"

// kernelFirewall is the helper's FirewallHost: netrules (AEROLVM-USER and
// AEROLVM-INPUT, the block sets, the node guard and the floor) and the IPv6
// fence, as sandboxd runs them in single mode.
type kernelFirewall struct {
	rules  *netrules.Manager
	fence  *ipv6fence.Supervisor
	subnet netip.Prefix

	// The node guard's and floor's last lists: a list that did not change
	// is re-asserted, not installed again.
	mu       sync.Mutex
	guard    []netrules.NodePort
	guardSet bool
	floor    []netip.Prefix
	floorSet bool
}

// newRulesManager builds the netrules manager; tests replace it with one
// over a fake backend.
var newRulesManager = func(backend string) (*netrules.Manager, error) {
	return netrules.NewWithOptions(true, backend, netrules.ChainAerolvmUser)
}

// newFenceBackend is the IPv6 fence's kernel backend; tests replace it.
var newFenceBackend = ipv6fence.NewBackend

// openFirewall opens the helper's firewall on the network it already
// opened: the bridge and the sandboxes' range come from the helper's own
// CNI config, the backend and interconnect from its own environment.
func openFirewall(cfg Config, n NetworkHost) (FirewallHost, error) {
	netrules.SetSandboxInterconnect(cfg.Firewall.Interconnect)
	m, err := newRulesManager(cfg.Firewall.Backend)
	if err != nil {
		return nil, fmt.Errorf("netrules: %w", err)
	}
	m.SetBridgeSubnet(n.Subnet().String())
	bridge := n.Bridge()
	fence := ipv6fence.NewSupervisor(newFenceBackend(), slog.New(slog.DiscardHandler), ipv6fence.Source{Runtime: fenceRuntime,
		Spec: func(context.Context) (ipv6fence.Spec, error) { return ipv6fence.Spec{Bridges: []string{bridge}}, nil }})
	k := &kernelFirewall{rules: m, fence: fence, subnet: n.Subnet()}
	// Before any rule call (PR 5 review): a helper that starts on a kernel
	// an earlier helper filled knows nothing of what is there. Its chain,
	// its block sets and its own floor (the cloud metadata endpoints, the
	// floor of its own environment, and the sandboxes' range when they may
	// not reach each other) go in first, so every sandbox rule from here on
	// lands below the floor's jump, and a release finds the address in the
	// block sets it reads. Without them no rule call is served: the open
	// fails, and the next call tries again.
	if err := m.EnsureChain(); err != nil {
		return nil, fmt.Errorf("the sandboxes' chain: %w", err)
	}
	// Block sets are an optimization: without them netrules keeps
	// per-address rules, which stay correct.
	_ = m.PrepareBlockSets()
	// The floor keeps everything it drops now (PR 5 review 2): an earlier
	// helper's floor holds the operator's deny ranges, which this helper
	// learns only when the agent next sends them. Until then its floor is
	// its own fixed part and whatever the live one drops, a superset of
	// both; the agent's list then replaces it.
	live, err := m.LiveFloor(n.Subnet())
	if err != nil {
		return nil, err
	}
	if _, err := k.SetFloor(live); err != nil {
		return nil, fmt.Errorf("the egress floor: %w", err)
	}
	return k, nil
}

// ensureSysctls turns bridged traffic through netfilter on; tests replace
// it.
var ensureSysctls = hostnet.EnsureForwardingSysctls

func (k *kernelFirewall) EnsureHost(ctx context.Context) (error, error) {
	if err := ensureSysctls(); err != nil {
		return nil, err
	}
	// The chain and the block sets went in when the firewall opened; this
	// puts back whatever has gone since.
	if err := k.rules.ReassertChain(); err != nil {
		return nil, fmt.Errorf("the sandboxes' chain: %w", err)
	}
	_, _ = k.rules.ReassertBlockSets()
	k.fence.Sync(ctx, true)
	return k.fence.Ready(fenceRuntime), nil
}

func (k *kernelFirewall) Reassert(ctx context.Context) {
	_ = k.rules.ReassertChain()
	_, _ = k.rules.ReassertBlockSets()
	_, _ = k.rules.ReassertNodeGuard()
	_, _ = k.rules.ReassertFloor()
	k.fence.Sync(ctx, false)
}

func (k *kernelFirewall) SetNodeGuard(allow []rootpolicy.NodePort) (bool, error) {
	ports := make([]netrules.NodePort, 0, len(allow))
	for _, p := range allow {
		np := netrules.NodePort{Proto: p.Proto, Port: uint16(p.Port)}
		if p.Dst != "" {
			np.Dst = netip.MustParseAddr(p.Dst) // checked by rootpolicy.CheckNodePorts
		}
		ports = append(ports, np)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.guardSet && slices.Equal(k.guard, ports) {
		return k.rules.ReassertNodeGuard()
	}
	if err := k.rules.SetNodeGuard(k.subnet, ports); err != nil {
		return false, err
	}
	k.guard, k.guardSet = ports, true
	return false, nil
}

func (k *kernelFirewall) SetFloor(cidrs []netip.Prefix) (bool, error) {
	// The cloud metadata endpoints and the node's own extra floor (the
	// helper's environment) are on the floor whatever the agent sends.
	full := egresspolicy.WithFixedFloor(cidrs)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.floorSet && slices.Equal(k.floor, full) {
		return k.rules.ReassertFloor()
	}
	if err := k.rules.SetFloor(k.subnet, full); err != nil {
		return false, err
	}
	k.floor, k.floorSet = full, true
	return false, nil
}

func (k *kernelFirewall) Rules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	m := k.rules
	switch op {
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS:
		return m.BlockAllEgressReport(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_LIFT_BLOCK_EGRESS:
		return false, m.LiftBlockAllEgress(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS:
		return false, m.ClearBlockAllEgress(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_INGRESS:
		return false, m.BlockAllIngress(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS:
		return false, m.ClearBlockAllIngress(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY:
		// A replace, never an add (PR 5 review): lists sent one after
		// another never pile up on an address, whatever an earlier helper
		// left there.
		return false, m.ReplaceEgressPolicy(ctx, ip, allow, deny)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY:
		return false, m.ClearEgressPolicyOf(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS:
		return false, m.HoldEgress(ip)
	case rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS:
		return false, m.ClearHoldEgress(ip)
	}
	return false, fmt.Errorf("op %v", op)
}

func (k *kernelFirewall) ClearAddress(ip string) error { return k.rules.ClearAddress(ip) }
