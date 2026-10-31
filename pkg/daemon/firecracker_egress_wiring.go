package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/coreos/go-iptables/iptables"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/tap"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// Seams for wireFirecrackerEgress; tests replace them.
var (
	newFirecrackerRules = func(cfg config.Config) (*netrules.Manager, error) {
		return netrules.NewWithOptions(cfg.EnableNetworkRules, cfg.NetrulesBackend, netrules.ChainAerolvmFC)
	}
	newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return iptables.New() }
)

// wireFirecrackerEgress gives Firecracker guests a way out and a firewall
// (plans/egress-domain-filtering.md Phase 4):
//   - forwarding on, and a masquerade for the TAP subnet, which nothing in
//     the repo or the provisioning set up (the TODOS.md "Audit Firecracker
//     outbound NAT path" gap);
//   - the guest isolation (tap.EnsureIsolation): no guest reaches another,
//     and nothing forwarded (a container, a gVisor sandbox) opens a
//     connection into a guest, in any protocol. Installed with or without
//     network rules, and re-asserted on the chain tick;
//   - the AEROLVM-FC chain, jumped from FORWARD, with accepts for the TAP
//     subnet below the per-guest-IP drops, so dockerd's FORWARD DROP
//     policy doesn't strand the guests;
//   - the driver gets that firewall for block-all, CIDR lists, quota blocks
//     and the gateway hold.
//
// With network rules disabled the guests still get NAT, but the driver has
// no firewall, so the service keeps refusing their egress options. The
// returned stop ends the chain reassert loop.
func wireFirecrackerEgress(ctx context.Context, cfg config.Config, logger *slog.Logger, d *fcruntime.Driver) (func(), error) {
	subnet, err := netip.ParsePrefix(cfg.FirecrackerTapBaseCIDR)
	if err != nil {
		return nil, fmt.Errorf("firecracker egress: tap base cidr: %w", err)
	}
	if err := ensureForwardingSysctls(); err != nil {
		return nil, fmt.Errorf("firecracker egress: forwarding sysctls: %w", err)
	}
	ipt, err := newFirecrackerIPTables()
	if err != nil {
		return nil, fmt.Errorf("firecracker egress: iptables: %w", err)
	}
	if err := tap.EnsureNAT(ipt, subnet.String()); err != nil {
		return nil, fmt.Errorf("firecracker egress: %w", err)
	}
	if err := tap.EnsureIsolation(ipt, subnet.String()); err != nil {
		return nil, fmt.Errorf("firecracker egress: %w", err)
	}
	stopIsolation := startIsolationReassert(ctx, ipt, subnet.String(), logger)
	rules, err := newFirecrackerRules(cfg)
	if err != nil {
		stopIsolation()
		return nil, fmt.Errorf("firecracker egress: netrules: %w", err)
	}
	if !rules.Enabled() {
		logger.Info("firecracker egress: network rules disabled; guests get NAT and isolation but no egress policies")
		return stopIsolation, nil
	}
	rules.SetBridgeSubnet(subnet.Masked().String())
	if err := rules.EnsureChain(); err != nil {
		stopIsolation()
		return nil, fmt.Errorf("firecracker egress: bootstrap %s: %w", netrules.ChainAerolvmFC, err)
	}
	d.SetNetRules(rules)
	d.SetTapSubnet(subnet.Masked())
	logger.Info("firecracker egress: NAT, isolation and per-guest firewall ready", "tap_subnet", subnet.Masked().String(),
		"chain", netrules.ChainAerolvmFC, "isolation_chain", tap.IsolationChain)
	stopChain := startChainReassert(ctx, rules, logger)
	return func() { stopChain(); stopIsolation() }, nil
}

// startIsolationReassert re-runs tap.EnsureIsolation on the chain reassert
// interval, so a flush of the mangle table (an operator, a firewall reload)
// does not leave the guests open until the next daemon start.
func startIsolationReassert(ctx context.Context, ipt tap.IsolationBackend, subnet string, logger *slog.Logger) func() {
	ctx, cancel := context.WithCancel(ctx)
	interval := chainReassertInterval
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := tap.EnsureIsolation(ipt, subnet); err != nil {
					logger.Warn("re-assert "+tap.IsolationChain+" failed", "error", err)
				}
			}
		}
	}()
	return cancel
}
