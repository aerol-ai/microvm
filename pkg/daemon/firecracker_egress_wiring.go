package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

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
	newFirecrackerNAT = func() (tap.NATBackend, error) { return iptables.New() }
)

// wireFirecrackerEgress gives Firecracker guests a way out and a firewall
// (plans/egress-domain-filtering.md Phase 4):
//   - forwarding on, and a masquerade for the TAP subnet, which nothing in
//     the repo or the provisioning set up (the TODOS.md "Audit Firecracker
//     outbound NAT path" gap);
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
	nat, err := newFirecrackerNAT()
	if err != nil {
		return nil, fmt.Errorf("firecracker egress: iptables: %w", err)
	}
	if err := tap.EnsureNAT(nat, subnet.String()); err != nil {
		return nil, fmt.Errorf("firecracker egress: %w", err)
	}
	rules, err := newFirecrackerRules(cfg)
	if err != nil {
		return nil, fmt.Errorf("firecracker egress: netrules: %w", err)
	}
	if !rules.Enabled() {
		logger.Info("firecracker egress: network rules disabled; guests get NAT but no egress policies")
		return func() {}, nil
	}
	rules.SetBridgeSubnet(subnet.Masked().String())
	if err := rules.EnsureChain(); err != nil {
		return nil, fmt.Errorf("firecracker egress: bootstrap %s: %w", netrules.ChainAerolvmFC, err)
	}
	d.SetNetRules(rules)
	d.SetTapSubnet(subnet.Masked())
	logger.Info("firecracker egress: NAT and per-guest firewall ready", "tap_subnet", subnet.Masked().String(), "chain", netrules.ChainAerolvmFC)
	return startChainReassert(ctx, rules, logger), nil
}
