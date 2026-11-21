package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The host firewall in privilege mode split (M1 PR 5). The containerd
// driver keeps calling the same firewall methods in the same order
// (cntr.HostFirewall); here each one is a call to the root helper, which
// checks what it is sent and renders the rules itself. On top of that, a
// create's rules and a teardown's clears are one call each, with the
// slot's own (PrepareSandbox, ReleaseSandbox): a cold create is one helper
// call in all, a warm one at most one, a teardown one.

// firewallHelper is the helper's firewall calls (*rootclient.Client).
type firewallHelper interface {
	EnsureHostFirewall(ctx context.Context) (fence string, err error)
	SetNodeGuard(ctx context.Context, allow []*rootdpb.NodePort) (bool, error)
	SetEgressFloor(ctx context.Context, cidrs []string) (bool, error)
	SandboxRules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error)
	PrepareSandbox(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error)
	ReleaseSandbox(ctx context.Context, req *rootdpb.ReleaseSandboxRequest) error
}

// splitFirewallOn: the host firewall is on (SB_ENABLE_NETWORK_RULES), so
// in split mode the helper keeps it.
func splitFirewallOn(cfg config.Config) bool { return cfg.EnableNetworkRules }

// splitHostStepOn: the helper's host step (chains, block sets, IPv6 fence)
// runs: the firewall is on, or enterprise mode, which always fences IPv6
// (wireIPv6Fence).
func splitHostStepOn(cfg config.Config) bool { return cfg.EnableNetworkRules || cfg.EnterpriseMode }

// helperFirewall is cntr.HostFirewall and cntr.CreateRules through the
// helper. The netrules methods take no context; each call is bounded by
// the client's network timeout.
type helperFirewall struct {
	h      firewallHelper
	subnet netip.Prefix

	// The last lists sent, which a re-assert sends again: the helper
	// answers "repaired" when the rules were gone.
	mu    sync.Mutex
	guard []*rootdpb.NodePort
	floor []string
}

func newHelperFirewall(h firewallHelper, subnet string) *helperFirewall {
	p, _ := netip.ParsePrefix(subnet)
	return &helperFirewall{h: h, subnet: p.Masked()}
}

var (
	_ cntr.HostFirewall = (*helperFirewall)(nil)
	_ cntr.CreateRules  = (*helperFirewall)(nil)
)

func (f *helperFirewall) Enabled() bool              { return true }
func (f *helperFirewall) BridgeSubnet() netip.Prefix { return f.subnet }

// rules makes one rule change. An empty address is no rule, as in
// netrules: nothing is sent.
func (f *helperFirewall) rules(op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	if strings.TrimSpace(ip) == "" {
		return false, nil
	}
	return f.h.SandboxRules(context.Background(), op, ip, allow, deny)
}

func (f *helperFirewall) op(op rootdpb.SandboxRulesOp, ip string) error {
	_, err := f.rules(op, ip, nil, nil)
	return err
}

func (f *helperFirewall) BlockAllEgress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, ip)
}

func (f *helperFirewall) BlockAllEgressReport(ip string) (bool, error) {
	return f.rules(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, ip, nil, nil)
}

func (f *helperFirewall) LiftBlockAllEgress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_LIFT_BLOCK_EGRESS, ip)
}

func (f *helperFirewall) ClearBlockAllEgress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS, ip)
}

func (f *helperFirewall) BlockAllIngress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_INGRESS, ip)
}

func (f *helperFirewall) ClearBlockAllIngress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS, ip)
}

func (f *helperFirewall) ApplyEgressPolicy(ip string, allow, deny []string) error {
	_, err := f.rules(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, ip, allow, deny)
	return err
}

func (f *helperFirewall) ClearEgressPolicy(ip string, allow, deny []string) error {
	_, err := f.rules(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY, ip, allow, deny)
	return err
}

func (f *helperFirewall) HoldEgress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS, ip)
}

func (f *helperFirewall) ClearHoldEgress(ip string) error {
	return f.op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS, ip)
}

// SetNodeGuard sends the allow list; the helper guards its own bridge's
// range, so subnet is not sent.
func (f *helperFirewall) SetNodeGuard(_ netip.Prefix, allow []netrules.NodePort) error {
	list := make([]*rootdpb.NodePort, 0, len(allow))
	for _, p := range allow {
		np := &rootdpb.NodePort{Proto: p.Proto, Port: uint32(p.Port)}
		if p.Dst.IsValid() {
			np.Dst = p.Dst.String()
		}
		list = append(list, np)
	}
	if _, err := f.h.SetNodeGuard(context.Background(), list); err != nil {
		return err
	}
	f.mu.Lock()
	f.guard = list
	f.mu.Unlock()
	return nil
}

// ReassertNodeGuard sends the last list again. The helper re-asserts on
// its own timer too; this keeps the service's repair count true.
func (f *helperFirewall) ReassertNodeGuard() (bool, error) {
	f.mu.Lock()
	list := f.guard
	f.mu.Unlock()
	if list == nil {
		return false, nil
	}
	return f.h.SetNodeGuard(context.Background(), list)
}

// SetFloor sends the node's deny floor; the helper adds the floor no
// setting can take off itself.
func (f *helperFirewall) SetFloor(_ netip.Prefix, cidrs []netip.Prefix) error {
	list := make([]string, 0, len(cidrs))
	for _, p := range cidrs {
		list = append(list, p.String())
	}
	if _, err := f.h.SetEgressFloor(context.Background(), list); err != nil {
		return err
	}
	f.mu.Lock()
	f.floor = list
	f.mu.Unlock()
	return nil
}

func (f *helperFirewall) ReassertFloor() (bool, error) {
	f.mu.Lock()
	list := f.floor
	f.mu.Unlock()
	if list == nil {
		return false, nil
	}
	return f.h.SetEgressFloor(context.Background(), list)
}

// ApplyCreateRules is a warm create's rules: one PrepareSandbox with the
// firewall part alone, for the slot it claimed.
func (f *helperFirewall) ApplyCreateRules(ctx context.Context, netnsName, ip string, blockAll bool, allow, deny []string) error {
	_, err := f.h.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: netnsName, Parts: []string{rootdpb.PartFirewall},
		ContainerIp: ip, Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: blockAll, AllowCidrs: allow, DenyCidrs: deny}})
	return err
}

func (f *helperFirewall) FoldsIntoBuild() bool  { return true }
func (f *helperFirewall) ClearsOnRelease() bool { return true }

// helperFence is the IPv6 fence's state as the helper reports it: the
// helper keeps the fence on the sandboxes' bridge (and re-asserts it on
// its own timer); the create gate asks this (service.IPv6Fence).
type helperFence struct {
	h   firewallHelper
	log *slog.Logger

	mu     sync.Mutex
	status error // nil: the fence covers the sandboxes
}

func newHelperFence(h firewallHelper, log *slog.Logger) *helperFence {
	return &helperFence{h: h, log: log, status: ipv6fence.ErrNotSynced}
}

// sync runs the helper's host step and records the fence's state. A call
// that failed is the error; a fence the helper could not put in place is
// only a state, which holds creates.
func (f *helperFence) sync(ctx context.Context) error {
	fence, err := f.h.EnsureHostFirewall(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case err != nil:
		f.status = err
	case fence != "":
		f.status = errors.New(fence)
	default:
		f.status = nil
	}
	return err
}

// Ready answers the create gate. Split mode runs containers alone (no
// Firecracker), whose sandboxes are on the helper's bridge.
func (f *helperFence) Ready(runtime string) error {
	if runtime != models.ContainerEngineContainerd {
		return fmt.Errorf("privilege mode split fences the containerd bridge only, not %s", runtime)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// run asks again every tick while the fence is not in place, and every
// ipv6fence.ReassertInterval once it is, until ctx ends.
func (f *helperFence) run(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if f.Ready(models.ContainerEngineContainerd) == nil && now.Sub(last) < ipv6fence.ReassertInterval {
				continue
			}
			last = now
			before := f.Ready(models.ContainerEngineContainerd)
			_ = f.sync(ctx)
			if after := f.Ready(models.ContainerEngineContainerd); (before == nil) != (after == nil) {
				if after != nil {
					f.log.Error("privilege mode split: the root helper's IPv6 fence is not in place; containerd creates are refused until it is", "error", after)
				} else {
					f.log.Info("privilege mode split: the root helper's IPv6 fence is in place")
				}
			}
		}
	}
}

// wire hands the fence to the create gate and keeps it current.
func (f *helperFence) wire(ctx context.Context, svc *service.Service, tick time.Duration) {
	svc.SetIPv6Fence(f)
	go f.run(ctx, tick)
}

// bootSplitFirewall runs the helper's host step at boot, as single mode's
// EnsureChain: a call that fails stops the start (a helper too old for it
// included: the supervisor swaps in the newer one, and the next start
// finds it). It answers the fence the create gate asks.
func bootSplitFirewall(ctx context.Context, h firewallHelper, logger *slog.Logger) (*helperFence, error) {
	fence := newHelperFence(h, logger)
	if err := fence.sync(ctx); err != nil {
		if errors.Is(err, rootclient.ErrUnsupported) {
			return nil, fmt.Errorf("root helper: the host firewall needs a newer helper (privilege mode split, SB_ENABLE_NETWORK_RULES): %w", err)
		}
		return nil, fmt.Errorf("root helper: set the host firewall up: %w", err)
	}
	if err := fence.Ready(models.ContainerEngineContainerd); err != nil {
		logger.Error("privilege mode split: the root helper's IPv6 fence is not in place yet; containerd creates are refused until it is", "error", err)
	}
	return fence, nil
}

// isLeaseRefusal: the helper refused an address that its CNI leased to
// another slot (rootpolicy RuleLease).
func isLeaseRefusal(err error) bool {
	var r *rootclient.RefusedError
	return errors.As(err, &r) && r.Reason == string(rootpolicy.RuleLease)
}
