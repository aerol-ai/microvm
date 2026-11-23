package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
)

// Firecracker in privilege mode split (M1 PR 9b): the driver's split seam
// (fcruntime.SplitHelper) over the root helper's calls.

// firecrackerHelper is the helper's calls the Firecracker driver uses
// (*rootclient.Client).
type firecrackerHelper interface {
	hostHelper
	PrepareFirecracker(ctx context.Context, id string, stage ...string) (root, stageDir string, err error)
	EnsureTap(ctx context.Context, name string) (*rootdpb.EnsureTapResponse, error)
	RemoveTap(ctx context.Context, name string) error
	MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error
}

const firecrackerKind = rootdpb.HostKind_HOST_KIND_FIRECRACKER

// splitFirecracker adapts the helper's calls to fcruntime.SplitHelper.
type splitFirecracker struct{ h firecrackerHelper }

var _ fcruntime.SplitHelper = splitFirecracker{}

func (s splitFirecracker) PrepareFirecracker(ctx context.Context, id string, stage ...string) (string, string, error) {
	return s.h.PrepareFirecracker(ctx, id, stage...)
}

func (s splitFirecracker) SpawnFirecracker(ctx context.Context, id string) (fcruntime.SplitProcess, error) {
	resp, err := s.h.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: firecrackerKind, Id: id})
	if err != nil {
		return nil, err
	}
	if resp.GetPid() == 0 {
		return nil, errors.New("root helper answered a Firecracker VM with no process")
	}
	return s.h.HoldHost(firecrackerKind, id, int(resp.GetPid()), resp.GetStartTicks()), nil
}

func (s splitFirecracker) OpenFirecracker(ctx context.Context, id string, pid int, ticks uint64) (fcruntime.SplitProcess, error) {
	p, err := s.h.OpenHost(ctx, firecrackerKind, id, pid, ticks)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s splitFirecracker) StopFirecracker(ctx context.Context, id string) error {
	_, err := s.h.StopHost(ctx, firecrackerKind, id)
	return err
}

func (s splitFirecracker) EnsureTap(ctx context.Context, name string) (fcruntime.TapSlot, error) {
	resp, err := s.h.EnsureTap(ctx, name)
	if err != nil {
		return fcruntime.TapSlot{}, err
	}
	return fcruntime.TapSlot{TapName: name, CIDR: resp.GetCidr(), HostIP: resp.GetHostIp(), GuestIP: resp.GetGuestIp(),
		VsockCID: resp.GetVsockCid()}, nil
}

func (s splitFirecracker) RemoveTap(ctx context.Context, name string) error {
	return s.h.RemoveTap(ctx, name)
}

func (s splitFirecracker) MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error {
	return s.h.MakeFilesystem(ctx, id, name, source, sizeMiB)
}

// the client is the helper.
var _ firecrackerHelper = (*rootclient.Client)(nil)

// The guests' firewall in privilege mode split (M1 PR 14). The driver keeps
// calling the same NetRules methods in the same order as in single mode
// (fcruntime.NetRules: a create's block-all or egress policy on the guest
// address, the gateway's hold, quota blocks, the clears on destroy, the
// floor and the node guard on the TAP base); each is one call to the
// helper, which checks what it is sent and renders the rules on the
// guests' chain itself.

// guestFirewallHelper is the helper's guest firewall calls
// (*rootclient.Client).
type guestFirewallHelper interface {
	EnsureGuestFirewall(ctx context.Context) error
	SetGuestNodeGuard(ctx context.Context, allow []*rootdpb.NodePort) (bool, error)
	SetGuestEgressFloor(ctx context.Context, cidrs []string) (bool, error)
	GuestRules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error)
}

var _ guestFirewallHelper = (*rootclient.Client)(nil)

// guestRuleCalls are ruleCalls on the guests' firewall.
type guestRuleCalls struct{ h guestFirewallHelper }

func (g guestRuleCalls) SetNodeGuard(ctx context.Context, allow []*rootdpb.NodePort) (bool, error) {
	return g.h.SetGuestNodeGuard(ctx, allow)
}

func (g guestRuleCalls) SetEgressFloor(ctx context.Context, cidrs []string) (bool, error) {
	return g.h.SetGuestEgressFloor(ctx, cidrs)
}

func (g guestRuleCalls) SandboxRules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	return g.h.GuestRules(ctx, op, ip, allow, deny)
}

// newHelperGuestRules is the driver's NetRules through the helper's guest
// firewall. The helper guards and floors its own TAP base; subnet is the
// driver's, which the floor and guard calls carry and the helper ignores.
func newHelperGuestRules(h guestFirewallHelper, subnet netip.Prefix) *helperFirewall {
	return &helperFirewall{h: guestRuleCalls{h: h}, subnet: subnet.Masked()}
}

var _ fcruntime.NetRules = (*helperFirewall)(nil)

// bootSplitGuestFirewall has the helper set the guests' firewall up at
// boot, as single mode's wireFirecrackerEgress does, and answers the
// driver's NetRules and TAP base. A call that fails stops the start (a
// helper too old for it included: the supervisor swaps in the newer one,
// and the next start finds it): with network rules on, no guest runs
// without its firewall.
func bootSplitGuestFirewall(ctx context.Context, cfg config.Config, h guestFirewallHelper) (*helperFirewall, netip.Prefix, error) {
	subnet, err := netip.ParsePrefix(cfg.FirecrackerTapBaseCIDR)
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("firecracker egress: tap base cidr: %w", err)
	}
	if err := h.EnsureGuestFirewall(ctx); err != nil {
		if errors.Is(err, rootclient.ErrUnsupported) {
			return nil, netip.Prefix{}, fmt.Errorf("root helper: the Firecracker guests' firewall needs a newer helper "+
				"(privilege mode split, SB_ENABLE_NETWORK_RULES): %w", err)
		}
		return nil, netip.Prefix{}, fmt.Errorf("root helper: set the Firecracker guests' firewall up: %w", err)
	}
	return newHelperGuestRules(h, subnet), subnet.Masked(), nil
}
