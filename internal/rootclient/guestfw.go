package rootclient

import (
	"context"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The Firecracker guests' firewall (M1 PR 14, internal/rootd guestfw.go):
// the guests' chain, block sets, node guard and floor on the helper's own
// TAP base, and one guest's rules. The agent sends typed values; the
// helper checks each and renders every rule itself. A helper whose
// handshake does not list a call is not sent it (call's UnsupportedError).

// EnsureGuestFirewall has the helper make sure of the guests' firewall:
// their NAT and isolation, their chain and block sets, and their floor.
func (c *Client) EnsureGuestFirewall(ctx context.Context) error {
	_, err := call(ctx, c, rootdpb.FeatureEnsureGuestFirewall, &rootdpb.EnsureGuestFirewallRequest{}, rootdpb.RootHelperClient.EnsureGuestFirewall)
	return err
}

// SetGuestNodeGuard sets the node ports guests may reach on the node.
// repaired: the list was already this one and the rules had to be put back.
func (c *Client) SetGuestNodeGuard(ctx context.Context, allow []*rootdpb.NodePort) (repaired bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureSetGuestNodeGuard, &rootdpb.SetNodeGuardRequest{Allow: allow}, rootdpb.RootHelperClient.SetGuestNodeGuard)
	return resp.GetRepaired(), err
}

// SetGuestEgressFloor sets the guests' deny floor; the helper adds the
// cloud metadata endpoints itself.
func (c *Client) SetGuestEgressFloor(ctx context.Context, cidrs []string) (repaired bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureSetGuestEgressFloor, &rootdpb.SetEgressFloorRequest{Cidrs: cidrs}, rootdpb.RootHelperClient.SetGuestEgressFloor)
	return resp.GetRepaired(), err
}

// GuestRules makes one of a guest's rules present or absent, by its
// address. inserted is BLOCK_EGRESS's answer: the rule was not there yet.
func (c *Client) GuestRules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (inserted bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureGuestRules,
		&rootdpb.GuestRulesRequest{GuestIp: ip, Op: op, AllowCidrs: allow, DenyCidrs: deny}, rootdpb.RootHelperClient.GuestRules)
	return resp.GetInserted(), err
}
