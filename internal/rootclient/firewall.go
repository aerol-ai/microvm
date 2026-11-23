package rootclient

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The helper's firewall calls (M1 PR 5, internal/rootd firewall.go and
// sandbox.go): the host's chains and IPv6 fence, the node guard and the
// deny floor, one sandbox's rules, and a create's and a teardown's root
// work in one call each. The agent sends typed values; the helper checks
// each and renders every rule itself.

// EnsureHostFirewall has the helper make sure of the host's part: the
// forwarding sysctls, the sandboxes' chains, the block sets and the IPv6
// fence. fence is why the fence is not in place yet, or "" once it is; the
// agent holds creates while it is not (service.ErrIPv6FenceNotReady).
func (c *Client) EnsureHostFirewall(ctx context.Context) (fence string, err error) {
	f, err := c.EnsureHostFences(ctx)
	return f.Containerd, err
}

// Fences is the IPv6 fence's state, as the helper's host step answers it:
// Containerd is why the fence does not cover the sandboxes' bridge yet,
// "" once it does; Firecracker is the same for the guests' TAPs, and
// counts only when CoversFirecracker says the fence takes them in (a
// helper that serves Firecracker, M1 PR 14). An older helper fences the
// bridge alone.
type Fences struct {
	Containerd        string
	Firecracker       string
	CoversFirecracker bool
}

// EnsureHostFences is EnsureHostFirewall with the fence's state on the
// Firecracker TAPs too.
func (c *Client) EnsureHostFences(ctx context.Context) (Fences, error) {
	resp, err := call(ctx, c, rootdpb.FeatureEnsureHost, &rootdpb.EnsureHostRequest{}, rootdpb.RootHelperClient.EnsureHost)
	return Fences{Containerd: resp.GetIpv6FenceError(), Firecracker: resp.GetFirecrackerIpv6FenceError(),
		CoversFirecracker: resp.GetFencesFirecracker()}, err
}

// SetNodeGuard sets the node ports sandboxes may reach on the node; every
// other port on the node is closed to them. repaired: the list was already
// this one and the rules had to be put back.
func (c *Client) SetNodeGuard(ctx context.Context, allow []*rootdpb.NodePort) (repaired bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureSetNodeGuard, &rootdpb.SetNodeGuardRequest{Allow: allow}, rootdpb.RootHelperClient.SetNodeGuard)
	return resp.GetRepaired(), err
}

// SetEgressFloor sets the node's own deny floor; the helper adds the
// floor no setting can take off (the cloud metadata endpoints) itself.
func (c *Client) SetEgressFloor(ctx context.Context, cidrs []string) (repaired bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureSetEgressFloor, &rootdpb.SetEgressFloorRequest{Cidrs: cidrs}, rootdpb.RootHelperClient.SetEgressFloor)
	return resp.GetRepaired(), err
}

// SandboxRules makes one of a sandbox's rules present or absent, by its
// address. inserted is BLOCK_EGRESS's answer: the rule was not there yet.
func (c *Client) SandboxRules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (inserted bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureSandboxRules,
		&rootdpb.SandboxRulesRequest{ContainerIp: ip, Op: op, AllowCidrs: allow, DenyCidrs: deny}, rootdpb.RootHelperClient.SandboxRules)
	return resp.GetInserted(), err
}

// PrepareSandbox is a create's root work in one call: the parts the
// request lists, each of which the helper must have said it serves. A
// part the helper lacks fails the call here, before it is sent, as one
// it lacks would (UnsupportedError): a create never runs without a part
// it needs.
func (c *Client) PrepareSandbox(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	if err := c.requireParts(ctx, rootdpb.FeaturePrepareSandbox, req.GetParts()); err != nil {
		return nil, err
	}
	return call(ctx, c, rootdpb.FeaturePrepareSandbox, req, rootdpb.RootHelperClient.PrepareSandbox)
}

// ReleaseSandbox is a teardown's root work in one call, by part, as
// PrepareSandbox.
func (c *Client) ReleaseSandbox(ctx context.Context, req *rootdpb.ReleaseSandboxRequest) error {
	if err := c.requireParts(ctx, rootdpb.FeatureReleaseSandbox, req.GetParts()); err != nil {
		return err
	}
	_, err := call(ctx, c, rootdpb.FeatureReleaseSandbox, req, rootdpb.RootHelperClient.ReleaseSandbox)
	return err
}

// Parts says which parts of PrepareSandbox and ReleaseSandbox the helper
// serves, connecting first if needed.
func (c *Client) Parts(ctx context.Context) ([]string, error) {
	s, err := c.require(ctx, rootdpb.FeaturePrepareSandbox)
	if err != nil {
		return nil, err
	}
	return s.info.Parts, nil
}

// requireParts checks that the helper serves feature and every part in
// parts. A helper that lacks one is asked again once per connection, as
// require does for a call: the connection may reach a newer one now.
func (c *Client) requireParts(ctx context.Context, feature string, parts []string) error {
	s, err := c.require(ctx, feature)
	if err != nil {
		return err
	}
	missing := func(info Info) string {
		for _, p := range parts {
			if !info.HasPart(p) {
				return p
			}
		}
		return ""
	}
	p := missing(s.info)
	if p == "" {
		return nil
	}
	if s.gen != c.dials.Load() || s.stale.Load() {
		if err := c.handshake(ctx, s); err != nil {
			return err
		}
		if s = c.sess.Load(); s == nil {
			return c.noSession()
		}
		if p = missing(s.info); p == "" {
			return nil
		}
	}
	return &UnsupportedError{Feature: fmt.Sprintf("%s part %q", feature, p), Helper: s.info}
}
