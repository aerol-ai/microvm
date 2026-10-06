package firecracker

import (
	"context"
	"errors"
	"net/netip"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Egress for Firecracker guests (plans/egress-domain-filtering.md Phase 4).
// A guest sits on a routed /30 behind its TAP device, so its traffic is
// forwarded by the host like a container's: the same per-IP host firewall
// the container engines use (pkg/docker/netrules, on its own chain with
// FORWARD accepts for the TAP subnet) keys block-all, CIDR allow/deny, the
// quota blocks and the fail-closed hold by the guest IP. The guest can't
// claim another slot's IP: rp_filter on its TAP drops a forged source.

// NetRules is the host firewall the driver keys by guest IP
// (*netrules.Manager).
type NetRules interface {
	BlockAllEgress(ip string) error
	ClearBlockAllEgress(ip string) error
	ApplyEgressPolicy(ip string, allow, deny []string) error
	ClearEgressPolicy(ip string, allow, deny []string) error
	BlockAllIngress(ip string) error
	ClearBlockAllIngress(ip string) error
	HoldEgress(ip string) error
	ClearHoldEgress(ip string) error
	SetFloor(subnet netip.Prefix, cidrs []netip.Prefix) error
}

// SetNetRules wires the host firewall; without one, every network-rule
// method reports ErrRuntimeNotImplemented and egress options stay refused.
func (d *Driver) SetNetRules(r NetRules) { d.netRules = r }

// SetTapSubnet records the TAP pool's base CIDR, which the node-wide deny
// floor is scoped to.
func (d *Driver) SetTapSubnet(p netip.Prefix) { d.tapSubnet = p }

// NetRulesEnabled reports whether the driver can enforce egress policies.
func (d *Driver) NetRulesEnabled() bool { return d.netRules != nil }

func (d *Driver) rules(op string) (NetRules, error) {
	if d.netRules == nil {
		return nil, methodNotImplemented(op)
	}
	return d.netRules, nil
}

// applyCreateEgress installs a create's egress policy on the guest IP
// before the VM runs, so it never runs unfiltered. Gateway-mode creates
// arrive as block-all (the driver-facing copy); the gateway attach lifts
// it.
func (d *Driver) applyCreateEgress(guestIP string, req models.CreateSandboxRequest) error {
	if !req.NetworkBlockAll && len(req.NetworkAllowOut) == 0 && len(req.NetworkDenyOut) == 0 {
		return nil
	}
	r, err := d.rules("egress policy")
	if err != nil {
		return err
	}
	if req.NetworkBlockAll {
		return r.BlockAllEgress(guestIP)
	}
	return r.ApplyEgressPolicy(guestIP, req.NetworkAllowOut, req.NetworkDenyOut)
}

// clearGuestRules removes every rule keyed by a guest IP, on destroy and on
// a failed create, so a recycled slot starts clean.
func (d *Driver) clearGuestRules(guestIP string, allow, deny []string) error {
	if d.netRules == nil || guestIP == "" {
		return nil
	}
	return errors.Join(
		d.netRules.ClearBlockAllEgress(guestIP),
		d.netRules.ClearBlockAllIngress(guestIP),
		d.netRules.ClearHoldEgress(guestIP),
		d.netRules.ClearEgressPolicy(guestIP, allow, deny),
	)
}

// ClearNetworkRules releases the per-IP block rules, as the Docker driver
// does.
func (d *Driver) ClearNetworkRules(ip string) error {
	r, err := d.rules("ClearNetworkRules")
	if err != nil {
		return err
	}
	return errors.Join(r.ClearBlockAllEgress(ip), r.ClearBlockAllIngress(ip))
}

func (d *Driver) ApplyNetworkBlockAll(ip string) error {
	r, err := d.rules("ApplyNetworkBlockAll")
	if err != nil {
		return err
	}
	return r.BlockAllEgress(ip)
}

func (d *Driver) ApplyEgressPolicy(ip string, allow, deny []string) error {
	r, err := d.rules("ApplyEgressPolicy")
	if err != nil {
		return err
	}
	return r.ApplyEgressPolicy(ip, allow, deny)
}

func (d *Driver) ClearEgressPolicy(ip string, allow, deny []string) error {
	r, err := d.rules("ClearEgressPolicy")
	if err != nil {
		return err
	}
	return r.ClearEgressPolicy(ip, allow, deny)
}

func (d *Driver) ApplyNetworkBlockIngress(ip string) error {
	r, err := d.rules("ApplyNetworkBlockIngress")
	if err != nil {
		return err
	}
	return r.BlockAllIngress(ip)
}

func (d *Driver) ClearNetworkBlockIngress(ip string) error {
	r, err := d.rules("ClearNetworkBlockIngress")
	if err != nil {
		return err
	}
	return r.ClearBlockAllIngress(ip)
}

func (d *Driver) ClearNetworkBlockEgress(ip string) error {
	r, err := d.rules("ClearNetworkBlockEgress")
	if err != nil {
		return err
	}
	return r.ClearBlockAllEgress(ip)
}

// ApplyEgressHold implements runtime.EgressHolder: the fail-closed hold
// (CEO D16) for a gateway-mode guest.
func (d *Driver) ApplyEgressHold(ip string) error {
	r, err := d.rules("ApplyEgressHold")
	if err != nil {
		return err
	}
	return r.HoldEgress(ip)
}

// ClearEgressHold implements runtime.EgressHolder.
func (d *Driver) ClearEgressHold(ip string) error {
	r, err := d.rules("ClearEgressHold")
	if err != nil {
		return err
	}
	return r.ClearHoldEgress(ip)
}

// SetEgressFloor implements runtime.EgressFloorSetter for the TAP subnet
// (§5.10 PC-2).
func (d *Driver) SetEgressFloor(_ context.Context, cidrs []netip.Prefix) error {
	r, err := d.rules("SetEgressFloor")
	if err != nil {
		return err
	}
	if !d.tapSubnet.IsValid() {
		return nil
	}
	return r.SetFloor(d.tapSubnet, cidrs)
}
