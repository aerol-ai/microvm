package containerd

import (
	"context"
	"fmt"
	"net/netip"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

func (d *Driver) PushAllowedPorts(ctx context.Context, containerIP, toolboxToken string, ports []int) error {
	_ = ctx
	_ = toolboxToken
	_ = ports
	// Toolbox allowlist push is toolboxd-local today; docker path is best-effort HTTP.
	return nil
}

func (d *Driver) ClearNetworkRules(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	_ = d.networkRules.ClearBlockAllEgress(containerIP)
	return d.networkRules.ClearBlockAllIngress(containerIP)
}

// hasCreateNetRules reports whether a create asks for host firewall rules.
func hasCreateNetRules(req models.CreateSandboxRequest) bool {
	return req.NetworkBlockAll || len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0
}

// applyCreateNetRules installs a create's rules on ip: block-all (which a
// hostname-filtered create arrives as, the gateway attach lifting it), or
// the CIDR lists. A create without either installs nothing.
func (d *Driver) applyCreateNetRules(ip string, req models.CreateSandboxRequest) error {
	if req.NetworkBlockAll {
		if err := d.ApplyNetworkBlockAll(ip); err != nil {
			return fmt.Errorf("apply network block: %w", err)
		}
	}
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := d.ApplyEgressPolicy(ip, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply egress policy: %w", err)
		}
	}
	return nil
}

// clearCreateNetRules removes what applyCreateNetRules may have installed
// on ip, a partial install included. Best effort, as Destroy's clears are.
func (d *Driver) clearCreateNetRules(ip string, req models.CreateSandboxRequest) {
	if !hasCreateNetRules(req) {
		return
	}
	_ = d.ClearNetworkRules(ip)
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		_ = d.ClearEgressPolicy(ip, req.NetworkAllowOut, req.NetworkDenyOut)
	}
}

func (d *Driver) ApplyNetworkBlockAll(containerIP string) error {
	_, err := d.ApplyNetworkBlockAllReport(containerIP)
	return err
}

// ApplyNetworkBlockAllReport implements runtime.NetworkBlockReporter. See the
// docker client's copy for why reconcile needs the inserted flag.
func (d *Driver) ApplyNetworkBlockAllReport(containerIP string) (bool, error) {
	if d.networkRules == nil {
		return false, nil
	}
	return d.networkRules.BlockAllEgressReport(containerIP)
}

func (d *Driver) ApplyNetworkBlockIngress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.BlockAllIngress(containerIP)
}

func (d *Driver) ClearNetworkBlockIngress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearBlockAllIngress(containerIP)
}

func (d *Driver) ClearNetworkBlockEgress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearBlockAllEgress(containerIP)
}

func (d *Driver) ApplyEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ApplyEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

func (d *Driver) ClearEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

var (
	_ sbruntime.EgressHolder     = (*Driver)(nil)
	_ sbruntime.NetRulesReporter = (*Driver)(nil)
)

// NetRulesEnabled reports whether the AEROLVM-USER rules are live. A nil or
// disabled manager (network rules off, or not Linux) makes every rule method
// here a no-op.
func (d *Driver) NetRulesEnabled() bool { return d.networkRules.Enabled() }

// ApplyEgressHold installs the fail-closed hold DROP (CEO D16).
func (d *Driver) ApplyEgressHold(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.HoldEgress(containerIP)
}

// ClearEgressHold lifts the hold after a successful gateway attach.
func (d *Driver) ClearEgressHold(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearHoldEgress(containerIP)
}

// SetEgressFloor installs the operator's node-wide deny floor for the CNI
// bridge subnet (§5.10 PC-2).
func (d *Driver) SetEgressFloor(_ context.Context, cidrs []netip.Prefix) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.SetFloor(d.networkRules.BridgeSubnet(), cidrs)
}
