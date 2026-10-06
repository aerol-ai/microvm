package containerd

import (
	"context"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
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

var _ sbruntime.EgressHolder = (*Driver)(nil)

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
