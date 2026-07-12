package containerd

import (
	"context"
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
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.BlockAllEgress(containerIP)
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
