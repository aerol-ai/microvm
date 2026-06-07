package wasm

import (
	"github.com/aerol-ai/microvm/pkg/models"
)

// DrainNetworkByteCounters implements NetworkByteCounter for the service netstats sink.
func (d *Driver) DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 } {
	if d == nil {
		return nil
	}
	out := make(map[string]struct{ BytesIn, BytesOut int64 })
	if d.net != nil {
		for id, u := range d.net.DrainNetworkByteCounters() {
			out[id] = u
		}
	}
	d.mu.Lock()
	instances := make([]*sandboxInstance, 0, len(d.byID))
	for _, inst := range d.byID {
		if inst != nil && inst.status == models.SandboxStatusStarted && inst.socketPath != "" {
			instances = append(instances, inst)
		}
	}
	d.mu.Unlock()
	for _, inst := range instances {
		client := d.newWorkerClient(inst.socketPath)
		in, workerOut, err := client.NetstatsTick(inst.sandboxID)
		if err != nil {
			if d.logger != nil {
				d.logger.Debug("wasm worker netstats tick failed", "sandbox_id", inst.sandboxID, "error", err)
			}
			continue
		}
		if in == 0 && workerOut == 0 {
			continue
		}
		cur := out[inst.sandboxID]
		cur.BytesIn += in
		cur.BytesOut += workerOut
		out[inst.sandboxID] = cur
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetNetworkBlocks implements NetworkPolicySink for WASM quota enforcement.
func (d *Driver) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) {
	if d == nil {
		return
	}
	if d.net != nil {
		d.net.SetNetworkBlocks(sandboxID, blockIngress, blockEgress)
	}
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil || inst.status != models.SandboxStatusStarted || inst.socketPath == "" {
		return
	}
	if err := d.newWorkerClient(inst.socketPath).SetNetworkBlocks(sandboxID, blockIngress, blockEgress); err != nil && d.logger != nil {
		d.logger.Debug("wasm worker set network blocks failed", "sandbox_id", sandboxID, "error", err)
	}
}
