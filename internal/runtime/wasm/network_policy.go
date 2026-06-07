package wasm

// DrainNetworkByteCounters implements NetworkByteCounter for the service netstats sink.
func (d *Driver) DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 } {
	if d == nil || d.net == nil {
		return nil
	}
	return d.net.DrainNetworkByteCounters()
}

// SetNetworkBlocks implements NetworkPolicySink for WASM quota enforcement.
func (d *Driver) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) {
	if d == nil || d.net == nil {
		return
	}
	d.net.SetNetworkBlocks(sandboxID, blockIngress, blockEgress)
}
