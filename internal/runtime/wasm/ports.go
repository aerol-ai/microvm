package wasm

import "context"

func (d *Driver) EnsureHTTPListener(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	if d.net == nil {
		d.net = newNetworkGateway()
	}
	return d.net.EnsureHTTPListener(ctx, sandboxID, guestPort)
}

func (d *Driver) ReleaseHTTPListener(sandboxID string, guestPort int) {
	if d.net == nil {
		return
	}
	d.net.ReleaseHTTPListener(sandboxID, guestPort)
}

func (d *Driver) SyncAllowedPorts(sandboxID string, ports []int) {
	if d.net == nil {
		return
	}
	d.net.SyncAllowedPorts(sandboxID, ports)
}
