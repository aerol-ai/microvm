package wasm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/models"
)

// GuestListenPortSyncer hot-updates wasip1 listener caps after expose_port.
type GuestListenPortSyncer interface {
	SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error
}

// SyncGuestListenPorts enables or disables the guest wasip1 listener to match
// exposed HTTP ports. When multiple ports are exposed, the lowest port wins.
// Port 0 requests an ephemeral guest bind; the resolved host port is stored on
// the instance and ProxyHTTP dials via guestPort=0.
func (d *Driver) SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if inst.status != models.SandboxStatusStarted {
		return nil
	}
	client := d.newWorkerClient(inst.socketPath)
	return d.syncGuestListenPort(ctx, inst, client, wasip1ListenPort(ports))
}

func (d *Driver) guestHTTPProxy(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if inst.status != models.SandboxStatusStarted {
		return fmt.Errorf("wasm sandbox %q is not started", sandboxID)
	}
	client := d.newWorkerClient(inst.socketPath)
	// Ephemeral wasip1 guests listen on resolvedListenPort; ProxyHTTP(0) dials caps.
	proxyPort := guestPort
	if inst.resolvedListenPort > 0 {
		proxyPort = 0
	}
	return client.ProxyHTTP(sandboxID, proxyPort, w, r)
}
