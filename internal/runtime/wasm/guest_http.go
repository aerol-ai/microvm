package wasm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
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
	listenPort := wasip1ListenPort(ports)
	if inst.fromResidentHost {
		if listenPort == wasmengine.WASIListenPortDisabled {
			// Resident sandboxes are non-listen by construction — there is no
			// listener to disable, so an unexpose is a no-op (do not send a
			// listener op to the shared host, which rejects them).
			return nil
		}
		// expose_port needs a wasip1 listener the shared resident host cannot
		// provide; migrate this sandbox onto a dedicated cold worker first
		// (PR-B / plan D4-A), then install the listener on it below.
		if err := d.migrateResidentToCold(ctx, inst); err != nil {
			return fmt.Errorf("migrate resident sandbox %q for expose: %w", sandboxID, err)
		}
	}
	client := d.newWorkerClient(inst.socketPath)
	return d.syncGuestListenPort(ctx, inst, client, listenPort)
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
