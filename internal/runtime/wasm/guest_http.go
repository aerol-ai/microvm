package wasm

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// GuestListenPortSyncer hot-updates wasip1 listener caps after expose_port.
type GuestListenPortSyncer interface {
	SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error
}

// SyncGuestListenPorts enables or disables the guest wasip1 listener to match
// exposed HTTP ports. When multiple ports are exposed, the lowest port wins.
func (d *Driver) SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if inst.status != models.SandboxStatusStarted {
		return nil
	}
	listenPort := wasmengine.WASIListenPortDisabled
	if len(ports) > 0 {
		sorted := append([]int(nil), ports...)
		sort.Ints(sorted)
		listenPort = sorted[0]
	}
	client := d.newWorkerClient(inst.socketPath)
	return client.SetListenPort(sandboxID, listenPort, "127.0.0.1")
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
	return client.ProxyHTTP(sandboxID, guestPort, w, r)
}
