package wasm

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

const guestListenReadyTimeout = 5 * time.Second

// bumpRunGeneration invalidates any in-flight guest _start goroutine after re-instantiate.
func (inst *sandboxInstance) bumpRunGeneration() uint64 {
	inst.guestServeMu.Lock()
	defer inst.guestServeMu.Unlock()
	inst.runGeneration++
	return inst.runGeneration
}

// startGuestEntryAsync runs the module entry export in the background. HTTP guests block
// inside _start; one-shot guests return quickly. Safe to call after Instantiate or SetListenPort.
func (d *Driver) startGuestEntryAsync(inst *sandboxInstance, client WorkerClient) {
	if inst == nil || client == nil {
		return
	}
	inst.guestServeMu.Lock()
	gen := inst.runGeneration
	if inst.guestServeGen == gen {
		inst.guestServeMu.Unlock()
		return
	}
	inst.guestServeGen = gen
	export := inst.entryExport
	if export == "" {
		export = "_start"
	}
	sandboxID := inst.sandboxID
	inst.guestServeMu.Unlock()

	go func() {
		_ = client.Invoke(sandboxID, export)
		inst.guestServeMu.Lock()
		if inst.guestServeGen == gen {
			inst.guestServeGen = 0
		}
		inst.guestServeMu.Unlock()
	}()
}

func (d *Driver) waitGuestListenReady(host string, port int) error {
	if port <= 0 {
		return fmt.Errorf("guest listen port not resolved")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(guestListenReadyTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			// _start enters http.Serve shortly after the wasip1 listener is bound.
			time.Sleep(100 * time.Millisecond)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("guest did not listen on %s within %s", addr, guestListenReadyTimeout)
}

// wasip1ListenPort picks the wasip1 pre-open port. Any exposed HTTP port enables an
// ephemeral bind (0 in caps); expose_port port numbers are routing keys for Caddy only.
func wasip1ListenPort(exposed []int) int {
	if len(exposed) == 0 {
		return wasmengine.WASIListenPortDisabled
	}
	return 0
}

// syncGuestListenPort hot-updates the worker listener and (re)starts the guest HTTP accept loop.
func (d *Driver) syncGuestListenPort(ctx context.Context, inst *sandboxInstance, client WorkerClient, listenPort int) error {
	if listenPort == wasmengine.WASIListenPortDisabled {
		inst.bumpRunGeneration()
		inst.resolvedListenPort = 0
		if err := client.SetListenPort(inst.sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
			return err
		}
		_ = ctx
		return nil
	}

	host := "127.0.0.1"
	inst.bumpRunGeneration()
	if err := client.SetListenPort(inst.sandboxID, listenPort, host); err != nil {
		return err
	}
	resolved := listenPort
	if listenPort == 0 {
		var err error
		resolved, err = client.ResolvedListenPort(inst.sandboxID)
		if err != nil {
			return fmt.Errorf("resolve ephemeral listen port: %w", err)
		}
		if resolved <= 0 {
			return fmt.Errorf("ephemeral listen port not resolved")
		}
	}
	inst.resolvedListenPort = resolved
	export := inst.entryExport
	if export == "" {
		export = "_start"
	}
	sandboxID := inst.sandboxID
	go func() { _ = client.Invoke(sandboxID, export) }()
	if d.waitListenReady != nil {
		return d.waitListenReady(host, resolved)
	}
	if err := d.waitGuestListenReady(host, resolved); err != nil {
		return err
	}
	// Guest _start may still be entering http.Serve after the wasip1 socket is bound.
	time.Sleep(150 * time.Millisecond)
	return nil
}
