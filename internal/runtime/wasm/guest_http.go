package wasm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// GuestListenPortSyncer hot-updates wasip1 listener caps after expose_port.
type GuestListenPortSyncer interface {
	SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error
}

// SyncGuestListenPorts makes the guest's wasip1 listeners match the exposed
// HTTP ports: one listener per port, each on an ephemeral loopback port
// (syncGuestListeners). A worker from an older release keeps one listener
// for every port.
func (d *Driver) SyncGuestListenPorts(ctx context.Context, sandboxID string, ports []int) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if inst.status != models.SandboxStatusStarted {
		return nil
	}
	// One sync per sandbox at a time, from here: two exposes at once would
	// each migrate a resident sandbox, or each re-instantiate the guest.
	inst.listenSync.Lock()
	defer inst.listenSync.Unlock()
	if inst.fromResidentHost {
		if len(desiredListenPorts(ports)) == 0 {
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
	return d.syncGuestListeners(ctx, inst, client, ports)
}

// ErrGuestNotListening: the sandbox has no guest listener to take a request
// for an exposed port yet (none was started, or starting it failed). The
// HTTP gateway answers it with 503.
var ErrGuestNotListening = errors.New("wasm guest is not listening for HTTP")

// ErrGuestBusy: the sandbox already has as many exposed-port requests in
// flight as Config.GuestHTTPMaxInFlight allows. The gateway answers 503.
var ErrGuestBusy = errors.New("wasm guest has too many HTTP requests in flight")

// defaultGuestHTTPMaxInFlight is GuestHTTPMaxInFlight's default.
const defaultGuestHTTPMaxInFlight = 64

func (d *Driver) guestHTTPMaxInFlight() int32 {
	if n := d.cfg.GuestHTTPMaxInFlight; n > 0 {
		return int32(min(n, 1<<20))
	}
	return defaultGuestHTTPMaxInFlight
}

func (d *Driver) guestHTTPProxy(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	inst, err := d.instance(sandboxID)
	if err != nil {
		return err
	}
	if inst.status != models.SandboxStatusStarted {
		return fmt.Errorf("wasm sandbox %q is not started", sandboxID)
	}
	st := inst.guestListen()
	proxyPort := 0
	switch {
	case len(st.ports) > 0:
		// A worker of this release routes the exposed port to its guest's
		// own listener for it, and never dials a port it is sent.
		proxyPort = guestPort
	case st.primary > 0:
		// Port 0 asks the worker for its own listener. The exposed port is
		// never sent to a worker from an older release: it dials a port it
		// is given on the host, where any process can listen on it.
	default:
		return fmt.Errorf("%w on port %d of sandbox %q", ErrGuestNotListening, guestPort, sandboxID)
	}
	// Each request in flight holds a goroutine here and a connection to
	// the guest for as long as the guest takes: a sandbox gets only so
	// many at once.
	if n := inst.guestHTTPInFlight.Add(1); n > d.guestHTTPMaxInFlight() {
		inst.guestHTTPInFlight.Add(-1)
		return fmt.Errorf("%w (sandbox %q)", ErrGuestBusy, sandboxID)
	}
	defer inst.guestHTTPInFlight.Add(-1)
	client := d.newWorkerClient(inst.socketPath)
	if hc, ok := client.(hostDialProxyClient); ok && !st.legacy {
		// This release's worker only names its guest's listener: sandboxd
		// connects to it and relays the request itself (only root opens
		// connections to guest listeners, and no worker holds one). The
		// listener must be one of the ports this sandbox's state names.
		// The bytes go to the sandbox's usage, as the worker counted them.
		in, out := d.net.guestCounters(sandboxID)
		err := hc.ProxyHTTPDialed(sandboxID, proxyPort, d.guestListenHost(), st.listenerPorts(), in, out, w, r)
		if !errors.Is(err, worker.ErrHostDialUnsupported) {
			return err
		}
		// A worker from an older release: it dials its listener itself,
		// as it always did (it runs as root).
	}
	return client.ProxyHTTP(sandboxID, proxyPort, w, r)
}

// hostDialProxyClient is a worker client that relays a request to the
// guest's listener from sandboxd (worker.Client.ProxyHTTPDialed).
// Optional, so test fakes without it take the plain ProxyHTTP path.
type hostDialProxyClient interface {
	ProxyHTTPDialed(sandboxID string, guestPort int, host string, ports []int, in, out *atomic.Int64, w http.ResponseWriter, r *http.Request) error
}
