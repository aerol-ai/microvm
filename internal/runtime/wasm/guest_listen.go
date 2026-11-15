package wasm

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"sort"
	"strconv"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
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

// wasip1ListenPort picks the single wasip1 listener of a worker from an
// older release: any exposed HTTP port enables an ephemeral bind (0 in
// caps), and every exposed port reaches it.
func wasip1ListenPort(exposed []int) int {
	if len(exposed) == 0 {
		return wasmengine.WASIListenPortDisabled
	}
	return 0
}

// desiredListenPorts is the exposed set as a worker takes it: valid ports,
// ascending, once each. The first is the primary listener's.
func desiredListenPorts(exposed []int) []int {
	seen := make(map[int]struct{}, len(exposed))
	out := make([]int, 0, len(exposed))
	for _, p := range exposed {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// guestListening reports whether a serving guest still accepts on port. A
// var so tests need no real listener.
var guestListening = func(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// guestListenState is the driver's copy of a sandbox's guest listeners.
type guestListenState struct {
	// primary is the host port of the primary listener (the lowest exposed
	// port's, or the one listener of an older worker); 0 for none.
	primary int
	// ports maps each exposed port to its listener's host port, from a
	// worker that routes per port. Empty for an older worker, which has one
	// listener for every port and must never be sent a port number.
	ports map[int]int
	// legacy marks a worker that predates per-port listeners.
	legacy bool
	// engine is the engine the worker serves HTTP on, when it said.
	engine string
}

func (inst *sandboxInstance) guestListen() guestListenState {
	inst.listenMu.Lock()
	defer inst.listenMu.Unlock()
	return guestListenState{
		primary: inst.resolvedListenPort,
		ports:   maps.Clone(inst.listenPorts),
		legacy:  inst.legacyListen,
		engine:  inst.listenEngine,
	}
}

// setGuestListen stores st and reports whether it changed.
func (inst *sandboxInstance) setGuestListen(st guestListenState) bool {
	inst.listenMu.Lock()
	defer inst.listenMu.Unlock()
	changed := inst.resolvedListenPort != st.primary || !maps.Equal(inst.listenPorts, st.ports) ||
		inst.legacyListen != st.legacy || inst.listenEngine != st.engine
	inst.resolvedListenPort = st.primary
	inst.listenPorts = maps.Clone(st.ports)
	inst.legacyListen = st.legacy
	inst.listenEngine = st.engine
	return changed
}

// resetGuestListen forgets the listeners after a fresh instantiation,
// which starts the guest without any, possibly on a new worker.
func (inst *sandboxInstance) resetGuestListen() {
	inst.setGuestListen(guestListenState{})
}

// listenPortsClient is a worker client that can give a guest one listener
// per exposed port (#177). Optional, so a client without it takes the
// single-listener path.
type listenPortsClient interface {
	SetListenPorts(sandboxID string, ports []int, host string) (worker.ListenPorts, error)
	ListenPorts(sandboxID string) (worker.ListenPorts, error)
}

// syncGuestListeners makes the guest's listeners match the exposed ports.
// The caller holds inst.listenSync.
func (d *Driver) syncGuestListeners(ctx context.Context, inst *sandboxInstance, client WorkerClient, exposed []int) error {
	ports := desiredListenPorts(exposed)
	if lc, ok := client.(listenPortsClient); ok && !inst.guestListen().legacy {
		err := d.syncListenPorts(ctx, inst, client, lc, ports)
		if !errors.Is(err, worker.ErrListenPortsUnsupported) {
			return err
		}
		// An adopted worker from an older release: it keeps one listener
		// for every exposed port, as it always did.
		st := inst.guestListen()
		st.legacy = true
		inst.setGuestListen(st)
	}
	return d.syncGuestListenPort(ctx, inst, client, wasip1ListenPort(ports))
}

// syncListenPorts gives a worker of this release one guest listener per
// exposed port.
//
//   - Every exposed port already has its listener and the guest still holds
//     them: nothing to do. Reconcile syncs every started sandbox, and a
//     re-instantiation restarts a serving guest (dropping its memory and
//     any request in flight).
//   - A new port: one re-instantiation with the full set, the same restart
//     the first expose always cost.
//   - A port no longer exposed keeps its listener until the next restart:
//     the gateway's allowed-port check answers 403 for it.
//   - No port: the listeners go, only if the guest has any (else the
//     re-instantiation would restart the guest, and end an exec it runs,
//     on every reconcile pass).
func (d *Driver) syncListenPorts(ctx context.Context, inst *sandboxInstance, client WorkerClient, lc listenPortsClient, ports []int) error {
	live, err := lc.ListenPorts(inst.sandboxID)
	if err != nil {
		return err
	}
	nothingToClose := len(ports) == 0 && live.Primary <= 0 && len(live.Ports) == 0
	allServed := len(ports) > 0 && live.Primary > 0 && coversPorts(live.Ports, ports)
	if nothingToClose || allServed {
		d.noteGuestListeners(inst, live)
		return nil
	}
	inst.bumpRunGeneration()
	host := ""
	if len(ports) > 0 {
		host = wasmLoopbackIP
	}
	got, err := lc.SetListenPorts(inst.sandboxID, ports, host)
	if err != nil {
		return err
	}
	if len(ports) > 0 && got.Primary <= 0 {
		return fmt.Errorf("guest listeners for ports %v were not bound", ports)
	}
	d.noteGuestListeners(inst, got)
	if len(ports) == 0 {
		return nil
	}
	return d.serveGuest(ctx, inst, client, wasmLoopbackIP, got.Primary)
}

// coversPorts reports whether have has a listener for every port of want.
func coversPorts(have map[int]int, want []int) bool {
	for _, p := range want {
		if have[p] <= 0 {
			return false
		}
	}
	return true
}

// noteGuestListeners stores a worker's listener report, writes the record
// when it changed and says once when the worker serves HTTP on another
// engine than the one configured (#175).
func (d *Driver) noteGuestListeners(inst *sandboxInstance, got worker.ListenPorts) {
	prev := inst.guestListen()
	if !inst.setGuestListen(guestListenState{primary: got.Primary, ports: got.Ports, engine: got.Engine}) {
		return
	}
	if got.FallbackFrom != "" && prev.engine != got.Engine && d.logger != nil {
		d.logger.Info("wasm sandbox serves HTTP on another engine: the configured one cannot pre-open a guest listener",
			"sandbox_id", inst.sandboxID, "engine", got.Engine, "configured_engine", got.FallbackFrom)
	}
	d.recordInstance(inst)
}

// serveGuest starts the guest's entry export (it blocks in its accept
// loop) and waits until the primary listener answers.
func (d *Driver) serveGuest(_ context.Context, inst *sandboxInstance, client WorkerClient, host string, primary int) error {
	export := inst.entryExport
	if export == "" {
		export = "_start"
	}
	sandboxID := inst.sandboxID
	go func() { _ = client.Invoke(sandboxID, export) }()
	if d.waitListenReady != nil {
		return d.waitListenReady(host, primary)
	}
	if err := d.waitGuestListenReady(host, primary); err != nil {
		return err
	}
	// Guest _start may still be entering http.Serve after the wasip1 socket is bound.
	time.Sleep(150 * time.Millisecond)
	return nil
}

// syncGuestListenPort hot-updates the one listener of a worker from an
// older release and (re)starts the guest HTTP accept loop.
//
// A guest that already serves on its port is left alone. Every reconcile
// pass syncs the ports of every started sandbox, and SetListenPort
// re-instantiates the guest: before, that restarted a serving HTTP guest on
// every pass (dropping its memory and any request in flight), and it would
// restart one a restarted sandboxd had just taken over. A guest that died
// (an exec replaced it, a crash) answers no dial and is started again here,
// as before.
func (d *Driver) syncGuestListenPort(ctx context.Context, inst *sandboxInstance, client WorkerClient, listenPort int) error {
	st := inst.guestListen()
	if listenPort == wasmengine.WASIListenPortDisabled {
		inst.bumpRunGeneration()
		inst.setGuestListen(guestListenState{legacy: st.legacy})
		if err := client.SetListenPort(inst.sandboxID, wasmengine.WASIListenPortDisabled, ""); err != nil {
			return err
		}
		d.recordInstance(inst)
		return nil
	}
	if st.primary > 0 && guestListening(st.primary) {
		return nil
	}

	host := wasmLoopbackIP
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
	inst.setGuestListen(guestListenState{primary: resolved, legacy: st.legacy})
	d.recordInstance(inst)
	return d.serveGuest(ctx, inst, client, host, resolved)
}
