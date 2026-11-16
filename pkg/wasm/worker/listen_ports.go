package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Per-port guest listeners (#177): set_listen_ports gives the guest one
// pre-opened listener per exposed port, and listen_ports reports them. Both
// answer with listenPortsPayload.

// setListenPortsPayload asks for one listener per exposed port. No ports
// turns the listeners off.
type setListenPortsPayload struct {
	Ports []int  `json:"ports,omitempty"`
	Host  string `json:"host,omitempty"`
}

// listenPortsPayload is the listeners of the instance the worker runs now.
type listenPortsPayload struct {
	// Ports maps each exposed port to its listener's host port.
	Ports map[int]int `json:"ports,omitempty"`
	// Primary is the host port of the lowest port's listener: the one
	// AEROL_WASM_LISTEN_FD names, which serves every port the guest does
	// not accept on itself. 0 when the instance has no live listener.
	Primary int `json:"primary,omitempty"`
	// Engine is the engine the instance runs on. FallbackFrom is the
	// configured engine the worker left for this sandbox to serve HTTP on
	// one that can (listen_engine.go): empty while it runs the configured
	// one, which is always so on wazero and, on Linux and macOS, on
	// wasmtime too (#175).
	Engine       string `json:"engine,omitempty"`
	FallbackFrom string `json:"fallback_from,omitempty"`
}

// ListenPorts is a worker's report of its guest's listeners.
type ListenPorts struct {
	// Ports maps each exposed port to its listener's host port. Empty from
	// an engine that keeps one listener for every port.
	Ports map[int]int
	// Primary is the host port of the listener every other port falls back
	// to; 0 when the guest has no live listener.
	Primary      int
	Engine       string
	FallbackFrom string
}

// ErrListenPortsUnsupported: the worker predates per-port listeners. An
// adopted per-sandbox worker from an older release answers a message it
// does not know with an empty invoke_result, and a resident host answers
// "not supported in resident-host mode". Such a worker keeps its one
// listener, set with SetListenPort.
var ErrListenPortsUnsupported = errors.New("wasm worker does not support per-port listeners")

// SetListenPorts gives the guest one listener per port (re-instantiating
// it) and returns the listeners it got. No ports turns them off.
func (c *Client) SetListenPorts(sandboxID string, ports []int, host string) (ListenPorts, error) {
	body, err := encodePayload(setListenPortsPayload{Ports: ports, Host: host})
	if err != nil {
		return ListenPorts{}, err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgSetListenPorts, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return ListenPorts{}, err
	}
	return decodeListenPortsReply(reply)
}

// ListenPorts reports the guest's live listeners without changing them.
func (c *Client) ListenPorts(sandboxID string) (ListenPorts, error) {
	reply, err := c.roundTrip(Envelope{Type: MsgListenPorts, SandboxID: sandboxID})
	if err != nil {
		return ListenPorts{}, err
	}
	return decodeListenPortsReply(reply)
}

func decodeListenPortsReply(reply Envelope) (ListenPorts, error) {
	switch reply.Type {
	case MsgOK:
	case MsgInvokeResult:
		return ListenPorts{}, ErrListenPortsUnsupported
	case MsgError:
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return ListenPorts{}, err
		}
		if strings.Contains(p.Message, "not supported in resident-host mode") {
			return ListenPorts{}, fmt.Errorf("%w: %s", ErrListenPortsUnsupported, p.Message)
		}
		return ListenPorts{}, errors.New(p.Message)
	default:
		return ListenPorts{}, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p listenPortsPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return ListenPorts{}, err
	}
	return ListenPorts{Ports: p.Ports, Primary: p.Primary, Engine: p.Engine, FallbackFrom: p.FallbackFrom}, nil
}

// serveListenPorts answers set_listen_ports and listen_ports on conn. It
// returns only a write error, like the cases of Serve.
func (s *Server) serveListenPorts(ctx context.Context, conn net.Conn, env Envelope) error {
	var (
		report listenPortsPayload
		err    error
	)
	if env.Type == MsgSetListenPorts {
		report, err = s.setListenPorts(ctx, env)
	} else {
		report = s.listenReport()
	}
	if err != nil {
		body, encErr := encodePayload(errorPayload{Message: err.Error()})
		if encErr != nil {
			return encErr
		}
		return writeFrame(conn, Envelope{Type: MsgError, SandboxID: env.SandboxID, Payload: body})
	}
	body, err := encodePayload(report)
	if err != nil {
		return err
	}
	return writeFrame(conn, Envelope{Type: MsgOK, SandboxID: env.SandboxID, Payload: body})
}

// normalizeListenPorts is the requested set as the engine takes it:
// ascending, once each. A port outside 1-65535 fails the request.
func normalizeListenPorts(ports []int) ([]int, error) {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid listen port %d", p)
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// setListenPorts re-instantiates the guest with one listener per port (or
// none) and reports what it got. Every listener binds an ephemeral host
// port: the driver routes by exposed port through the worker and never
// needs a host port to stay the same across a re-instantiation.
func (s *Server) setListenPorts(ctx context.Context, env Envelope) (listenPortsPayload, error) {
	var p setListenPortsPayload
	if err := decodePayload(env.Payload, &p); err != nil {
		return listenPortsPayload{}, err
	}
	ports, err := normalizeListenPorts(p.Ports)
	if err != nil {
		return listenPortsPayload{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.eng == nil {
		return listenPortsPayload{}, fmt.Errorf("engine not loaded")
	}
	if len(ports) > 0 {
		if err := s.ensureListenEngineLocked(ctx, env.SandboxID); err != nil {
			return listenPortsPayload{}, err
		}
	}
	s.bindNetworkHook(env.SandboxID)
	next := s.lastCaps
	next.WASIListenPort = wasmengine.WASIListenPortDisabled
	next.WASIListeners = nil
	for _, port := range ports {
		next.WASIListeners = append(next.WASIListeners, wasmengine.WASIListener{GuestPort: port})
	}
	if host := strings.TrimSpace(p.Host); host != "" {
		next.WASIListenHost = host
	}
	if err := s.eng.Instantiate(ctx, next); err != nil {
		return listenPortsPayload{}, err
	}
	s.lastCaps = next
	s.syncResolvedListeners(&s.lastCaps)
	return s.listenReportLocked(), nil
}

// syncResolvedListeners copies the host ports the engine bound into caps,
// so a later re-instantiation from lastCaps (set_capability) binds the same
// ones, as syncResolvedListenPort does for the single listener.
func (s *Server) syncResolvedListeners(caps *wasmengine.Capabilities) {
	me, ok := s.eng.(wasmengine.MultiListenEngine)
	if !ok || len(caps.WASIListeners) == 0 {
		return
	}
	bound := make(map[int]int)
	for _, l := range me.ResolvedListeners() {
		bound[l.GuestPort] = l.HostPort
	}
	// A copy: the caps the engine was given share the slice.
	caps.WASIListeners = append([]wasmengine.WASIListener(nil), caps.WASIListeners...)
	for i := range caps.WASIListeners {
		if port := bound[caps.WASIListeners[i].GuestPort]; port > 0 {
			caps.WASIListeners[i].HostPort = port
		}
	}
}

func (s *Server) listenReport() listenPortsPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenReportLocked()
}

// listenReportLocked reports the live listeners of the running instance.
// The caller holds mu.
func (s *Server) listenReportLocked() listenPortsPayload {
	report := listenPortsPayload{Engine: s.engineNameLocked(), FallbackFrom: s.loaded.fallbackFrom}
	if s.eng == nil {
		return report
	}
	if me, ok := s.eng.(wasmengine.MultiListenEngine); ok {
		for _, l := range me.ResolvedListeners() {
			if report.Primary == 0 {
				report.Primary = l.HostPort
			}
			if l.GuestPort > 0 {
				if report.Ports == nil {
					report.Ports = make(map[int]int)
				}
				report.Ports[l.GuestPort] = l.HostPort
			}
		}
		return report
	}
	if port, ok := s.eng.ResolvedListenPort(); ok && port > 0 {
		report.Primary = port
	}
	return report
}

// listenerFor picks the host port a request on exposed port guestPort goes
// to: that port's own listener once the guest has accepted on it, else the
// primary (lowest) listener, else 0 (none). A guest written for one
// listener reads only AEROL_WASM_LISTEN_FD and never accepts on the
// others, so it keeps serving every exposed port on the primary, as
// before. A request for a port whose listener the guest has not reached
// yet, early in its start, goes to the primary too.
//
// Only a listener the engine bound for the running instance and still
// reports live is ever returned; guestPort itself is a name, never an
// address (see guestHTTPTarget).
func listenerFor(eng wasmengine.Engine, guestPort int) int {
	if eng == nil {
		return 0
	}
	me, ok := eng.(wasmengine.MultiListenEngine)
	if !ok {
		if port, ok := eng.ResolvedListenPort(); ok {
			return port
		}
		return 0
	}
	live := me.ResolvedListeners()
	if len(live) == 0 {
		return 0
	}
	if guestPort > 0 {
		for _, l := range live {
			if l.GuestPort == guestPort && me.ListenerAccepted(guestPort) {
				return l.HostPort
			}
		}
	}
	return live[0].HostPort
}
