package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ServerHooks connects the UDS server to the rest of the gateway process.
// Nil hooks report the feature as unavailable.
type ServerHooks struct {
	// SetBridges (re)binds the DNS and proxy listeners on the given bridges.
	SetBridges func([]Bridge) error
	// Probe opens or closes a self-test window (T41).
	Probe func(ProbeRequest) (ProbeResult, error)
	// Listeners lists the bound listener addresses for Ready.
	Listeners func() []string
	// Learned returns a sandbox's learn-mode recording (Phase 2).
	Learned func(id string) (json.RawMessage, error)
	// ForgetLearned discards a destroyed sandbox's recording.
	ForgetLearned func(id string) error
	// Changed is called after any state change so the snapshot can be saved.
	Changed func()
	// NodeControl replaces the control endpoints of the node-wide guard.
	NodeControl func([]netip.AddrPort) error
}

// PeerCheck vets a new UDS connection (SO_PEERCRED, CEO D22).
type PeerCheck func(net.Conn) error

// Server serves the gateway protocol on a UDS.
type Server struct {
	g      *Gateway
	hooks  ServerHooks
	peer   PeerCheck
	events *EventHub
	log    *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	done  bool
}

// NewServer wires a protocol server around g.
func NewServer(g *Gateway, hooks ServerHooks, peer PeerCheck, events *EventHub, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if events == nil {
		events = NewEventHub(0)
	}
	return &Server{g: g, hooks: hooks, peer: peer, events: events, log: log, conns: map[net.Conn]struct{}{}}
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if s.peer != nil {
			if err := s.peer(c); err != nil {
				s.log.Warn("egress: rejected UDS peer", "error", err)
				_ = c.Close()
				continue
			}
		}
		s.mu.Lock()
		if s.done {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.handle(c)
	}
}

// Close closes every open connection.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) handle(c net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
	}()
	fr := newFrameReader(c)
	var hello request
	if err := fr.read(&hello); err != nil || hello.Op != opHello {
		_ = writeFrame(c, response{ID: hello.ID, Code: codeVersion, Error: "first frame must be hello"})
		return
	}
	v, ok := negotiate(hello.Versions)
	if !ok {
		_ = writeFrame(c, response{ID: hello.ID, Code: codeVersion,
			Error: fmt.Sprintf("gateway speaks %d and %d, peer offered %v", ProtocolVersion, ProtocolVersion-1, hello.Versions)})
		return
	}
	if err := writeFrame(c, response{ID: hello.ID, Version: v}); err != nil {
		return
	}
	for {
		var req request
		if err := fr.read(&req); err != nil {
			return
		}
		if req.Op == opSubscribe {
			s.stream(c, req.ID)
			return
		}
		span := startServerSpan(req.Trace, req.Op)
		payload, err := s.dispatch(req)
		endSpan(span, err)
		resp := response{ID: req.ID, Payload: payload}
		if err != nil {
			resp.Code, resp.Error = codeFor(err), err.Error()
		}
		if err := writeFrame(c, resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(req request) (json.RawMessage, error) {
	var err error
	var out any
	switch req.Op {
	case opAttach, opUpdate:
		var spec Spec
		if err = json.Unmarshal(req.Payload, &spec); err != nil {
			return nil, err
		}
		if req.Op == opAttach {
			err = s.g.Attach(spec)
		} else {
			err = s.g.Update(spec)
		}
	case opDetach:
		var p detachPayload
		if err = json.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		err = s.g.Detach(p.ID, p.IP)
	case opSetBlocked:
		var p setBlockedPayload
		if err = json.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		err = s.g.SetBlocked(p.ID, p.Reason, p.On)
	case opSync:
		var specs []Spec
		if err = json.Unmarshal(req.Payload, &specs); err != nil {
			return nil, err
		}
		err = s.g.Sync(specs)
	case opReady:
		st := ReadyStatus{Layout: s.g.CheckLayout() == nil}
		if s.hooks.Listeners != nil {
			st.Listeners = s.hooks.Listeners()
		}
		if !st.Layout {
			st.Error = "nft layout missing"
		}
		out = st
	case opBridges:
		var bridges []Bridge
		if err = json.Unmarshal(req.Payload, &bridges); err != nil {
			return nil, err
		}
		if s.hooks.SetBridges == nil {
			return nil, fmt.Errorf("%w: bridges not supported", ErrUnavailable)
		}
		err = s.hooks.SetBridges(bridges)
	case opProbe:
		var p ProbeRequest
		if err = json.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		if s.hooks.Probe == nil {
			return nil, fmt.Errorf("%w: probe not supported", ErrUnavailable)
		}
		out, err = s.hooks.Probe(p)
	case opLearned:
		var id string
		if err = json.Unmarshal(req.Payload, &id); err != nil {
			return nil, err
		}
		if s.hooks.Learned == nil {
			return nil, fmt.Errorf("%w: learn mode not supported", ErrUnavailable)
		}
		return s.hooks.Learned(id)
	case opForget:
		var id string
		if err = json.Unmarshal(req.Payload, &id); err != nil {
			return nil, err
		}
		if s.hooks.ForgetLearned != nil {
			err = s.hooks.ForgetLearned(id)
		}
	case opNodeCtl:
		var eps []netip.AddrPort
		if err = json.Unmarshal(req.Payload, &eps); err != nil {
			return nil, err
		}
		if s.hooks.NodeControl == nil {
			return nil, fmt.Errorf("%w: node control guard not supported", ErrUnavailable)
		}
		err = s.hooks.NodeControl(eps)
	default:
		return nil, fmt.Errorf("unknown op %q", req.Op)
	}
	if err != nil {
		return nil, err
	}
	switch req.Op {
	case opAttach, opUpdate, opDetach, opSetBlocked, opSync, opBridges:
		if s.hooks.Changed != nil {
			s.hooks.Changed()
		}
	}
	if out == nil {
		return nil, nil
	}
	return json.Marshal(out)
}

// stream turns the connection into an event stream. Queued events drain
// first; a failed write requeues the batch so nothing is lost on reconnect.
func (s *Server) stream(c net.Conn, id uint64) {
	if err := writeFrame(c, response{ID: id}); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// A peer close shows up as a read error; stop streaming then.
		_, _ = io.Copy(io.Discard, c)
		cancel()
	}()
	for {
		batch := s.events.take(256)
		for i, e := range batch {
			e := e
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writeFrame(c, response{Event: &e}); err != nil {
				s.events.requeue(batch[i:])
				return
			}
		}
		if len(batch) > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-s.events.notify:
		case <-time.After(time.Second):
		}
	}
}
