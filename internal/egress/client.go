package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// API is what sandboxd uses to drive the egress gateway. Client implements it
// over the UDS; Noop is the fail-closed stand-in when the feature is off or
// the gateway is unreachable.
type API interface {
	Attach(ctx context.Context, spec Spec) error
	Update(ctx context.Context, spec Spec) error
	Detach(ctx context.Context, id string, ip netip.Addr) error
	SetBlocked(ctx context.Context, id string, reason BlockReason, on bool) error
	Sync(ctx context.Context, specs []Spec) error
	Ready(ctx context.Context) (ReadyStatus, error)
	SetBridges(ctx context.Context, bridges []Bridge) error
	Probe(ctx context.Context, p ProbeRequest) (ProbeResult, error)
	Learned(ctx context.Context, id string) (json.RawMessage, error)
	// ForgetLearned discards a sandbox's learn-mode recording; sandboxd
	// calls it on destroy. A recording outlives learn → enforce so the
	// owner can still read it, so detach alone can't drop it.
	ForgetLearned(ctx context.Context, id string) error
	// SetNodeControl replaces the node-wide control-port guard's endpoints
	// (§5.10 PC-2).
	SetNodeControl(ctx context.Context, endpoints []netip.AddrPort) error
}

// Noop is the API when there is no gateway. Anything that would put a sandbox
// into gateway mode fails with ErrUnavailable, so callers keep the sandbox
// shut (G7, CEO D16). Removing state is a successful no-op: without a gateway
// there is nothing to remove.
type Noop struct{}

var _ API = Noop{}

func (Noop) Attach(context.Context, Spec) error {
	return fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}
func (Noop) Update(context.Context, Spec) error {
	return fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}
func (Noop) Detach(context.Context, string, netip.Addr) error {
	return nil
}
func (Noop) SetBlocked(context.Context, string, BlockReason, bool) error { return nil }
func (Noop) Sync(context.Context, []Spec) error {
	return fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}
func (Noop) Ready(context.Context) (ReadyStatus, error) {
	return ReadyStatus{}, fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}
func (Noop) SetBridges(context.Context, []Bridge) error {
	return fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}
func (Noop) Probe(context.Context, ProbeRequest) (ProbeResult, error) {
	return ProbeResult{}, fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}

// SetNodeControl is a no-op: without a gateway there is no table to guard.
func (Noop) SetNodeControl(context.Context, []netip.AddrPort) error { return nil }

func (Noop) Learned(context.Context, string) (json.RawMessage, error) {
	return nil, fmt.Errorf("%w: gateway disabled", ErrUnavailable)
}

// ForgetLearned is a no-op: without a gateway there is no recording.
func (Noop) ForgetLearned(context.Context, string) error { return nil }

// clientConn is one handshaken UDS connection.
type clientConn struct {
	c  net.Conn
	fr *frameReader
}

// Client speaks the gateway protocol over a pool of persistent UDS
// connections, so a create never pays a connect (latency amendment §8.2).
type Client struct {
	path    string
	dialTO  time.Duration
	pool    chan *clientConn
	nextID  atomic.Uint64
	version atomic.Int32
	mu      sync.Mutex
	closed  bool
}

// DefaultPoolSize is the number of idle connections the client keeps.
const DefaultPoolSize = 8

// NewClient returns a client for the gateway socket at path. Connections are
// dialed lazily.
func NewClient(path string) *Client {
	return &Client{path: path, dialTO: 2 * time.Second, pool: make(chan *clientConn, DefaultPoolSize)}
}

var _ API = (*Client)(nil)

// Version is the negotiated protocol version (0 before the first handshake).
func (c *Client) Version() int { return int(c.version.Load()) }

// Close drops every pooled connection.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	for {
		select {
		case cc := <-c.pool:
			_ = cc.c.Close()
		default:
			return
		}
	}
}

func (c *Client) dial(ctx context.Context) (*clientConn, error) {
	d := net.Dialer{Timeout: c.dialTO}
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrUnavailable, c.path, err)
	}
	cc := &clientConn{c: conn, fr: newFrameReader(conn)}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	id := c.nextID.Add(1)
	if err := writeFrame(conn, request{ID: id, Op: opHello, Versions: []int{ProtocolVersion, ProtocolVersion - 1}}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: hello: %v", ErrUnavailable, err)
	}
	var resp response
	if err := cc.fr.read(&resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: hello: %v", ErrUnavailable, err)
	}
	if resp.Error != "" {
		_ = conn.Close()
		return nil, errFor(resp.Code, resp.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	c.version.Store(int32(resp.Version))
	return cc, nil
}

func (c *Client) get(ctx context.Context) (*clientConn, error) {
	select {
	case cc := <-c.pool:
		return cc, nil
	default:
		return c.dial(ctx)
	}
}

func (c *Client) put(cc *clientConn) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		_ = cc.c.Close()
		return
	}
	select {
	case c.pool <- cc:
	default:
		_ = cc.c.Close()
	}
}

// call sends one request and waits for its response. A transport failure
// closes the connection; the next call dials a fresh one.
func (c *Client) call(ctx context.Context, op string, in any, out any) (err error) {
	ctx, span := startClientSpan(ctx, op)
	defer func() { endSpan(span, err) }()
	cc, err := c.get(ctx)
	if err != nil {
		return err
	}
	var payload json.RawMessage
	if in != nil {
		if payload, err = json.Marshal(in); err != nil {
			c.put(cc)
			return err
		}
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(30 * time.Second)
	}
	_ = cc.c.SetDeadline(dl)
	id := c.nextID.Add(1)
	if err := writeFrame(cc.c, request{ID: id, Op: op, Payload: payload, Trace: injectTrace(ctx)}); err != nil {
		_ = cc.c.Close()
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, op, err)
	}
	var resp response
	if err := cc.fr.read(&resp); err != nil {
		_ = cc.c.Close()
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, op, err)
	}
	_ = cc.c.SetDeadline(time.Time{})
	if resp.ID != id {
		_ = cc.c.Close()
		return fmt.Errorf("%w: %s: response id %d, want %d", ErrUnavailable, op, resp.ID, id)
	}
	c.put(cc)
	if resp.Error != "" {
		return errFor(resp.Code, resp.Error)
	}
	if out != nil && len(resp.Payload) > 0 {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}

func (c *Client) Attach(ctx context.Context, spec Spec) error {
	return c.call(ctx, opAttach, spec, nil)
}
func (c *Client) Update(ctx context.Context, spec Spec) error {
	return c.call(ctx, opUpdate, spec, nil)
}
func (c *Client) Detach(ctx context.Context, id string, ip netip.Addr) error {
	return c.call(ctx, opDetach, detachPayload{ID: id, IP: ip}, nil)
}
func (c *Client) SetBlocked(ctx context.Context, id string, reason BlockReason, on bool) error {
	return c.call(ctx, opSetBlocked, setBlockedPayload{ID: id, Reason: reason, On: on}, nil)
}
func (c *Client) Sync(ctx context.Context, specs []Spec) error {
	if specs == nil {
		specs = []Spec{}
	}
	return c.call(ctx, opSync, specs, nil)
}
func (c *Client) Ready(ctx context.Context) (ReadyStatus, error) {
	var st ReadyStatus
	err := c.call(ctx, opReady, nil, &st)
	return st, err
}
func (c *Client) SetNodeControl(ctx context.Context, endpoints []netip.AddrPort) error {
	if endpoints == nil {
		endpoints = []netip.AddrPort{}
	}
	return c.call(ctx, opNodeCtl, endpoints, nil)
}

func (c *Client) SetBridges(ctx context.Context, bridges []Bridge) error {
	if bridges == nil {
		bridges = []Bridge{}
	}
	return c.call(ctx, opBridges, bridges, nil)
}
func (c *Client) Probe(ctx context.Context, p ProbeRequest) (ProbeResult, error) {
	var r ProbeResult
	err := c.call(ctx, opProbe, p, &r)
	return r, err
}
func (c *Client) Learned(ctx context.Context, id string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.call(ctx, opLearned, id, &raw)
	return raw, err
}

func (c *Client) ForgetLearned(ctx context.Context, id string) error {
	return c.call(ctx, opForget, id, nil)
}

// Subscribe opens a dedicated event-stream connection. Events arrive on the
// returned channel until ctx ends or the stream breaks (the channel closes;
// callers resubscribe with backoff).
func (c *Client) Subscribe(ctx context.Context) (<-chan Event, error) {
	cc, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	id := c.nextID.Add(1)
	if err := writeFrame(cc.c, request{ID: id, Op: opSubscribe}); err != nil {
		_ = cc.c.Close()
		return nil, fmt.Errorf("%w: subscribe: %v", ErrUnavailable, err)
	}
	var ack response
	if err := cc.fr.read(&ack); err != nil || ack.Error != "" {
		_ = cc.c.Close()
		if err == nil {
			err = errors.New(ack.Error)
		}
		return nil, fmt.Errorf("%w: subscribe: %v", ErrUnavailable, err)
	}
	ch := make(chan Event, 256)
	go func() {
		<-ctx.Done()
		_ = cc.c.Close()
	}()
	go func() {
		defer close(ch)
		for {
			var r response
			if err := cc.fr.read(&r); err != nil {
				return
			}
			if r.Event == nil {
				continue
			}
			select {
			case ch <- *r.Event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}
