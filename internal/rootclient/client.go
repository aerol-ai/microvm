// Package rootclient is the agent's side of the root helper's socket
// (plans/security-gaps-m1-m4.md §3.3): the helper's own calls, and a dialer
// that sends containerd's Go client through the same socket to the gate.
//
// The helper is reached lazily, with the repo's bootstrap pattern
// (Service.EnsureLayer4Ready): an atomic.Bool latch for the steady state, a
// sync.Mutex so a burst of first callers dials and shakes hands once, and a
// failed handshake leaves the latch unset so the next caller tries again.
// A helper that is down fails a call at once, or within Config.Timeout if
// it hangs, with an error that wraps ErrUnavailable, which the API turns
// into a 503; it never hangs a create.
//
// Agent N must work with helper N-1 (eng review D5). The handshake reads
// which calls this helper serves; a call it lacks is refused here, before
// it is sent, with an UnsupportedError naming the call and the helper.
//
// Nothing uses this yet; the agent moves onto it in task T4.
package rootclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/version"
)

const (
	// DefaultSocket is where the helper listens (internal/rootd).
	DefaultSocket = "/run/aerolvm/root.sock"
	// DefaultTimeout bounds one connect and handshake. The helper is a
	// local process; anything slower is a helper that is stuck.
	DefaultTimeout = 2 * time.Second
	// maxReconnectDelay caps gRPC's reconnect backoff. Its default grows to
	// two minutes, and containerd's client to ten seconds; a helper that
	// restarts (a crash, or the signed swap of eng review D4) is back in
	// about a second, and calls should reach it then.
	maxReconnectDelay = time.Second
)

// ErrUnavailable: the helper could not be reached or did not answer. The
// API maps it to 503: the supervisor restarts a helper that died.
var ErrUnavailable = errors.New("root helper unavailable")

// ErrUnsupported: the helper is older than this agent and lacks what the
// agent asked for. The API maps it to 503 too: the agent stages the newer
// helper and the supervisor swaps it in (eng review D4).
var ErrUnsupported = errors.New("root helper does not support this")

// Info is what the helper said in the handshake.
type Info struct {
	HelperVersion string
	API           uint32
	Features      []string
}

// Has reports whether the helper serves feature.
func (i Info) Has(feature string) bool { return slices.Contains(i.Features, feature) }

// UnsupportedError is a call or a helper this agent cannot use.
type UnsupportedError struct {
	// Feature is what the helper lacks; empty when the whole helper is
	// older than MinHelperAPI.
	Feature string
	Helper  Info
}

func (e *UnsupportedError) Error() string {
	if e.Feature == "" {
		return fmt.Sprintf("root helper %s speaks API %d; this agent needs %d or newer: upgrade the helper",
			e.Helper.HelperVersion, e.Helper.API, rootdpb.MinHelperAPI)
	}
	return fmt.Sprintf("root helper %s (API %d) does not have %s; this agent (API %d) needs a newer helper",
		e.Helper.HelperVersion, e.Helper.API, e.Feature, rootdpb.APIVersion)
}

func (e *UnsupportedError) Is(target error) bool { return target == ErrUnsupported }

// Config is how to reach the helper.
type Config struct {
	// Socket is the helper's socket. Empty means DefaultSocket.
	Socket string
	// Timeout bounds each connect and each handshake. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// AgentVersion goes into the handshake, for the helper's log. Empty
	// means this build's version.
	AgentVersion string
}

// session is one connection to the helper and what its handshake said.
type session struct {
	conn *grpc.ClientConn
	rpc  rootdpb.RootHelperClient
	info Info
	// gen is the count of dials when the handshake ran. A later dial means
	// the helper may have been swapped for a newer one.
	gen uint64
}

// Client talks to the helper. It is safe for concurrent use.
type Client struct {
	socket       string
	timeout      time.Duration
	agentVersion string

	ready  atomic.Bool // latch: a handshake succeeded on the current session
	mu     sync.Mutex  // single flight for handshakes; guards closed and session swaps
	sess   atomic.Pointer[session]
	dials  atomic.Uint64 // successful dials of the helper's own connection
	closed bool
}

// New returns a client. It does not dial: the first call does.
func New(cfg Config) *Client {
	c := &Client{socket: cfg.Socket, timeout: cfg.Timeout, agentVersion: cfg.AgentVersion}
	if c.socket == "" {
		c.socket = DefaultSocket
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.agentVersion == "" {
		c.agentVersion = version.Version
	}
	return c
}

// Socket is the helper's socket path, which is also the address to give
// containerd's client (with ContainerdOptions).
func (c *Client) Socket() string { return c.socket }

// Ensure connects and shakes hands once. The steady state is one atomic
// load; concurrent first callers share one handshake; a failed one is
// tried again by the next caller.
func (c *Client) Ensure(ctx context.Context) error {
	if c.ready.Load() {
		return nil
	}
	return c.handshake(ctx, nil)
}

// Info is the latest handshake's answer, if one succeeded.
func (c *Client) Info() (Info, bool) {
	if s := c.sess.Load(); s != nil {
		info := s.info
		info.Features = slices.Clone(info.Features)
		return info, true
	}
	return Info{}, false
}

// handshake runs Version under the single flight. With stale set it runs
// it again on the live session, unless another caller already replaced that
// session while this one waited for the lock.
func (c *Client) handshake(ctx context.Context, stale *session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("%w: the client is closed", ErrUnavailable)
	}
	s := c.sess.Load()
	if stale == nil && c.ready.Load() {
		return nil
	}
	if stale != nil && s != stale {
		return nil
	}
	if s == nil {
		conn, err := grpc.NewClient("passthrough:///aerolvm-rootd",
			grpc.WithContextDialer(c.dialOwn),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(connectParams(c.timeout)))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		s = &session{conn: conn, rpc: rootdpb.NewRootHelperClient(conn)}
	}
	hctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := s.rpc.Version(hctx, &rootdpb.VersionRequest{AgentVersion: c.agentVersion, AgentApi: rootdpb.APIVersion})
	if err != nil {
		// Drop the connection rather than keep it: gRPC would sit in its
		// reconnect backoff, and the next caller should dial the moment
		// the helper is back.
		c.dropLocked(s)
		return c.unavailable(err)
	}
	info := Info{HelperVersion: resp.GetHelperVersion(), API: resp.GetApi(), Features: resp.GetFeatures()}
	if info.API < rootdpb.MinHelperAPI {
		c.dropLocked(s)
		return &UnsupportedError{Helper: info}
	}
	c.sess.Store(&session{conn: s.conn, rpc: s.rpc, info: info, gen: c.dials.Load()})
	c.ready.Store(true)
	return nil
}

// dropLocked forgets s and unlatches, so the next caller dials afresh.
func (c *Client) dropLocked(s *session) {
	c.ready.Store(false)
	c.sess.Store(nil)
	_ = s.conn.Close()
}

// Require connects if needed and checks that the helper serves feature.
func (c *Client) Require(ctx context.Context, feature string) error {
	_, err := c.require(ctx, feature)
	return err
}

func (c *Client) require(ctx context.Context, feature string) (*session, error) {
	if err := c.Ensure(ctx); err != nil {
		return nil, err
	}
	s := c.sess.Load()
	if s == nil { // closed, or dropped by a failed refresh, since Ensure
		return nil, c.noSession()
	}
	if s.info.Has(feature) {
		// Helpers only move forward (eng review D4), so a feature the
		// helper had is still there; no need to look again.
		return s, nil
	}
	// A connection lost or made since the handshake may be a newer helper
	// (the swap closes the old one's connections): ask again before
	// refusing, once per connection.
	if s.gen != c.dials.Load() || s.conn.GetState() != connectivity.Ready {
		if err := c.handshake(ctx, s); err != nil {
			return nil, err
		}
		if s = c.sess.Load(); s == nil {
			return nil, c.noSession()
		}
		if s.info.Has(feature) {
			return s, nil
		}
	}
	return nil, &UnsupportedError{Feature: feature, Helper: s.info}
}

// EnsureHost asks the helper to set the host up for sandboxes. No helper
// serves it yet, so it returns an UnsupportedError.
func (c *Client) EnsureHost(ctx context.Context) error {
	s, err := c.require(ctx, rootdpb.FeatureEnsureHost)
	if err != nil {
		return err
	}
	_, err = s.rpc.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	return c.callErr(s, rootdpb.FeatureEnsureHost, err)
}

// callErr turns a typed call's gRPC error into the client's own: a helper
// that went away is ErrUnavailable, a call it turns out not to have is an
// UnsupportedError. Anything else is the helper's answer, as it came.
func (c *Client) callErr(s *session, feature string, err error) error {
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.Unavailable:
		return c.unavailable(err)
	case codes.Unimplemented:
		return &UnsupportedError{Feature: feature, Helper: s.info}
	}
	return err
}

func (c *Client) noSession() error {
	return fmt.Errorf("%w: no connection to %s", ErrUnavailable, c.socket)
}

func (c *Client) unavailable(err error) error {
	return fmt.Errorf("%w at %s: %w", ErrUnavailable, c.socket, err)
}

// dialOwn dials the helper's own connection and counts it.
func (c *Client) dialOwn(ctx context.Context, _ string) (net.Conn, error) {
	conn, err := c.dial(ctx)
	if err == nil {
		c.dials.Add(1)
	}
	return conn, err
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	return d.DialContext(ctx, "unix", c.socket)
}

// DialContainerd is the dialer containerd's client uses: it makes sure
// the helper has shaken hands, then connects to its socket, where the gate
// answers containerd's API. A helper that is down or too old fails the
// dial with the handshake's error.
func (c *Client) DialContainerd(ctx context.Context, _ string) (net.Conn, error) {
	if err := c.Ensure(ctx); err != nil {
		return nil, err
	}
	return c.dial(ctx)
}

// ContainerdOptions make containerd's Go client reach containerd through
// the helper: cntr.New(c.Socket(), append(c.ContainerdOptions(), ...)...).
// They come as extra dial options, after the client's own, so this dialer
// and backoff replace containerd's.
func (c *Client) ContainerdOptions() []cntr.Opt {
	return []cntr.Opt{cntr.WithExtraDialOpts([]grpc.DialOption{
		grpc.WithContextDialer(c.DialContainerd),
		grpc.WithConnectParams(connectParams(c.timeout)),
	})}
}

func connectParams(timeout time.Duration) grpc.ConnectParams {
	bc := backoff.DefaultConfig
	bc.BaseDelay = 100 * time.Millisecond
	bc.MaxDelay = maxReconnectDelay
	return grpc.ConnectParams{Backoff: bc, MinConnectTimeout: timeout}
}

// Close closes the helper's connection. Calls after it fail with
// ErrUnavailable. containerd's client has its own connection, which its
// Close closes.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if s := c.sess.Load(); s != nil {
		c.dropLocked(s)
	}
	return nil
}
