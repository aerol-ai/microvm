// Package rootclient is the agent's side of the root helper's socket
// (plans/security-gaps-m1-m4.md §3.3): the helper's own calls, and a dialer
// that sends containerd's Go client through the same socket to the gate.
//
// The helper is reached lazily, with the repo's bootstrap pattern
// (Service.EnsureLayer4Ready): an atomic.Bool latch for the steady state, a
// sync.Mutex so a burst of first callers dials and shakes hands once, and a
// failed handshake leaves the latch unset so the next caller tries again.
// The mutex is not held across the handshake itself: callers that arrive
// during it wait for its result, so all of them finish within
// Config.Timeout even when the helper hangs (review M2).
//
// A helper that is down, hung or not root fails a call at once, or within
// Config.Timeout, with an error that wraps ErrUnavailable, which the API
// turns into a 503; it never hangs a create. That holds on the containerd
// path too: a call containerd's client makes through the helper carries
// ErrUnavailable through containerd's own error conversion (review M1).
//
// A typed call whose connection dropped before the helper answered is
// tried again, briefly (retryCall): the supervisor swaps the helper for a
// newer one with every release (eng review D4), and the swap closes the
// old helper's connections. Only calls safe to run twice are, which today
// is all of them (retrySafe).
//
// Agent N must work with helper N-1 (eng review D5). The handshake reads
// which calls this helper serves; a call it lacks is refused here, before
// it is sent, with an UnsupportedError naming the call and the helper.
//
// A call the helper or its gate refuses, on either path, comes back as an
// error matching ErrRefused, which the API turns into a 500, and is
// counted and handed to Config.OnRefusal (refusal.go, eng review D9).
//
// Nothing uses this yet; the agent moves onto it in task T4.
package rootclient

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/version"
)

const (
	// DefaultSocket is where the helper listens (internal/rootd).
	DefaultSocket = "/run/aerolvm-rootd/sock/root.sock"
	// DefaultTimeout bounds one connect, one handshake, and a typed call
	// whose context has no deadline. The helper is a local process;
	// anything slower is a helper that is stuck.
	DefaultTimeout = 2 * time.Second
	// maxReconnectDelay caps gRPC's reconnect backoff. Its default grows to
	// two minutes, and containerd's client to ten seconds; a helper that
	// restarts (a crash, or the signed swap of eng review D4) is back in
	// about a second, and calls should reach it then.
	maxReconnectDelay = time.Second
)

// ErrUnavailable: the helper could not be reached, did not answer in time,
// or is not root. The API maps it to 503: the supervisor restarts a helper
// that died.
var ErrUnavailable = rootdpb.ErrHelperUnavailable

// ErrUnsupported: the helper is older than this agent and lacks what the
// agent asked for. The API maps it to 503 too: the agent stages the newer
// helper and the supervisor swaps it in (eng review D4).
var ErrUnsupported = rootdpb.ErrHelperUnsupported

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
	// Timeout bounds each connect, each handshake, and each typed call
	// whose context has no deadline. Zero means DefaultTimeout.
	Timeout time.Duration
	// AgentVersion goes into the handshake, for the helper's log. Empty
	// means this build's version.
	AgentVersion string
	// HelperUID is the uid the process serving the socket must run as,
	// read with SO_PEERCRED on Linux: 0, root, outside tests. Whatever can
	// bind the socket's path otherwise gets every containerd spec the agent
	// sends and answers for the helper (review M3).
	HelperUID uint32
	// OnRefusal hears every call the helper or its gate refuses, on the
	// helper's own calls and on containerd's (refusal.go). sandboxd sets it
	// to (*service.Service).RecordRootRefusal, which writes the audit
	// record; task T4 wires it where the daemon builds this client, after
	// the service exists:
	//
	//	rootclient.New(rootclient.Config{..., OnRefusal: svc.RecordRootRefusal})
	//
	// Nil records no audit event. The client counts every refusal in
	// aerolvm_rootd_refusals_total either way.
	OnRefusal RefusalFunc
}

// session is one connection to the helper and what its handshake said.
type session struct {
	conn *grpc.ClientConn
	rpc  rootdpb.RootHelperClient
	info Info
	// gen is the count of dials when the handshake ran, or 0 when a dial
	// may have come between the handshake and that count. A later dial
	// means the helper may have been swapped for a newer one.
	gen uint64
	// stale is set when a call this helper listed comes back
	// Unimplemented: the helper behind the connection is no longer the
	// one that answered the handshake, so info is asked for again.
	stale atomic.Bool
}

// attempt is a handshake in flight; callers that arrive during it share
// its result.
type attempt struct {
	done chan struct{}
	conn *grpc.ClientConn // closed by Close, to end the attempt at once
	err  error
}

// Client talks to the helper. It is safe for concurrent use.
type Client struct {
	socket       string
	timeout      time.Duration
	agentVersion string
	peer         egress.PeerCheck
	onRefusal    RefusalFunc

	ready    atomic.Bool // latch: a handshake succeeded on the current session
	mu       sync.Mutex  // single flight: guards inflight, closed and session swaps
	inflight *attempt
	sess     atomic.Pointer[session]
	dials    atomic.Uint64 // successful dials of the helper's own connection
	closed   bool
	// tooOld is the last handshake's verdict when it found the helper too
	// old, else nil. gRPC passes a dialer's error on as text only, so this
	// is how a containerd call the dialer refused learns why (review N5).
	tooOld atomic.Pointer[UnsupportedError]
}

// New returns a client. It does not dial: the first call does.
func New(cfg Config) *Client {
	c := &Client{socket: cfg.Socket, timeout: cfg.Timeout, agentVersion: cfg.AgentVersion,
		peer: egress.UnixPeerCheck([]uint32{cfg.HelperUID}, ""), onRefusal: cfg.OnRefusal}
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

// handshake runs Version once for everyone who needs it now. With stale
// set it runs it again on that session, unless another caller replaced the
// session while this one waited. The mutex guards only the bookkeeping:
// the call itself runs in its own goroutine (start), and every caller, the
// one that started it included, waits for its result or its own context,
// whichever ends first (review M2, N1).
func (c *Client) handshake(ctx context.Context, stale *session) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.closedErr()
	}
	cur := c.sess.Load()
	if (stale == nil && c.ready.Load()) || (stale != nil && cur != stale) {
		c.mu.Unlock()
		return nil
	}
	a := c.inflight
	if a == nil {
		var err error
		if a, err = c.startLocked(ctx, cur); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	c.mu.Unlock()
	select {
	case <-a.done:
		return a.err
	case <-ctx.Done():
		return c.unavailable(ctx.Err())
	}
}

// startLocked starts a handshake on cur's connection, or a new one. It runs
// on ctx's values but not its cancel or deadline, bounded by the client's
// timeout instead: the callers who share it each have their own deadline,
// and the first one giving up (its request cancelled) must not fail the
// rest (review N1).
func (c *Client) startLocked(ctx context.Context, cur *session) (*attempt, error) {
	fresh := cur == nil
	var conn *grpc.ClientConn
	var rpc rootdpb.RootHelperClient
	if fresh {
		var err error
		conn, err = grpc.NewClient("passthrough:///aerolvm-rootd",
			grpc.WithContextDialer(c.dialOwn),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(connectParams(c.timeout)))
		if err != nil {
			return nil, c.unavailable(err)
		}
		rpc = rootdpb.NewRootHelperClient(conn)
	} else {
		conn, rpc = cur.conn, cur.rpc
	}
	a := &attempt{done: make(chan struct{}), conn: conn}
	c.inflight = a
	go c.run(context.WithoutCancel(ctx), a, cur, rpc, fresh)
	return a, nil
}

// run is one handshake. It records the result under the mutex and wakes
// everyone waiting on a.
func (c *Client) run(ctx context.Context, a *attempt, cur *session, rpc rootdpb.RootHelperClient, fresh bool) {
	before := c.dials.Load()
	hctx, cancel := context.WithTimeout(ctx, c.timeout)
	resp, err := rpc.Version(hctx, &rootdpb.VersionRequest{AgentVersion: c.agentVersion, AgentApi: rootdpb.APIVersion})
	cancel()
	after := c.dials.Load()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.inflight = nil
	defer close(a.done)
	switch {
	case c.closed:
		err = c.closedErr()
	case err != nil:
		err = c.unavailable(err)
	case resp.GetApi() < rootdpb.MinHelperAPI:
		err = &UnsupportedError{Helper: Info{HelperVersion: resp.GetHelperVersion(), API: resp.GetApi(), Features: resp.GetFeatures()}}
	}
	var ue *UnsupportedError
	if errors.As(err, &ue) {
		c.tooOld.Store(ue)
	} else {
		c.tooOld.Store(nil)
	}
	if err != nil {
		// Drop the connection rather than keep it: gRPC would sit in its
		// reconnect backoff, and the next caller should dial the moment
		// the helper is back.
		c.ready.Store(false)
		if cur != nil && c.sess.Load() == cur {
			c.sess.Store(nil)
		}
		_ = a.conn.Close()
		a.err = err
		return
	}
	// A dial other than the handshake's own, before or after its answer,
	// may have reached a newer helper than the one that answered: leave
	// gen 0, so the next missing feature asks again (review L4).
	gen := after
	if (fresh && after != before+1) || (!fresh && after != before) {
		gen = 0
	}
	c.sess.Store(&session{conn: a.conn, rpc: rpc, gen: gen,
		info: Info{HelperVersion: resp.GetHelperVersion(), API: resp.GetApi(), Features: resp.GetFeatures()}})
	c.ready.Store(true)
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
	if s.info.Has(feature) && !s.stale.Load() {
		// Helpers move forward (eng review D4), so a feature the helper
		// had is still there; no need to look again. The one way back, a
		// supervisor's rollback, shows as a listed call that is
		// Unimplemented (callErr), which marks the session stale.
		return s, nil
	}
	// A connection lost or made since the handshake may be a newer helper
	// (the swap closes the old one's connections): ask again before
	// refusing, once per connection.
	if s.stale.Load() || s.gen != c.dials.Load() || s.conn.GetState() != connectivity.Ready {
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
	_, err := call(ctx, c, rootdpb.FeatureEnsureHost, &rootdpb.EnsureHostRequest{}, rootdpb.RootHelperClient.EnsureHost)
	return err
}

// The calls below have the helper make the files runc, runsc and the
// containerd shim open as root, in folders only root can write
// (internal/rootd files.go). Each answers with the paths the agent puts in
// its specs; the agent never names a path itself. A value the helper
// refuses comes back as a RefusedError, which unwraps to the helper's
// InvalidArgument or PermissionDenied.

// EnsureHostFiles has the helper write a container's hostname, hosts and
// resolv.conf files, and the egress CA when the request has one.
func (c *Client) EnsureHostFiles(ctx context.Context, req *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	return call(ctx, c, rootdpb.FeatureEnsureHostFiles, req, rootdpb.RootHelperClient.EnsureHostFiles)
}

// EnsureTaskFIFOs has the helper make fresh stdout and stderr FIFOs for a
// container's next task. Call it once per task, before opening them: a
// second call replaces them, and a reader of the first pair would then
// never see the task's output. Re-attaching to a running task opens the
// FIFOs it has, without this call.
func (c *Client) EnsureTaskFIFOs(ctx context.Context, containerID string) (*rootdpb.EnsureTaskFIFOsResponse, error) {
	return call(ctx, c, rootdpb.FeatureEnsureTaskFIFOs, &rootdpb.EnsureTaskFIFOsRequest{ContainerId: containerID}, rootdpb.RootHelperClient.EnsureTaskFIFOs)
}

// EnsureRunscConfig has the helper write one of its runsc shim configs and
// returns its path, for the runsc runtime options' ConfigPath.
func (c *Client) EnsureRunscConfig(ctx context.Context, config rootdpb.RunscConfig) (string, error) {
	resp, err := call(ctx, c, rootdpb.FeatureEnsureRunscConfig, &rootdpb.EnsureRunscConfigRequest{Config: config}, rootdpb.RootHelperClient.EnsureRunscConfig)
	return resp.GetPath(), err
}

// EnsureReadySocket names, in the helper's folder, the ready socket the
// agent has bound for a container in its own ready folder (pkg/docker:
// <id>.<nonce>.sock, or <id>.sock for a park socket when nonce is empty),
// and returns that name for the spec's bind. Call it again after binding
// the socket again.
func (c *Client) EnsureReadySocket(ctx context.Context, containerID, nonce string) (string, error) {
	resp, err := call(ctx, c, rootdpb.FeatureEnsureReadySocket, &rootdpb.EnsureReadySocketRequest{ContainerId: containerID, Nonce: nonce}, rootdpb.RootHelperClient.EnsureReadySocket)
	return resp.GetPath(), err
}

// RemoveContainerFiles has the helper remove everything it made for a
// container. Gone already counts as done.
func (c *Client) RemoveContainerFiles(ctx context.Context, containerID string) error {
	_, err := call(ctx, c, rootdpb.FeatureRemoveContainerFiles, &rootdpb.RemoveContainerFilesRequest{ContainerId: containerID}, rootdpb.RootHelperClient.RemoveContainerFiles)
	return err
}

// call runs one typed call: refused here, before it is sent, when the
// helper lacks it; bounded by the client's timeout when ctx has no
// deadline; tried again when its connection dropped (retryCall); and with
// the client's errors (ErrUnavailable, ErrUnsupported).
func call[Req, Resp any](ctx context.Context, c *Client, feature string, req Req,
	rpc func(rootdpb.RootHelperClient, context.Context, Req, ...grpc.CallOption) (Resp, error)) (Resp, error) {
	var zero Resp
	var firstDrop time.Time
	for attempt := 0; ; attempt++ {
		s, err := c.require(ctx, feature)
		if err != nil {
			if c.retryCall(ctx, feature, &firstDrop, attempt, droppedBefore(err)) {
				continue
			}
			return zero, err
		}
		cctx, cancel := c.callContext(ctx)
		var trailer metadata.MD
		resp, err := rpc(s.rpc, cctx, req, grpc.Trailer(&trailer))
		cancel()
		if err == nil {
			return resp, nil
		}
		if c.retryCall(ctx, feature, &firstDrop, attempt, dropped(err, trailer)) {
			continue
		}
		return zero, c.callErr(ctx, s, feature, err)
	}
}

// retrySafe says, for each of the helper's calls, whether one whose
// connection dropped may be sent again. Every call has an entry
// (TestEveryCallHasARetryRule), so a new call cannot be retried by
// default.
//
// A dropped call may or may not have run. Two things make running it
// again safe. The helper drops connections only when it stops, and the
// supervisor starts the next helper only once the old one's whole cgroup
// is empty: the helper and every process it started, such as a CNI plugin
// and the IPAM plugin that one runs, have exited (exclusive handover,
// outside review O6; internal/supervisor HelperGroup). So no part of the
// first try can run after the second. And each call below leaves the same
// result when run twice: "make sure this exists" or "make sure this is
// gone".
//
// EnsureTaskFIFOs is the one that makes something new each time: fresh
// FIFOs, renamed over the last pair. A second run replaces a pair only
// the first run made, and the agent never saw that pair (the answer that
// names it was lost), so no reader holds it and no task was given it.
var retrySafe = map[string]bool{
	rootdpb.FeatureEnsureHost:           true,
	rootdpb.FeatureEnsureHostFiles:      true,
	rootdpb.FeatureEnsureTaskFIFOs:      true,
	rootdpb.FeatureEnsureRunscConfig:    true,
	rootdpb.FeatureEnsureReadySocket:    true,
	rootdpb.FeatureRemoveContainerFiles: true,
}

// Retries of a dropped call: a growing wait from retryFirstWait to
// retryMaxWait, for at most one client timeout after the first drop (not
// after the call began: a long call cut by a swap's drain deadline is
// tried again too). A swap is usually over in well under a second, and a
// connection made meanwhile waits in the socket's backlog for the next
// helper; a helper that stays away still fails the call within about
// twice the timeout of its drop, as a 503.
const (
	retryFirstWait = 20 * time.Millisecond
	retryMaxWait   = 250 * time.Millisecond
)

// retryCall waits before the next try of a dropped call, and says whether
// to make it: only a call safe to run twice, whose caller still waits,
// within the retry window, on a client that is open.
func (c *Client) retryCall(ctx context.Context, feature string, firstDrop *time.Time, attempt int, dropped bool) bool {
	if !dropped || !retrySafe[feature] || ctx.Err() != nil || c.isClosed() {
		return false
	}
	if firstDrop.IsZero() {
		*firstDrop = time.Now()
	}
	wait := min(retryFirstWait<<min(attempt, 8), retryMaxWait)
	if time.Since(*firstDrop)+wait >= c.timeout {
		return false
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// dropped reports whether a call failed for want of the helper, not by
// its answer: Unavailable without the trailer the helper puts on every
// call it handles (rootdpb.AnsweredTrailer). A refusal, or containerd's
// own Unavailable passed on, carries it; a connection that closed under
// the call, or could not be made, does not.
func dropped(err error, trailer metadata.MD) bool {
	if _, refused := rootdpb.RefusalReason(err); refused {
		return false
	}
	return status.Code(err) == codes.Unavailable && len(trailer.Get(rootdpb.AnsweredTrailer)) == 0
}

// droppedBefore reports whether reaching the helper failed before the call
// was sent: no connection, or no handshake. The handshake is Version, a
// read, so trying again is always safe. A helper too old for the call is
// no such failure.
func droppedBefore(err error) bool {
	var ue *UnsupportedError
	return errors.Is(err, ErrUnavailable) && !errors.As(err, &ue)
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// callContext bounds a typed call by the client's timeout when the caller
// set no deadline: a helper stuck inside a call must not hang a create
// (review M4).
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

// callErr turns a typed call's gRPC error into the client's own. A refusal
// (the helper's HelperRefused detail) is recorded and is a RefusedError. A
// helper that went away, did not answer in time, or whose connection this
// client closed under the call (a failed re-handshake) is ErrUnavailable;
// a call it turns out not to have is an UnsupportedError. A cancel that is
// the caller's own, and anything else the helper answered, comes back as
// it is.
func (c *Client) callErr(ctx context.Context, s *session, feature string, err error) error {
	if reason, ok := rootdpb.RefusalReason(err); ok {
		return &RefusedError{Refusal: c.refused(ctx, ownMethod(feature), reason), Err: err}
	}
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.Unavailable, codes.DeadlineExceeded:
		return c.unavailable(err)
	case codes.Canceled:
		if ctx.Err() == nil {
			return c.unavailable(err)
		}
	case codes.Unimplemented:
		if s.info.Has(feature) {
			// The handshake listed it, so another helper answers now: an
			// older copy a supervisor went back to. Ask again on the next
			// call rather than trust the old list until sandboxd restarts.
			s.stale.Store(true)
		}
		return &UnsupportedError{Feature: feature, Helper: s.info}
	}
	return err
}

func (c *Client) closedErr() error {
	return fmt.Errorf("%w: the client is closed", ErrUnavailable)
}

func (c *Client) noSession() error {
	return fmt.Errorf("%w: no connection to %s", ErrUnavailable, c.socket)
}

func (c *Client) unavailable(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
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

// dial connects to the socket and checks that root serves it. Every error
// wraps ErrUnavailable.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, c.unavailable(err)
	}
	if err := c.peer(conn); err != nil {
		_ = conn.Close()
		return nil, c.unavailable(fmt.Errorf("the process serving it is not the helper: %w", err))
	}
	return conn, nil
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
// and backoff replace containerd's; the interceptors mark a call that
// failed for want of the helper (markFailure).
func (c *Client) ContainerdOptions() []cntr.Opt {
	return []cntr.Opt{cntr.WithExtraDialOpts([]grpc.DialOption{
		grpc.WithContextDialer(c.DialContainerd),
		grpc.WithConnectParams(connectParams(c.timeout)),
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			var trailer metadata.MD
			err := invoker(ctx, method, req, reply, cc, append(opts, grpc.Trailer(&trailer))...)
			return c.markFailure(ctx, method, err, trailer, nil)
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			s, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				return nil, c.markFailure(ctx, method, err, nil, nil)
			}
			return &markedStream{ClientStream: s, c: c, method: method}, nil
		}),
	})}
}

// markFailure marks a containerd call that the helper refused, or that
// failed for want of the helper, so the API answers it as it answers the
// helper's own calls:
//
//   - a refusal (the gate's HelperRefused detail): recorded once (reported
//     dedups a stream's repeated receives) and ErrRefused, never
//     ErrUnavailable: the helper answered, and a retry meets it again;
//   - a helper older than this agent (the dialer's handshake said so, in
//     the error or in c.tooOld): ErrUnsupported, with the reason, "upgrade
//     the helper" (review N5);
//   - a deadline that ran out: ErrUnavailable, as for a typed call (N3);
//   - Unavailable that the helper did not answer itself: the connection to
//     it failed, so ErrUnavailable. Unavailable that it did answer (its
//     trailer, rootdpb.AnsweredTrailer, is on the call) is containerd's own
//     error passed on by the gate, and keeps containerd's meaning (N4).
//
// containerd's client rebuilds most errors from the gRPC status
// (errgrpc.ToNative), which drops any Go error chain but keeps status
// details that are errors. So the mark rides twice: as a detail of the
// status (rootdpb.HelperUnavailable or HelperUnsupported), for the calls
// containerd converts, and in the chain of the error returned, for the
// calls it hands back as they are (review M1).
func (c *Client) markFailure(ctx context.Context, method string, err error, trailer metadata.MD, reported *atomic.Bool) error {
	var already *marked
	if err == nil || errors.As(err, &already) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if reason, refused := rootdpb.RefusalReason(err); refused {
		if reported == nil || reported.CompareAndSwap(false, true) {
			c.refused(ctx, method, reason)
		}
		// The status keeps the helper's detail, which is an error matching
		// ErrRefused, so the error containerd's client rebuilds from it
		// still matches.
		return &marked{st: st, is: ErrRefused}
	}
	ue, unreached := (*UnsupportedError)(nil), st.Code() == codes.Unavailable && len(trailer.Get(rootdpb.AnsweredTrailer)) == 0
	if !errors.As(err, &ue) && unreached {
		ue = c.tooOld.Load()
	}
	switch {
	case ue != nil:
		return mark(st, &rootdpb.HelperUnsupported{Reason: ue.Error()}, ErrUnsupported)
	case unreached, st.Code() == codes.DeadlineExceeded:
		return mark(st, &rootdpb.HelperUnavailable{}, ErrUnavailable)
	}
	return err
}

func mark(st *status.Status, detail protoadapt.MessageV1, is error) error {
	if withDetail, err := st.WithDetails(detail); err == nil {
		st = withDetail
	}
	return &marked{st: st, is: is}
}

// marked is a failed call's status, with the mark.
type marked struct {
	st *status.Status
	is error
}

func (e *marked) Error() string              { return e.st.Err().Error() }
func (e *marked) GRPCStatus() *status.Status { return e.st }
func (e *marked) Is(target error) bool       { return target == e.is }

// markedStream marks the errors of a streaming call (an event
// subscription, a container list, a content write) as markFailure does.
// The trailer is read only after a receive failed, when gRPC has it; a
// failed send is the connection's.
type markedStream struct {
	grpc.ClientStream
	c      *Client
	method string
	// reported holds a refusal to one record: gRPC answers every receive
	// after a failed one with the same status.
	reported atomic.Bool
}

func (s *markedStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	return s.c.markFailure(s.Context(), s.method, err, s.Trailer(), &s.reported)
}

func (s *markedStream) SendMsg(m any) error {
	return s.c.markFailure(s.Context(), s.method, s.ClientStream.SendMsg(m), nil, &s.reported)
}

func connectParams(timeout time.Duration) grpc.ConnectParams {
	bc := backoff.DefaultConfig
	bc.BaseDelay = 100 * time.Millisecond
	bc.MaxDelay = maxReconnectDelay
	return grpc.ConnectParams{Backoff: bc, MinConnectTimeout: timeout}
}

// Close closes the helper's connection, and ends a handshake in flight.
// Calls after it fail with ErrUnavailable. containerd's client has its own
// connection, which its Close closes.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.ready.Store(false)
	if s := c.sess.Load(); s != nil {
		c.sess.Store(nil)
		_ = s.conn.Close()
	}
	if a := c.inflight; a != nil {
		_ = a.conn.Close()
	}
	return nil
}
