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
// sandboxd uses it in privilege mode split (internal/privmode): the
// containerd engine's network work goes through the network calls below.
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
	// DefaultNetworkTimeout bounds a network call whose context has no
	// deadline. A namespace build runs CNI plugins and waits on host-wide
	// locks (the IPAM plugin's, the xtables lock), so under a burst of
	// creates it queues behind the others for seconds, as it does in
	// single mode, where nothing bounds it at all (PR 4 review: at the
	// 2 s of DefaultTimeout, 90 of 100 parallel builds failed while the
	// helper still finished them).
	DefaultNetworkTimeout = time.Minute
	// DefaultMountTimeout bounds a mount call whose context has no
	// deadline. A mount set waits for each of up to eight tools to serve
	// (SB_MOUNT_WAIT_TIMEOUT each, 30 s by default), and an unmount or a
	// sweep stops tools and unmounts, a few seconds each.
	DefaultMountTimeout = 5 * time.Minute
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

// ErrBusy: the helper has as many network calls running and waiting as it
// takes, and answered this one at once without running it. The API maps
// it to 503; it is not tried again here, since the load that caused it is
// still there.
var ErrBusy = errors.New("root helper: at its limit of network calls in flight")

// ErrUnsupported: the helper is older than this agent and lacks what the
// agent asked for. The API maps it to 503 too: the agent stages the newer
// helper and the supervisor swaps it in (eng review D4).
var ErrUnsupported = rootdpb.ErrHelperUnsupported

// Info is what the helper said in the handshake.
type Info struct {
	HelperVersion string
	API           uint32
	Features      []string
	// Parts are the parts of PrepareSandbox and ReleaseSandbox the helper
	// serves (rootdpb.Parts).
	Parts []string
}

// Has reports whether the helper serves feature.
func (i Info) Has(feature string) bool { return slices.Contains(i.Features, feature) }

// HasPart reports whether the helper serves part of PrepareSandbox and
// ReleaseSandbox.
func (i Info) HasPart(part string) bool { return slices.Contains(i.Parts, part) }

func infoOf(resp *rootdpb.VersionResponse) Info {
	return Info{HelperVersion: resp.GetHelperVersion(), API: resp.GetApi(), Features: resp.GetFeatures(), Parts: resp.GetParts()}
}

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
	// whose context has no deadline, the network calls aside. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// NetworkTimeout bounds a network call (networkCalls) whose context
	// has no deadline. Zero means DefaultNetworkTimeout.
	NetworkTimeout time.Duration
	// MountTimeout bounds a mount call (mountCalls) whose context has no
	// deadline. Zero means DefaultMountTimeout.
	MountTimeout time.Duration
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
	netTimeout   time.Duration
	mountTimeout time.Duration
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
	c := &Client{socket: cfg.Socket, timeout: cfg.Timeout, netTimeout: cfg.NetworkTimeout, mountTimeout: cfg.MountTimeout, agentVersion: cfg.AgentVersion,
		peer: egress.UnixPeerCheck([]uint32{cfg.HelperUID}, ""), onRefusal: cfg.OnRefusal}
	if c.socket == "" {
		c.socket = DefaultSocket
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.netTimeout <= 0 {
		c.netTimeout = DefaultNetworkTimeout
	}
	if c.mountTimeout <= 0 {
		c.mountTimeout = DefaultMountTimeout
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
		err = &UnsupportedError{Helper: infoOf(resp)}
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
		info: infoOf(resp)})
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

// EnsureHost is EnsureHostFirewall for a caller that needs no more than
// whether it worked.
func (c *Client) EnsureHost(ctx context.Context) error {
	_, err := c.EnsureHostFirewall(ctx)
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

// The calls below are a containerd sandbox's network work (internal/rootd
// network.go): its named network namespace, its CNI attachment and its
// address. The agent's netns pool keeps its bookkeeping and names a
// namespace by its pool name; the helper builds every path, runs CNI with
// its own config, and touches only namespaces that are a sandbox's.

// EnsureHostNetwork has the helper make the host ready for sandbox
// networks and answers the sandboxes' address range its CNI config hands
// out.
func (c *Client) EnsureHostNetwork(ctx context.Context) (string, error) {
	resp, err := call(ctx, c, rootdpb.FeatureEnsureHostNetwork, &rootdpb.EnsureHostNetworkRequest{}, rootdpb.RootHelperClient.EnsureHostNetwork)
	return resp.GetSubnet(), err
}

// RealizeNetns has the helper make sure the namespace name exists and is
// attached, and answers its path and address.
func (c *Client) RealizeNetns(ctx context.Context, name string) (path, ip string, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureRealizeNetns, &rootdpb.RealizeNetnsRequest{NetnsName: name}, rootdpb.RootHelperClient.RealizeNetns)
	return resp.GetNetnsPath(), resp.GetContainerIp(), err
}

// RemoveNetns has the helper make sure the namespace name is gone, with
// its attachment and the NAT and connection tracking state of ip (the
// address the pool recorded; empty when none was).
func (c *Client) RemoveNetns(ctx context.Context, name, ip string) error {
	_, err := call(ctx, c, rootdpb.FeatureRemoveNetns, &rootdpb.RemoveNetnsRequest{NetnsName: name, ContainerIp: ip}, rootdpb.RootHelperClient.RemoveNetns)
	return err
}

// DisableNetnsIPv6 has the helper turn IPv6 off inside a realized
// namespace.
func (c *Client) DisableNetnsIPv6(ctx context.Context, name string) error {
	_, err := call(ctx, c, rootdpb.FeatureDisableNetnsIPv6, &rootdpb.DisableNetnsIPv6Request{NetnsName: name}, rootdpb.RootHelperClient.DisableNetnsIPv6)
	return err
}

// NetnsAddrs says whether the namespace name exists and lists its IPv4
// addresses, loopback aside.
func (c *Client) NetnsAddrs(ctx context.Context, name string) (exists bool, ipv4 []string, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureNetnsAddrs, &rootdpb.NetnsAddrsRequest{NetnsName: name}, rootdpb.RootHelperClient.NetnsAddrs)
	return resp.GetExists(), resp.GetIpv4(), err
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
		cctx, cancel := c.callContext(ctx, feature)
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
//
// The network calls:
//   - EnsureHostNetwork sets sysctls to fixed values and writes the CNI
//     config only when it is absent.
//   - RealizeNetns answers a namespace it already realized as it is (the
//     helper reads it back from the kernel), and clears a half-made one
//     whole before it builds again; so a second run never attaches the
//     sandbox twice or gives it a second address.
//   - RemoveNetns is "make sure it is gone": CNI DEL is idempotent by the
//     CNI contract, the NAT teardown and the connection tracking flush go
//     by identity, and a missing namespace is success.
//   - DisableNetnsIPv6 writes fixed sysctl values; NetnsAddrs is a read.
//
// The firewall calls (M1 PR 5) each make a rule present or absent, by
// the address it is for:
//   - EnsureHost makes sure of the chains, the block sets, the forwarding
//     sysctls and the IPv6 fence; SetNodeGuard and SetEgressFloor replace
//     a whole list with the one sent.
//   - SandboxRules checks for a rule before it adds one, and a missing one
//     is no error to remove. One answer is lost by a retry: whether the
//     block-all rule was new (inserted). The retry answers "already
//     there", so the agent leaves the block in place when the sandbox's
//     own block is lifted: a sandbox stays more closed, never more open.
//   - PrepareSandbox is RealizeNetns and SandboxRules in one call, with
//     the same answers to a repeat; ReleaseSandbox is "make sure it is
//     gone" for both. Its cgroup part (M1 PR 6) writes the same two
//     values to the same group each time. Its files part (M1 PR 7) is the
//     file calls above in one: the same host files, ready socket name,
//     runsc config and toolbox each time, and fresh FIFOs, as
//     EnsureTaskFIFOs makes them; ReleaseSandbox's files part is
//     RemoveContainerFiles.
//
// The hostname gateway's calls (M1 PR 5b): BridgeProbe's set-up replaces
// what its slot had, its send sends one more probe (the gateway counts
// flows seen, not their number), and its close is "make sure it is
// gone"; MatchProcess is a read. HostPort sets a port's forward, removes
// it, or makes the node's set exact: each "make it so", whatever the
// first attempt did.
//
// The mount calls (M1 PR 8): UnmountExternal is "make sure it is gone",
// and SweepExternalMounts removes what no sandbox keeps; both are safe to
// run again. MountExternal is not tried again: a create's set refuses a
// sandbox whose mounts serve, so a second try of one the first made would
// fail it, and a dropped create is rolled back by the service's
// UnmountAll (or the next sweep) like any failed one. A start's or a
// reconcile's set is tried again by the next reconcile pass.
var retrySafe = map[string]bool{
	rootdpb.FeatureMountExternal:        false,
	rootdpb.FeatureUnmountExternal:      true,
	rootdpb.FeatureSweepExternalMounts:  true,
	rootdpb.FeatureEnsureHost:           true,
	rootdpb.FeatureEnsureHostFiles:      true,
	rootdpb.FeatureEnsureTaskFIFOs:      true,
	rootdpb.FeatureEnsureRunscConfig:    true,
	rootdpb.FeatureEnsureReadySocket:    true,
	rootdpb.FeatureRemoveContainerFiles: true,
	rootdpb.FeatureEnsureHostNetwork:    true,
	rootdpb.FeatureRealizeNetns:         true,
	rootdpb.FeatureRemoveNetns:          true,
	rootdpb.FeatureDisableNetnsIPv6:     true,
	rootdpb.FeatureNetnsAddrs:           true,
	rootdpb.FeatureSetNodeGuard:         true,
	rootdpb.FeatureSetEgressFloor:       true,
	rootdpb.FeatureSandboxRules:         true,
	rootdpb.FeaturePrepareSandbox:       true,
	rootdpb.FeatureReleaseSandbox:       true,
	rootdpb.FeatureBridgeProbe:          true,
	rootdpb.FeatureMatchProcess:         true,
	rootdpb.FeatureHostPort:             true,
	// The volume's folder emptied again is the same empty folder.
	rootdpb.FeatureReclaimVolume: true,
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
// (review M4). A network call gets the network timeout.
func (c *Client) callContext(ctx context.Context, feature string) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	if networkCalls[feature] {
		return context.WithTimeout(ctx, c.netTimeout)
	}
	if mountCalls[feature] {
		return context.WithTimeout(ctx, c.mountTimeout)
	}
	return context.WithTimeout(ctx, c.timeout)
}

// networkCalls are the calls bounded by the network timeout: they run CNI
// plugins, or wait for a namespace's lock behind one that does.
var networkCalls = map[string]bool{
	rootdpb.FeatureEnsureHostNetwork: true,
	rootdpb.FeatureRealizeNetns:      true,
	rootdpb.FeatureRemoveNetns:       true,
	rootdpb.FeatureDisableNetnsIPv6:  true,
	rootdpb.FeatureNetnsAddrs:        true,
	// The firewall's calls wait on the xtables lock, and the two per-create
	// calls on CNI too.
	rootdpb.FeatureEnsureHost:     true,
	rootdpb.FeatureSetNodeGuard:   true,
	rootdpb.FeatureSetEgressFloor: true,
	rootdpb.FeatureSandboxRules:   true,
	rootdpb.FeaturePrepareSandbox: true,
	rootdpb.FeatureReleaseSandbox: true,
	// Host-port forwarding waits on the xtables lock, and a node's whole
	// set (up to its range's ports) is written rule by rule.
	rootdpb.FeatureHostPort: true,
}

// mountCalls are the calls bounded by the mount timeout: they wait for
// mount tools to serve, or stop them.
var mountCalls = map[string]bool{
	rootdpb.FeatureMountExternal:       true,
	rootdpb.FeatureUnmountExternal:     true,
	rootdpb.FeatureSweepExternalMounts: true,
	// An NFS mount, a delete of a volume's files, an unmount.
	rootdpb.FeatureReclaimVolume: true,
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
	case codes.ResourceExhausted:
		return fmt.Errorf("%w: %w", ErrBusy, err)
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
