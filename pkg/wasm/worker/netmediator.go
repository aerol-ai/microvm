package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// EgressObserver is notified after a successful DialContext. Implementations
// must be non-blocking (or fire-and-forget); the dial path must not wait on
// audit I/O. Destination is host or host:port — never credentials.
type EgressObserver func(sandboxID, network, address string)

// EgressDenialObserver is notified when policy refuses a dial or a TLS
// hello (plans/egress-domain-filtering.md H5). Same non-blocking contract
// as EgressObserver; reason is one of the mediator's denial reasons.
type EgressDenialObserver func(sandboxID, network, address, reason string)

// NetMediator is the host-mediated TCP egress surface for UC-43. Guest WASI
// sockets (when wired) and host-side proxies dial through here so bytes and
// quota blocks are observable per sandbox.
type NetMediator struct {
	mu sync.RWMutex
	// sandboxID -> block flags
	blocked map[string]struct{ ingress, egress bool }
	usage   map[string]*workerNetUsage
	// observer is called after a successful dial (destination attribution).
	observer EgressObserver
	// denialObserver is called when policy refuses a connection (H5).
	denialObserver EgressDenialObserver
	// policies are the per-sandbox egress policies (P1-6); guard is the
	// operator dial guard. No policy keeps the open default.
	policies map[string]*egresspolicy.Policy
	guard    egresspolicy.DialGuard
	// upstream chains allowed names through the operator's proxy
	// (§5.10 PC-4); nil dials direct.
	upstream *egresspolicy.Upstream
	// learn holds the recordings of sandboxes that have been in learn
	// mode (P2-7). A recording outlives a switch to enforce, so the owner
	// can still read it; ForgetLearned drops it when the sandbox goes.
	learn map[string]*egresspolicy.Recorder
	// stopOperator ends the SB_EGRESS_OPERATOR_FILE poll (§5.10) that keeps
	// a running worker's floor, zone and upstream current; operatorDone
	// closes once it has. Both nil without the file.
	stopOperator context.CancelFunc
	operatorDone chan struct{}

	// conns are the live mediated connections per sandbox, each with the
	// destination it was admitted for, so a narrowed policy, an egress block
	// or a tightened operator guard closes the ones it no longer admits
	// (the gateway's registry, internal/egress/conns.go). An entry leaves
	// when its connection closes, and the engine closes every connection of
	// an instance it stops, so the registry holds only open sockets.
	connMu sync.Mutex
	conns  map[string]map[*meteredConn]struct{}
}

func newNetMediator() *NetMediator {
	return &NetMediator{
		blocked: make(map[string]struct{ ingress, egress bool }),
		usage:   make(map[string]*workerNetUsage),
	}
}

// SetEgressObserver installs (or clears, when nil) the post-dial attribution
// callback. Safe to call concurrently with DialContext.
func (m *NetMediator) SetEgressObserver(obs EgressObserver) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.observer = obs
	m.mu.Unlock()
}

// SetEgressDenialObserver installs (or clears) the denial audit callback.
func (m *NetMediator) SetEgressDenialObserver(obs EgressDenialObserver) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.denialObserver = obs
	m.mu.Unlock()
}

func (m *NetMediator) observeDenial(sandboxID, network, address, reason string) {
	m.mu.RLock()
	obs := m.denialObserver
	m.mu.RUnlock()
	if obs != nil {
		obs(sandboxID, network, address, reason)
	}
}

func (m *NetMediator) egressObserver() EgressObserver {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.observer
}

func (m *NetMediator) usageFor(sandboxID string) *workerNetUsage {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.usage[sandboxID] == nil {
		m.usage[sandboxID] = &workerNetUsage{}
	}
	return m.usage[sandboxID]
}

func (m *NetMediator) SetBlocks(sandboxID string, blockIngress, blockEgress bool) {
	if sandboxID == "" {
		return
	}
	m.mu.Lock()
	if !blockIngress && !blockEgress {
		delete(m.blocked, sandboxID)
	} else {
		m.blocked[sandboxID] = struct{ ingress, egress bool }{ingress: blockIngress, egress: blockEgress}
	}
	m.mu.Unlock()
	if blockEgress {
		// A block stops bytes, not just new dials: the gateway closes a
		// newly blocked sandbox's proxied connections the same way.
		m.revalidate(sandboxID)
	}
}

// AddBlocks ORs blocks into the sandbox's current state; it never lifts one.
// Instantiation paths use it with the blocks carried in caps.
func (m *NetMediator) AddBlocks(sandboxID string, blockIngress, blockEgress bool) {
	if sandboxID == "" || (!blockIngress && !blockEgress) {
		return
	}
	m.mu.Lock()
	cur := m.blocked[sandboxID]
	m.blocked[sandboxID] = struct{ ingress, egress bool }{ingress: cur.ingress || blockIngress, egress: cur.egress || blockEgress}
	m.mu.Unlock()
	if blockEgress {
		m.revalidate(sandboxID)
	}
}

func (m *NetMediator) egressBlocked(sandboxID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blocked[sandboxID]
	return ok && b.egress
}

func (m *NetMediator) ingressBlocked(sandboxID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blocked[sandboxID]
	return ok && b.ingress
}

// DialContext dials address when egress is allowed and counts bytes in/out.
// On success, the EgressObserver (if any) is invoked asynchronously with the
// destination — attribution must not block the dial path. Per-destination
// bytes stay best-effort; aggregate totals use DrainUsage / netstats.
func (m *NetMediator) DialContext(ctx context.Context, sandboxID, network, address string) (net.Conn, error) {
	if m.egressBlocked(sandboxID) {
		return nil, wasmengine.ErrNetworkEgressBlocked
	}
	var conn net.Conn
	var dest connDest
	var err error
	if p := m.policyFor(sandboxID); p != nil {
		conn, dest, err = m.policyDial(ctx, sandboxID, p, network, address)
	} else {
		conn, dest, err = m.openDial(ctx, network, address)
	}
	if err != nil {
		var denied *wasmengine.EgressDeniedError
		if errors.As(err, &denied) {
			m.observeDenial(sandboxID, network, address, denied.Reason)
		}
		return nil, err
	}
	mc, err := m.track(sandboxID, dest, conn)
	if err != nil {
		return nil, err
	}
	if obs := m.egressObserver(); obs != nil {
		// Observer is responsible for non-blocking enqueue (bounded pool).
		obs(sandboxID, network, address)
	}
	return mc, nil
}

// track registers a mediated connection against its sandbox, then confirms
// its admission still holds. A policy, block or guard change that landed
// while the dial was in flight scanned the registry before this connection
// was in it, so it is re-decided here against the current state; a change
// after registration finds it in the registry.
func (m *NetMediator) track(sandboxID string, dest connDest, conn net.Conn) (net.Conn, error) {
	mc := &meteredConn{Conn: conn, usage: m.usageFor(sandboxID), m: m, sandboxID: sandboxID, dest: dest}
	m.connMu.Lock()
	if m.conns == nil {
		m.conns = map[string]map[*meteredConn]struct{}{}
	}
	if m.conns[sandboxID] == nil {
		m.conns[sandboxID] = map[*meteredConn]struct{}{}
	}
	m.conns[sandboxID][mc] = struct{}{}
	m.connMu.Unlock()
	if !admits(m.admissionState(sandboxID), dest) {
		_ = mc.Close()
		return nil, wasmengine.ErrNetworkEgressBlocked
	}
	return mc, nil
}

func (m *NetMediator) untrack(c *meteredConn) {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	delete(m.conns[c.sandboxID], c)
	if len(m.conns[c.sandboxID]) == 0 {
		delete(m.conns, c.sandboxID)
	}
}

// admission is what a sandbox's connections are decided against.
type admission struct {
	blocked bool
	policy  *egresspolicy.Policy
	guard   egresspolicy.DialGuard
}

func (m *NetMediator) admissionState(sandboxID string) admission {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return admission{blocked: m.blocked[sandboxID].egress, policy: m.policies[sandboxID], guard: m.guard}
}

// revalidate closes the sandbox's live connections that an egress block, its
// current policy or the operator guard would not admit now.
func (m *NetMediator) revalidate(sandboxID string) {
	a := m.admissionState(sandboxID)
	m.connMu.Lock()
	var victims []*meteredConn
	for c := range m.conns[sandboxID] {
		if !admits(a, c.dest) {
			victims = append(victims, c)
		}
	}
	m.connMu.Unlock()
	// Closed outside connMu: Close unregisters, which takes it again.
	for _, c := range victims {
		_ = c.Close()
	}
}

// revalidateAll re-decides every sandbox's live connections: a guard change
// binds all of them.
func (m *NetMediator) revalidateAll() {
	m.connMu.Lock()
	ids := make([]string, 0, len(m.conns))
	for id := range m.conns {
		ids = append(ids, id)
	}
	m.connMu.Unlock()
	for _, id := range ids {
		m.revalidate(id)
	}
}

// meteredConn counts a mediated connection's bytes and keeps it in the
// mediator's registry until it closes.
type meteredConn struct {
	net.Conn
	usage *workerNetUsage

	m         *NetMediator
	sandboxID string
	dest      connDest
	once      sync.Once
	closeErr  error
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.usage.bytesIn.Add(int64(n))
	}
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.usage.bytesOut.Add(int64(n))
	}
	return n, err
}

// Close closes the connection once, whether the guest or a revocation gets
// there first, and drops it from the registry.
func (c *meteredConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.m.untrack(c)
	})
	return c.closeErr
}

// Copy counts bytes moved through the mediator for tests and host proxies.
func (m *NetMediator) Copy(sandboxID string, dst io.Writer, src io.Reader, outbound bool) (int64, error) {
	u := m.usageFor(sandboxID)
	if outbound && m.egressBlocked(sandboxID) {
		return 0, wasmengine.ErrNetworkEgressBlocked
	}
	if !outbound && m.ingressBlocked(sandboxID) {
		return 0, errors.New("network ingress blocked by quota")
	}
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if outbound {
				u.bytesOut.Add(int64(n))
			} else {
				u.bytesIn.Add(int64(n))
			}
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

// DrainUsage returns and clears accumulated socket bytes for sandboxID.
func (m *NetMediator) DrainUsage(sandboxID string) (in, out int64) {
	u := m.usageFor(sandboxID)
	return u.bytesIn.Swap(0), u.bytesOut.Swap(0)
}
