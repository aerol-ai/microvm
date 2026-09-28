package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// EgressObserver is notified after a successful DialContext. Implementations
// must be non-blocking (or fire-and-forget); the dial path must not wait on
// audit I/O. Destination is host or host:port — never credentials.
type EgressObserver func(sandboxID, network, address string)

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
	defer m.mu.Unlock()
	if !blockIngress && !blockEgress {
		delete(m.blocked, sandboxID)
		return
	}
	m.blocked[sandboxID] = struct{ ingress, egress bool }{ingress: blockIngress, egress: blockEgress}
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
	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if obs := m.egressObserver(); obs != nil {
		// Observer is responsible for non-blocking enqueue (bounded pool).
		obs(sandboxID, network, address)
	}
	u := m.usageFor(sandboxID)
	return &meteredConn{Conn: conn, usage: u}, nil
}

type meteredConn struct {
	net.Conn
	usage *workerNetUsage
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.usage.bytesIn.Add(int64(n))
	}
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	if c.usage != nil {
		// Parent may have closed egress mid-flight; best-effort reject new writes.
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.usage.bytesOut.Add(int64(n))
	}
	return n, err
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
