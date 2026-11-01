package harness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// The harness talks to the scenario's API domain the way a client behind a
// health-checked load balancer would.
//
// The API domain has one A record per ingress node (Terraform/dns.tf), each
// node's Caddy proxies /v1 only to its own daemon, and Go keeps a keep-alive
// connection to whichever address it dialled first. So when a case stops
// sandboxd on a node and leaves Caddy up, a client whose connection happens
// to be to that node's Caddy gets a 502 on every request for the whole
// outage. On cluster-3-mixed-secrets (main f34b607e) UC-135 and UC-118's
// docker/failover-recreate row polled the placement for 8 minutes and
// reported "never reassigned", while node3 had recreated the sandbox about
// 40 s after the kill. The cases were testing which node DNS handed out,
// not failover.
//
// A production deployment puts a load balancer in front whose /health check
// reaches the local daemon through Caddy, so a node whose daemon is down
// leaves the pool. The harness models exactly that and nothing more: helpers
// that take a daemon down mark the node's public IP down, and every client
// that talks to the API domain dials through apiPool, which skips marked
// addresses. Round-robin DNS without health checks is a real product gap; it
// is handled in Terraform, not papered over here.

// apiPool is the one pool every harness and suite client shares.
var apiPool = newLBPool(
	func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	},
	// The same dialer settings as http.DefaultTransport.
	(&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
)

// sharedTransport is http.DefaultTransport's configuration with apiPool's
// dialer, shared by the SDK client, APIClient and the raw request helpers so
// they share one connection pool for MarkNodeDown to clear.
var sharedTransport = apiPool.newTransport(nil)

// SharedTransport is the transport every client that talks to the API domain
// must use, so that MarkNodeDown routes it away from a node whose daemon a
// case took down.
func SharedTransport() *http.Transport { return sharedTransport }

// HTTPClient is an http.Client on SharedTransport. A zero timeout means none,
// as with http.DefaultClient.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: sharedTransport}
}

// NewTransport is a transport with its own connection pool (for a case that
// needs different pool or TLS settings) that still dials through apiPool.
// configure may adjust anything except DialContext. MarkNodeDown clears it
// too, so it is remembered for the life of the test binary; make one per
// case, not one per request.
func NewTransport(configure func(*http.Transport)) *http.Transport {
	return apiPool.newTransport(configure)
}

// MarkNodeDown takes publicIP out of the API pool: new connections skip it,
// and every open connection to it is closed. Idle connections on every
// harness transport are closed as well, so nothing keeps a request pinned to
// the old address. A request in flight to that node fails at once; callers
// mark a node down only after its daemon is already stopped, when such a
// request could only end in a 502.
//
// An empty or unparsable address is ignored: a node with no public IP is not
// in the API domain's A records.
func MarkNodeDown(publicIP string) { apiPool.setDown(publicIP, true) }

// MarkNodeUp returns publicIP to the API pool. Helpers call it only once the
// daemon is running again and the node has rejoined, which is when a load
// balancer's health check would pass.
func MarkNodeUp(publicIP string) { apiPool.setDown(publicIP, false) }

// lbPool resolves a host, skips the addresses marked down, and dials the rest
// in the resolver's order. It remembers every transport it built and every
// connection it opened so MarkNodeDown can clear them.
type lbPool struct {
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)

	mu         sync.Mutex
	down       map[netip.Addr]bool
	conns      map[*poolConn]struct{}
	transports []*http.Transport
}

func newLBPool(
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error),
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
) *lbPool {
	return &lbPool{
		lookup: lookup,
		dial:   dial,
		down:   map[netip.Addr]bool{},
		conns:  map[*poolConn]struct{}{},
	}
}

// newTransport clones http.DefaultTransport (proxy, TLS handshake timeout,
// HTTP/2) and swaps in the pool's dialer.
func (p *lbPool) newTransport(configure func(*http.Transport)) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if configure != nil {
		configure(tr)
	}
	tr.DialContext = p.DialContext
	p.mu.Lock()
	p.transports = append(p.transports, tr)
	p.mu.Unlock()
	return tr
}

// poolKey normalises an address so "203.0.113.10", " 203.0.113.10 " and its
// IPv4-mapped form all name the same node.
func poolKey(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

func (p *lbPool) setDown(ip string, down bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return
	}
	key := poolKey(addr)
	p.mu.Lock()
	if !down {
		delete(p.down, key)
		p.mu.Unlock()
		return
	}
	p.down[key] = true
	transports := append([]*http.Transport(nil), p.transports...)
	var doomed []*poolConn
	for c := range p.conns {
		if c.key == key {
			doomed = append(doomed, c)
		}
	}
	p.mu.Unlock()

	// Idle connections first, through the transports, so each pool drops
	// them cleanly. That alone misses a connection that is mid-request at
	// this moment: it returns to the idle pool when the response lands and
	// is reused for every later request, which is the 502 loop this exists
	// to prevent. Closing the node's connections directly covers it.
	for _, tr := range transports {
		tr.CloseIdleConnections()
	}
	for _, c := range doomed {
		_ = c.Close()
	}
}

// candidates is addrs minus the ones marked down, in order. When every
// address is down it is all of them: a case that downs the only ingress must
// still fail loudly on the request, not hang or fail on a dial error that
// hides what it did.
func (p *lbPool) candidates(addrs []netip.Addr) []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	up := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !p.down[poolKey(a)] {
			up = append(up, a)
		}
	}
	if len(up) == 0 {
		return addrs
	}
	return up
}

// resolve returns host's addresses. An IP literal is its own answer, so a
// case that dials one node on purpose still reaches it.
func (p *lbPool) resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	family := "ip"
	switch network {
	case "tcp4":
		family = "ip4"
	case "tcp6":
		family = "ip6"
	}
	addrs, err := p.lookup(ctx, family, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("lookup %s: no %s addresses", host, family)
	}
	return addrs, nil
}

// DialContext is the transports' dialer.
func (p *lbPool) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := p.resolve(ctx, network, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, a := range p.candidates(addrs) {
		conn, err := p.dial(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return p.track(conn, poolKey(a)), nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 1 {
		return nil, errs[0]
	}
	return nil, errors.Join(errs...)
}

func (p *lbPool) track(conn net.Conn, key netip.Addr) net.Conn {
	c := &poolConn{Conn: conn, pool: p, key: key}
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
	return c
}

// poolConn is a connection the pool opened, remembered until it closes so
// MarkNodeDown can find the ones to its node.
type poolConn struct {
	net.Conn
	pool *lbPool
	key  netip.Addr
	once sync.Once
}

func (c *poolConn) Close() error {
	c.once.Do(func() {
		c.pool.mu.Lock()
		delete(c.pool.conns, c)
		c.pool.mu.Unlock()
	})
	return c.Conn.Close()
}
