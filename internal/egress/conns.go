package egress

import (
	"net"
	"net/netip"
	"sync"
)

// TrackedConn is a proxied connection registered against its sandbox, so a
// block, a detach or a narrowing policy can close it (EF-13, §5.5 registry).
type TrackedConn struct {
	conn net.Conn
	// Host is the SNI or Host the connection was allowed for, and Port the
	// redirected port it came in on.
	Host string
	Port uint16
	once sync.Once
	g    *Gateway
	id   string
}

// Close closes the underlying connection and unregisters it.
func (c *TrackedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.conn.Close()
		c.g.unregister(c)
	})
	return err
}

// Track registers conn for sandbox id. The caller closes it through the
// returned TrackedConn when the proxied exchange ends.
func (g *Gateway) Track(id, host string, port uint16, conn net.Conn) *TrackedConn {
	tc := &TrackedConn{conn: conn, Host: host, Port: port, g: g, id: id}
	g.connMu.Lock()
	if g.conns[id] == nil {
		g.conns[id] = map[*TrackedConn]struct{}{}
	}
	g.conns[id][tc] = struct{}{}
	g.connMu.Unlock()
	return tc
}

func (g *Gateway) unregister(c *TrackedConn) {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	delete(g.conns[c.id], c)
	if len(g.conns[c.id]) == 0 {
		delete(g.conns, c.id)
	}
}

// closeConns closes every tracked connection of a sandbox.
func (g *Gateway) closeConns(id string) {
	g.CloseConnsWhere(id, func(string, uint16) bool { return true })
}

// CloseConnsWhere closes a sandbox's tracked connections whose host and port
// match pred; a policy update closes the ones the new policy no longer
// allows.
func (g *Gateway) CloseConnsWhere(id string, pred func(host string, port uint16) bool) int {
	g.connMu.Lock()
	var victims []*TrackedConn
	for c := range g.conns[id] {
		if pred(c.Host, c.Port) {
			victims = append(victims, c)
		}
	}
	g.connMu.Unlock()
	for _, c := range victims {
		_ = c.Close()
	}
	return len(victims)
}

// permits reports whether e's policy still allows a proxied connection to
// host on port, by the same rule the proxy applied when it opened it.
func (e *entry) permits(host string, port uint16) bool {
	if e.mode != ModeAllowlist {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ok, _ := e.pol.MatchIP(ip, port)
		return ok
	}
	ok, _ := e.pol.MatchHostPort(host, port)
	return ok
}

// ConnCount returns the number of tracked connections for a sandbox.
func (g *Gateway) ConnCount(id string) int {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	return len(g.conns[id])
}
