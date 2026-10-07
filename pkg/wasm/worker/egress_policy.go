package worker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Denial reasons (shared with the gateway's audit vocabulary).
const (
	reasonHostNotAllowed = "host_not_allowed"
	reasonIPNotAllowed   = "ip_not_allowed"
	reasonBlockedIP      = "blocked_ip"
	reasonSNIMismatch    = "sni_mismatch"
)

// SetPolicy installs (or, with nil, removes) a sandbox's egress policy. With
// no policy the mediator keeps today's behavior: any destination the
// operator floor allows. Connections already open that the new policy would
// not admit are closed, as the gateway does for a narrowed policy (§5.8
// FQDN → FQDN′): a live update must not leave a revoked destination
// reachable through a socket opened before it.
func (m *NetMediator) SetPolicy(sandboxID string, p *egresspolicy.Policy) {
	if sandboxID == "" {
		return
	}
	m.setPolicy(sandboxID, p)
	m.revalidate(sandboxID)
}

func (m *NetMediator) setPolicy(sandboxID string, p *egresspolicy.Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policies == nil {
		m.policies = map[string]*egresspolicy.Policy{}
	}
	if p == nil {
		delete(m.policies, sandboxID)
		return
	}
	m.policies[sandboxID] = p
	if p.Mode() == egresspolicy.ModeLearn {
		if m.learn == nil {
			m.learn = map[string]*egresspolicy.Recorder{}
		}
		if m.learn[sandboxID] == nil {
			m.learn[sandboxID] = egresspolicy.NewRecorder(egresspolicy.DefaultLearnMax)
		}
	}
}

// Learned returns a sandbox's learn-mode recording (empty if it has none).
func (m *NetMediator) Learned(sandboxID string) egresspolicy.Learned {
	m.mu.RLock()
	r := m.learn[sandboxID]
	m.mu.RUnlock()
	if r == nil {
		return egresspolicy.NewRecorder(egresspolicy.DefaultLearnMax).Snapshot()
	}
	return r.Snapshot()
}

// ForgetLearned drops a sandbox's recording when its instance goes.
func (m *NetMediator) ForgetLearned(sandboxID string) {
	m.mu.Lock()
	delete(m.learn, sandboxID)
	m.mu.Unlock()
}

// recordLearned notes a connection a learn-mode sandbox made. Only dials
// that went through are recorded, so an address the dial guard refuses never
// becomes a suggestion.
func (m *NetMediator) recordLearned(sandboxID string, p *egresspolicy.Policy, host string, port uint16) {
	if p.Mode() != egresspolicy.ModeLearn {
		return
	}
	m.mu.RLock()
	r := m.learn[sandboxID]
	m.mu.RUnlock()
	if r != nil {
		r.ObserveHost(host, port)
	}
}

// ApplyCapsPolicy installs the policy carried in caps, when the caps carry
// one. A policy that doesn't compile is enforced as block-all: fail closed.
func (m *NetMediator) ApplyCapsPolicy(sandboxID string, caps wasmengine.Capabilities) {
	if !caps.EgressPolicySet {
		return
	}
	m.SetPolicy(sandboxID, compileLists(caps.EgressAllowOut, caps.EgressDenyOut, caps.EgressLearn))
}

// compileLists compiles raw lists; empty lists mean no policy, unless the
// sandbox is in learn mode, which is open egress that is recorded.
func compileLists(allow, deny []string, learn bool) *egresspolicy.Policy {
	mode := egresspolicy.ModeEnforce
	if learn {
		mode = egresspolicy.ModeLearn
	} else if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	p, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: allow, DenyOut: deny, Mode: mode, MaxHostnames: egresspolicy.MaxUnionHostnames})
	if err != nil {
		return egresspolicy.BlockAllPolicy()
	}
	return p
}

func (m *NetMediator) policyFor(sandboxID string) *egresspolicy.Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policies[sandboxID]
}

// SetDialGuard installs the operator dial guard (internal zone, deny floor)
// and closes every live connection the new guard refuses: a tightened floor
// must cut a socket opened before it, not just the next dial.
func (m *NetMediator) SetDialGuard(g egresspolicy.DialGuard) {
	m.mu.Lock()
	m.guard = g
	m.mu.Unlock()
	m.revalidateAll()
}

// operatorPoll is how often a worker notices a changed operator file without
// a restart: the interval sandboxd polls the same file at
// (pkg/daemon egressOperatorPoll), so a tightened floor reaches WASM
// sandboxes on the same clock as every other runtime. A var for tests.
var operatorPoll = 10 * time.Second

// installOperatorGuard applies the private-cloud operator file's internal
// zone, deny floor and upstream proxy to this worker's dials
// (plans/egress-domain-filtering.md §5.10, runtime coverage: WASM uses the
// mediator's dial control), and keeps them current with the same Watcher
// sandboxd uses: a changed file is picked up by the mtime poll, and an
// invalid edit keeps the last good file. A file that can't be loaded at
// start leaves the worker strict (no private destination at all) rather
// than open, until a good one loads.
//
// The watcher has no logger: sandboxd watches the same file and already
// logs an invalid edit once per node, where every worker logging it would
// repeat that line once per WASM sandbox.
func installOperatorGuard(m *NetMediator) {
	path := strings.TrimSpace(os.Getenv("SB_EGRESS_OPERATOR_FILE"))
	if path == "" {
		return
	}
	m.stopOperatorWatch()
	w := operator.NewWatcher(path, nil, m.applyOperator)
	if w.Current() == nil {
		m.SetDialGuard(egresspolicy.DialGuard{Strict: true})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, interval := make(chan struct{}), operatorPoll
	m.mu.Lock()
	m.stopOperator, m.operatorDone = cancel, done
	m.mu.Unlock()
	go func() {
		defer close(done)
		w.Run(ctx, interval)
	}()
}

// applyOperator installs a (re)loaded operator file. An upstream chain that
// can't be built (an unreadable auth_file) keeps the previous one, as
// sandboxd does for isolate: sending without the credentials, or direct on
// a network with no other way out, helps nobody (sandboxd logs that failure
// once per node). The guard goes last, since installing it re-decides the
// live connections.
func (m *NetMediator) applyOperator(op *operator.Operator) {
	if up, err := op.UpstreamDialer(); err == nil {
		m.mu.Lock()
		m.upstream = up
		m.mu.Unlock()
	}
	m.SetDialGuard(op.Guard())
}

// stopOperatorWatch ends the operator-file poll and waits for it; the worker
// calls it when it stops serving.
func (m *NetMediator) stopOperatorWatch() {
	if m == nil {
		return
	}
	m.mu.Lock()
	stop, done := m.stopOperator, m.operatorDone
	m.stopOperator, m.operatorDone = nil, nil
	m.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
}

func (m *NetMediator) dialGuard() egresspolicy.DialGuard {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.guard
}

// connDest is the destination a mediated connection was admitted for: what a
// later policy, block or guard change re-decides it against.
type connDest struct {
	// host is the canonical name, or the IP literal, the guest dialed.
	host string
	port uint16
	// name is host when it was dialed by name ("" for an IP literal): the
	// guard's internal zone and allow-wins rule key on it.
	name string
	// addr is the address the connection reached.
	addr netip.AddrPort
	// tunneled marks a connection through the operator's upstream proxy.
	// The proxy chose its address, so the guard never judged it and only
	// the policy re-decides it.
	tunneled bool
}

// parseDest splits a guest "host:port" into the canonical host the policy
// matches and the port.
func parseDest(address string) (connDest, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return connDest{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return connDest{}, err
	}
	d := connDest{host: strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), "."), port: uint16(port)}
	if _, err := netip.ParseAddr(d.host); err != nil {
		d.name = d.host
	}
	return d, nil
}

// policyMatch is the policy half of a mediated decision: an IP literal must
// be allowed by a CIDR, a name by a host rule.
func policyMatch(p *egresspolicy.Policy, d connDest) (allowed bool, rule string) {
	if d.name == "" {
		ip, err := netip.ParseAddr(d.host)
		if err != nil {
			return false, ""
		}
		return p.MatchIP(ip.Unmap(), d.port)
	}
	return p.MatchHostPort(d.name, d.port)
}

// openCheck is the guard half for a sandbox with no policy of its own. Such
// a sandbox is open by design (§5.10 PC-2 default_policy: open), so only
// what the operator imposes on every sandbox applies: the deny floor, as the
// container runtimes get it from their node-wide rules. The private-range
// rule and the internal zone only narrow what a policy's allow rules open,
// so they stay policy-mode rules. A strict guard is this worker's "operator
// file unreadable" posture: the floor is unknown, so the whole strict guard
// applies (fail closed, as for policy dials).
func openCheck(g egresspolicy.DialGuard, name string, addr netip.AddrPort) error {
	if g.Strict {
		return g.Check(nil, egresspolicy.DialTarget{Name: name, Addr: addr})
	}
	return g.CheckFloor(addr)
}

// admits re-decides a live connection by the rules its dial was decided
// under: an egress block refuses everything; then the policy match; then
// the guard, on the address the connection actually reached.
func admits(a admission, d connDest) bool {
	if a.blocked {
		return false
	}
	nameAllowed := false
	if a.policy != nil {
		allowed, rule := policyMatch(a.policy, d)
		if !allowed {
			return false
		}
		nameAllowed = rule != ""
	}
	switch {
	case d.tunneled:
		return true
	case a.policy == nil:
		return openCheck(a.guard, d.name, d.addr) == nil
	default:
		return a.guard.Check(a.policy, egresspolicy.DialTarget{Name: d.name, NameAllowed: nameAllowed, Addr: d.addr}) == nil
	}
}

// remoteAddr is the address a direct dial reached. A connection whose
// address can't be read gets the zero AddrPort, which the guard refuses as
// invalid, so a re-check fails closed.
func remoteAddr(c net.Conn) netip.AddrPort {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort()
	}
	return netip.AddrPort{}
}

// openDial dials for a sandbox with no policy. With no operator guard it is
// today's plain dial to any destination, byte for byte (no Control hook at
// all). With one, every resolved address goes through openCheck first.
//
// It never routes through the operator's upstream proxy, even for a name
// the proxy would carry: the proxy is part of the policy path (it serves
// allowed names, PC-4), and a no-policy container doesn't use it either, so
// sending open traffic through it would change where that traffic goes, and
// with whose credentials, beyond anything the guard requires.
func (m *NetMediator) openDial(ctx context.Context, network, address string) (net.Conn, connDest, error) {
	dest, perr := parseDest(address)
	if perr != nil {
		// Let the dialer report the bad address, as it always has.
		dest = connDest{host: address}
	}
	d := net.Dialer{Timeout: 30 * time.Second}
	if g := m.dialGuard(); g.Strict || len(g.DenyFloor) > 0 {
		d.Control = egresspolicy.ControlHook(func(ap netip.AddrPort) error { return openCheck(g, dest.name, ap) })
	}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		if errors.Is(err, egresspolicy.ErrDialRefused) {
			return nil, dest, &wasmengine.EgressDeniedError{Host: dest.host, Port: dest.port, Reason: reasonBlockedIP}
		}
		return nil, dest, err
	}
	dest.addr = remoteAddr(conn)
	return conn, dest, nil
}

// policyDial decides and dials one guest connection under policy p. An IP
// literal must be allowed by a CIDR; a name must match a rule and is then
// resolved here, on the host, through the shared dial guard (loopback and
// link-local always refused, private ranges only when a CIDR allows them).
// On 443 the guest's TLS SNI must equal the name it dialed, which closes
// TLS-level fronting inside an allowed IP.
func (m *NetMediator) policyDial(ctx context.Context, sandboxID string, p *egresspolicy.Policy, network, address string) (net.Conn, connDest, error) {
	dest, err := parseDest(address)
	if err != nil {
		return nil, dest, err
	}
	allowed, rule := policyMatch(p, dest)
	if !allowed {
		reason := reasonHostNotAllowed
		if dest.name == "" {
			reason = reasonIPNotAllowed
		}
		return nil, dest, &wasmengine.EgressDeniedError{Host: dest.host, Port: dest.port, Reason: reason, Rule: rule}
	}
	m.mu.RLock()
	up := m.upstream
	m.mu.RUnlock()
	var conn net.Conn
	if dest.name != "" && !up.Bypass(dest.name) {
		// An allowed name the operator proxies: tunnel to it by name, so
		// the proxy (not this host's resolver) decides where it lands.
		conn, err = up.DialConnect(ctx, address)
		dest.tunneled = true
	} else {
		d := net.Dialer{Timeout: 30 * time.Second, Control: m.dialGuard().Control(p, dest.name, rule != "")}
		conn, err = d.DialContext(ctx, network, address)
	}
	if err != nil {
		if errors.Is(err, egresspolicy.ErrDialRefused) {
			return nil, dest, &wasmengine.EgressDeniedError{Host: dest.host, Port: dest.port, Reason: reasonBlockedIP}
		}
		return nil, dest, err
	}
	if !dest.tunneled {
		dest.addr = remoteAddr(conn)
	}
	m.recordLearned(sandboxID, p, dest.host, dest.port)
	if dest.port == 443 && dest.name != "" {
		return &sniCheckConn{Conn: conn, host: dest.host, port: dest.port, onDeny: func(sni string) {
			m.observeDenial(sandboxID, network, net.JoinHostPort(sni, "443"), reasonSNIMismatch)
		}}, dest, nil
	}
	return conn, dest, nil
}

// sniCheckConn buffers the guest's first writes until a ClientHello parses,
// then requires its SNI to be the dialed name. Bytes that are not TLS pass
// through: only a TLS hello naming another host is fronting.
type sniCheckConn struct {
	net.Conn
	host string
	port uint16
	// onDeny reports a fronting attempt for audit (H5); nil in tests.
	onDeny func(sni string)

	mu      sync.Mutex
	decided bool
	buf     []byte
}

func (c *sniCheckConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decided {
		return c.Conn.Write(p)
	}
	c.buf = append(c.buf, p...)
	hello, err := egresspolicy.ParseClientHello(c.buf)
	switch {
	case errors.Is(err, egresspolicy.ErrIncomplete) && len(c.buf) < egresspolicy.MaxClientHelloBytes:
		return len(p), nil
	case err == nil && hello.ServerName != "" && !strings.EqualFold(hello.ServerName, c.host):
		_ = c.Conn.Close()
		if c.onDeny != nil {
			c.onDeny(hello.ServerName)
		}
		return 0, &wasmengine.EgressDeniedError{Host: hello.ServerName, Port: c.port, Reason: reasonSNIMismatch}
	}
	c.decided = true
	buf := c.buf
	c.buf = nil
	if _, err := c.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}
