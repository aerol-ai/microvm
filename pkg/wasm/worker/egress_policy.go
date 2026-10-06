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
// no policy the mediator keeps today's behavior: any destination.
func (m *NetMediator) SetPolicy(sandboxID string, p *egresspolicy.Policy) {
	if sandboxID == "" {
		return
	}
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
}

// ApplyCapsPolicy installs the policy carried in caps, when the caps carry
// one. A policy that doesn't compile is enforced as block-all: fail closed.
func (m *NetMediator) ApplyCapsPolicy(sandboxID string, caps wasmengine.Capabilities) {
	if !caps.EgressPolicySet {
		return
	}
	m.SetPolicy(sandboxID, compileLists(caps.EgressAllowOut, caps.EgressDenyOut))
}

// compileLists compiles raw lists; empty lists mean no policy.
func compileLists(allow, deny []string) *egresspolicy.Policy {
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	p, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: allow, DenyOut: deny, MaxHostnames: egresspolicy.MaxUnionHostnames})
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

// SetDialGuard installs the operator dial guard (internal zone, deny floor).
func (m *NetMediator) SetDialGuard(g egresspolicy.DialGuard) {
	m.mu.Lock()
	m.guard = g
	m.mu.Unlock()
}

// installOperatorGuard applies the private-cloud operator file's internal
// zone and deny floor to this worker's dials (plans/egress-domain-
// filtering.md §5.10, runtime coverage: WASM uses the mediator's dial
// control). The worker reads the file once at start; a file it can't load
// leaves it strict (no private destination at all) rather than open.
func installOperatorGuard(m *NetMediator) {
	path := strings.TrimSpace(os.Getenv("SB_EGRESS_OPERATOR_FILE"))
	if path == "" {
		return
	}
	op, err := operator.Load(path)
	if err != nil {
		m.SetDialGuard(egresspolicy.DialGuard{Strict: true})
		return
	}
	m.SetDialGuard(op.Guard())
	if up, err := op.UpstreamDialer(); err == nil {
		m.mu.Lock()
		m.upstream = up
		m.mu.Unlock()
	}
}

func (m *NetMediator) dialGuard() egresspolicy.DialGuard {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.guard
}

// policyDial decides and dials one guest connection under policy p. An IP
// literal must be allowed by a CIDR; a name must match a rule and is then
// resolved here, on the host, through the shared dial guard (loopback and
// link-local always refused, private ranges only when a CIDR allows them).
// On 443 the guest's TLS SNI must equal the name it dialed, which closes
// TLS-level fronting inside an allowed IP.
func (m *NetMediator) policyDial(ctx context.Context, sandboxID string, p *egresspolicy.Policy, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	port := uint16(port64)
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	ip, isIP := netip.ParseAddr(host)
	var allowed bool
	var rule string
	if isIP == nil {
		allowed, rule = p.MatchIP(ip.Unmap(), port)
	} else {
		allowed, rule = p.MatchHostPort(host, port)
	}
	if !allowed {
		reason := reasonHostNotAllowed
		if isIP == nil {
			reason = reasonIPNotAllowed
		}
		return nil, &wasmengine.EgressDeniedError{Host: host, Port: port, Reason: reason, Rule: rule}
	}
	name := host
	if isIP == nil {
		name = ""
	}
	m.mu.RLock()
	up := m.upstream
	m.mu.RUnlock()
	var conn net.Conn
	if name != "" && !up.Bypass(name) {
		// An allowed name the operator proxies: tunnel to it by name, so
		// the proxy (not this host's resolver) decides where it lands.
		conn, err = up.DialConnect(ctx, address)
	} else {
		d := net.Dialer{Timeout: 30 * time.Second, Control: m.dialGuard().Control(p, name, allowed && rule != "")}
		conn, err = d.DialContext(ctx, network, address)
	}
	if err != nil {
		if errors.Is(err, egresspolicy.ErrDialRefused) {
			return nil, &wasmengine.EgressDeniedError{Host: host, Port: port, Reason: reasonBlockedIP}
		}
		return nil, err
	}
	if port == 443 && isIP != nil {
		return &sniCheckConn{Conn: conn, host: host, port: port, onDeny: func(sni string) {
			m.observeDenial(sandboxID, network, net.JoinHostPort(sni, portStr), reasonSNIMismatch)
		}}, nil
	}
	return conn, nil
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
