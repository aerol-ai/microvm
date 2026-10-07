// Package proxy is the egress gateway's transparent SNI/Host proxy
// (plans/egress-domain-filtering.md §5.5). nft redirects a gateway-mode
// sandbox's TCP 80/443 here; the proxy decides on the outer SNI (443) or each
// request's Host (80), dials the name itself through the shared dial guard,
// and splices bytes without terminating TLS.
package proxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/netsplice"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// Defaults (SB_EGRESS_PROXY_MAX_CONNS[_PER_SANDBOX] and timeouts).
const (
	DefaultMaxConns           = 16384
	DefaultMaxConnsPerSandbox = 512
	DefaultIdleTimeout        = 30 * time.Minute
	defaultDialTimeout        = 10 * time.Second
	defaultHelloTimeout       = 5 * time.Second
	// overCapCloseSlots bounds concurrent over-cap alert writes per node, so a
	// flood of over-cap connections can't itself exhaust the gateway (F2).
	overCapCloseSlots = 64
)

// Denial reasons (audit and explainable denials, CEO D4/D10).
const (
	ReasonSNINotAllowed  = "sni_not_allowed"
	ReasonHostNotAllowed = "host_not_allowed"
	ReasonNoSNI          = "no_sni"
	ReasonBlockedIP      = "blocked_ip"
	ReasonBlocked        = "blocked"
	ReasonConnCap        = "conn_cap"
	ReasonUpstreamProxy  = "upstream_proxy_unavailable"
	ReasonUnknownSource  = "unknown_source"
	ReasonDialFailed     = "dial_failed"
	ReasonBadRequest     = "bad_request"
	// ReasonBinaryNotAllowed: a per-binary rule covers the destination and
	// the connection's executable isn't listed (P3-3).
	ReasonBinaryNotAllowed = "binary_not_allowed"
	// ReasonBinaryUnknown: the connection couldn't be traced to an
	// executable, so a per-binary rule can't admit it.
	ReasonBinaryUnknown = "binary_unknown"
	// ReasonRuleDenied: a ruled host's request matched no rule (P3-1).
	ReasonRuleDenied = "rule_denied"
	// ReasonPathNotCanonical: a ruled host's request path could be read two
	// ways (dot segments, encoded slashes), so no rule can vouch for it.
	ReasonPathNotCanonical = "path_not_canonical"
)

// Sources resolves a peer IP to its sandbox and registers live connections
// (*egress.Gateway).
type Sources interface {
	Source(netip.Addr) (egress.Source, bool)
	Track(id, host string, port uint16, conn net.Conn) *egress.TrackedConn
	// BinName names the host a redirected per-binary flow is for (P3-3).
	BinName(id string, dst netip.AddrPort) (string, bool)
}

// Identifier traces a sandbox connection local→remote to its executable
// (P3-3): is(path) reports whether the connection's process is the binary
// at path inside the sandbox, for the paths its rules list. In production
// sandboxd answers it (procid.Client): the gateway can't read the
// sandbox's /proc itself (review finding 16).
type Identifier func(sandboxID string, pid int, local, remote netip.AddrPort, paths []string) (is func(path string) bool, err error)

// Decision is one decided connection or request, for audit and learn mode.
type Decision struct {
	SandboxID string
	Host      string
	Port      uint16
	Allowed   bool
	Reason    string
	Rule      string
	Mode      egress.Mode
}

// Observer receives decisions. It must not block.
type Observer func(Decision)

// Dialer opens the upstream connection. The default dials directly through
// the host resolver; the private-cloud upstream proxy chain (§5.10 PC-4)
// plugs in here.
type Dialer interface {
	DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error)
}

type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	return d.DialContext(ctx, network, address)
}

// Config tunes a Proxy.
type Config struct {
	MaxConns           int
	MaxConnsPerSandbox int
	IdleTimeout        time.Duration
	DialTimeout        time.Duration
	HelloTimeout       time.Duration
	Guard              egresspolicy.DialGuard
	// OriginalDst returns the pre-REDIRECT destination (SO_ORIGINAL_DST).
	OriginalDst func(net.Conn) (netip.AddrPort, error)
	Dialer      Dialer
	Logger      *slog.Logger
	// Upstream chains allowed names through the operator's proxy
	// (§5.10 PC-4); nil dials direct.
	Upstream *egresspolicy.Upstream
	// UpstreamRoots verifies the real host behind an inspected connection;
	// nil is the gateway host's system roots.
	UpstreamRoots *x509.CertPool
	// InspectMaxBody caps an inspected request body (P3-1).
	InspectMaxBody int64
	// Identify traces connections for per-binary rules (P3-3); nil refuses
	// every connection a per-binary rule covers.
	Identify Identifier
}

// Proxy serves redirected connections.
type Proxy struct {
	src     Sources
	observe Observer
	cfg     Config
	limit   *netsplice.Limiter
	overCap chan struct{}
	log     *slog.Logger

	mu      sync.Mutex
	active  int
	closing bool

	inspector atomic.Pointer[inspectorBox]

	// opMu guards cfg.Guard and cfg.Upstream, which an operator-file reload
	// replaces while connections are served (review finding 7).
	opMu sync.RWMutex
}

// SetOperator replaces the dial guard and upstream chain from a reloaded
// operator file; dials after it use the new ones. Connections already open
// are revalidated by the gateway (Gateway.RevalidateConns).
func (p *Proxy) SetOperator(g egresspolicy.DialGuard, up *egresspolicy.Upstream) {
	p.opMu.Lock()
	p.cfg.Guard, p.cfg.Upstream = g, up
	p.opMu.Unlock()
}

func (p *Proxy) guard() egresspolicy.DialGuard {
	p.opMu.RLock()
	defer p.opMu.RUnlock()
	return p.cfg.Guard
}

func (p *Proxy) upstream() *egresspolicy.Upstream {
	p.opMu.RLock()
	defer p.opMu.RUnlock()
	return p.cfg.Upstream
}

// New builds a Proxy.
func New(src Sources, observe Observer, cfg Config) *Proxy {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxConnsPerSandbox <= 0 {
		cfg.MaxConnsPerSandbox = DefaultMaxConnsPerSandbox
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.HelloTimeout <= 0 {
		cfg.HelloTimeout = defaultHelloTimeout
	}
	if cfg.InspectMaxBody <= 0 {
		cfg.InspectMaxBody = DefaultInspectMaxBody
	}
	if cfg.OriginalDst == nil {
		cfg.OriginalDst = OriginalDst
	}
	if cfg.Dialer == nil {
		cfg.Dialer = directDialer{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if observe == nil {
		observe = func(Decision) {}
	}
	perKey, global := cfg.MaxConnsPerSandbox, cfg.MaxConns
	return &Proxy{
		src: src, observe: observe, cfg: cfg, log: cfg.Logger,
		limit:   netsplice.NewLimiter(func() int { return perKey }, func() int { return global }),
		overCap: make(chan struct{}, overCapCloseSlots),
	}
}

// Serve accepts redirected connections until ln closes.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go p.handle(c)
	}
}

// Active returns the number of connections being proxied.
func (p *Proxy) Active() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

func peerAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

func (p *Proxy) handle(c net.Conn) {
	src, ok := p.src.Source(peerAddr(c))
	if !ok {
		p.observe(Decision{Reason: ReasonUnknownSource})
		_ = c.Close()
		return
	}
	id := src.Spec.ID
	dst, err := p.cfg.OriginalDst(c)
	if err != nil {
		p.log.Warn("egress proxy: original destination", "sandbox_id", id, "error", err)
		_ = c.Close()
		return
	}
	if src.Blocked != 0 {
		// Blocked sandboxes are dropped at input by @blocked_src; this is the
		// in-memory belt for races and failed nft writes (S3).
		p.observe(Decision{SandboxID: id, Port: dst.Port(), Reason: ReasonBlocked, Mode: src.Mode})
		if dst.Port() == 443 {
			writeTLSAlert(c)
		}
		_ = c.Close()
		return
	}
	release, ok := p.limit.TryAcquire(id, nil, nil)
	if !ok {
		p.overCapClose(c, src, dst.Port())
		return
	}
	defer release()
	p.mu.Lock()
	p.active++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	switch dst.Port() {
	case 443:
		p.serveTLS(c, src, dst)
	case 80:
		p.serveHTTP(c, src, dst)
	default:
		// Other ports reach the proxy only through bin_learned (P3-3).
		p.serveTraced(c, src, dst)
	}
}

// identify traces c, whose original destination is dst, to its executable.
func (p *Proxy) identify(src egress.Source, rules *egresspolicy.Rules, c net.Conn, dst netip.AddrPort) (func(string) bool, error) {
	if p.cfg.Identify == nil {
		return nil, errors.New("this gateway can't trace connections to executables")
	}
	local, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	return p.cfg.Identify(src.Spec.ID, src.Spec.Pid, netip.AddrPortFrom(local.Addr().Unmap(), local.Port()), dst, rules.Binaries())
}

// admit holds a connection to host:port to per-binary rules (P3-3) and
// returns the rules its requests are then held to. is is traced on first
// need and cached in *is.
func (p *Proxy) admit(src egress.Source, rules *egresspolicy.Rules, c net.Conn, dst netip.AddrPort, host string, port uint16,
	is *func(string) bool) (*egresspolicy.Rules, string, bool) {
	if !rules.NeedsBinary(host, port) {
		return rules, "", true
	}
	if *is == nil {
		fn, err := p.identify(src, rules, c, dst)
		if err != nil {
			p.log.Debug("egress proxy: trace connection", "sandbox_id", src.Spec.ID, "host", host, "error", err)
			return nil, ReasonBinaryUnknown, false
		}
		*is = fn
	}
	admitted, ok := rules.AdmitConn(host, port, *is)
	if !ok {
		return nil, ReasonBinaryNotAllowed, false
	}
	return admitted, "", true
}

// serveTraced decides a flow bin_learned redirected (P3-3): a port other
// than 80/443 to a host a per-binary rule covers. It is a raw TCP splice
// once the executable is admitted; a refusal resets the connection.
func (p *Proxy) serveTraced(c net.Conn, src egress.Source, dst netip.AddrPort) {
	id := src.Spec.ID
	deny := func(reason, host string) {
		p.observe(Decision{SandboxID: id, Host: host, Port: dst.Port(), Reason: reason, Mode: src.Mode})
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // RST: fail fast (CEO D10)
		}
		_ = c.Close()
	}
	name, ok := p.src.BinName(id, dst)
	if !ok {
		deny(ReasonBinaryUnknown, dst.String())
		return
	}
	allowed, rule := src.Policy.MatchHostPort(name, dst.Port())
	if !allowed {
		deny(ReasonHostNotAllowed, name)
		return
	}
	var is func(string) bool
	if _, reason, ok := p.admit(src, src.Rules, c, dst, name, dst.Port(), &is); !ok {
		deny(reason, name)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.DialTimeout)
	up, err := p.cfg.Dialer.DialContext(ctx, p.dialer(src.Policy, name, rule != ""), "tcp", dst.String())
	cancel()
	if err != nil {
		reason := ReasonDialFailed
		if egresspolicyRefused(err) {
			reason = ReasonBlockedIP
		}
		deny(reason, name)
		return
	}
	p.observe(Decision{SandboxID: id, Host: name, Port: dst.Port(), Allowed: true, Rule: rule, Mode: src.Mode})
	p.splice(c, up, nil, id, name, dst.Port())
}

// overCapClose answers an over-cap connection without reading it: the TLS
// alert on 443 (no hello is buffered, F2), 429 on 80.
func (p *Proxy) overCapClose(c net.Conn, src egress.Source, port uint16) {
	p.observe(Decision{SandboxID: src.Spec.ID, Port: port, Reason: ReasonConnCap, Mode: src.Mode})
	select {
	case p.overCap <- struct{}{}:
		defer func() { <-p.overCap }()
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		if port == 443 {
			writeTLSAlert(c)
		} else {
			_, _ = io.WriteString(c, "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\naerolvm egress policy: connection cap reached for this sandbox\n")
		}
	default:
	}
	_ = c.Close()
}

// dialer returns a net.Dialer whose Control applies the dial guard to every
// resolved address, bound to this connection's name and match result.
func (p *Proxy) dialer(pol *egresspolicy.Policy, name string, nameAllowed bool) *net.Dialer {
	return &net.Dialer{Timeout: p.cfg.DialTimeout, Control: p.guard().Control(pol, name, nameAllowed)}
}

// splice tracks the downstream conn against the sandbox (a block, detach or
// narrowing closes it) and copies until both sides finish.
func (p *Proxy) splice(c, up net.Conn, br *bufio.Reader, id, host string, port uint16) {
	tc := p.src.Track(id, host, port, c)
	defer tc.Close()
	defer up.Close()
	if a, ok := up.RemoteAddr().(*net.TCPAddr); ok && p.upstream().Bypass(host) {
		// Dialed directly (not through the operator's proxy): a reloaded
		// guard checks this address.
		if ap := a.AddrPort(); ap.IsValid() {
			tc.SetDst(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
	}
	if err := netsplice.Splice(c, up, br, netsplice.WithIdleTimeout(p.cfg.IdleTimeout)); err != nil && !errors.Is(err, netsplice.ErrIdleTimeout) {
		p.log.Debug("egress proxy: splice", "sandbox_id", id, "error", err)
	}
}
