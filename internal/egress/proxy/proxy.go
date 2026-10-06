// Package proxy is the egress gateway's transparent SNI/Host proxy
// (plans/egress-domain-filtering.md §5.5). nft redirects a gateway-mode
// sandbox's TCP 80/443 here; the proxy decides on the outer SNI (443) or each
// request's Host (80), dials the name itself through the shared dial guard,
// and splices bytes without terminating TLS.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
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
}

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
		// Only 80/443 are redirected; anything else is a misconfiguration.
		_ = c.Close()
	}
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
	return &net.Dialer{Timeout: p.cfg.DialTimeout, Control: p.cfg.Guard.Control(pol, name, nameAllowed)}
}

// splice tracks the downstream conn against the sandbox (a block, detach or
// narrowing closes it) and copies until both sides finish.
func (p *Proxy) splice(c, up net.Conn, br *bufio.Reader, id, host string, port uint16) {
	tc := p.src.Track(id, host, port, c)
	defer tc.Close()
	defer up.Close()
	if err := netsplice.Splice(c, up, br, netsplice.WithIdleTimeout(p.cfg.IdleTimeout)); err != nil && !errors.Is(err, netsplice.ErrIdleTimeout) {
		p.log.Debug("egress proxy: splice", "sandbox_id", id, "error", err)
	}
}
