package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TLS inspection (plans/egress-domain-filtering.md §5.9, P3-1): for a host
// with an inspect rule the proxy terminates the sandbox's TLS with a leaf
// from the node's CA, which only sandboxes created with inspect rules trust,
// checks each request, and re-originates TLS to the real host, verified
// against the gateway host's roots. ALPN is offered as h2 and http/1.1, and
// net/http serves whichever the client picks.

// DefaultInspectMaxBody caps an inspected request body
// (SB_EGRESS_INSPECT_MAX_BODY_BYTES).
const DefaultInspectMaxBody = 256 << 20

// Inspection denial reasons.
const (
	// ReasonInspectUnavailable: the gateway has no CA yet (sandboxd sends it
	// after every gateway start), so the connection is refused, never
	// passed through unchecked.
	ReasonInspectUnavailable = "inspect_unavailable"
	// ReasonHostMismatch: an inspected request's Host is not the TLS server
	// name, the domain-fronting shape (EF-53).
	ReasonHostMismatch = "host_mismatch"
	// ReasonBodyTooLarge: an inspected request body is over the cap.
	ReasonBodyTooLarge = "body_too_large"
)

// Inspector issues the certificate the proxy presents for an inspected
// name (*inspect.Authority).
type Inspector interface {
	Leaf(host string) (*tls.Certificate, error)
}

type inspectorBox struct{ Inspector }

// SetInspector installs the node CA's issuer; nil removes it.
func (p *Proxy) SetInspector(i Inspector) {
	if i == nil {
		p.inspector.Store(nil)
		return
	}
	p.inspector.Store(&inspectorBox{i})
}

func (p *Proxy) currentInspector() Inspector {
	if b := p.inspector.Load(); b != nil {
		return b.Inspector
	}
	return nil
}

// replayConn hands the buffered ClientHello to the TLS server before the
// rest of the connection.
type replayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// oneConnListener serves a single, already-accepted connection to an
// http.Server, then reports closed once the server is done with it.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// serveInspect terminates TLS for an inspected name and serves its requests
// until the client leaves, the connection idles out, or a policy change
// closes it.
func (p *Proxy) serveInspect(c net.Conn, br *bufio.Reader, src egress.Source, name string, nameAllowed bool) {
	id := src.Spec.ID
	ins := p.currentInspector()
	if ins == nil {
		p.observe(Decision{SandboxID: id, Host: name, Port: 443, Reason: ReasonInspectUnavailable, Mode: src.Mode})
		writeTLSAlert(c)
		_ = c.Close()
		return
	}
	peer := peerAddr(c)
	tc := p.src.Track(id, name, 443, c)
	defer tc.Close()
	tlsConn := tls.Server(&replayConn{Conn: c, r: br}, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return ins.Leaf(name) },
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	})
	_ = c.SetDeadline(time.Now().Add(p.cfg.HelloTimeout))
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		p.log.Debug("egress proxy: inspect handshake", "sandbox_id", id, "host", name, "error", err)
		return
	}
	_ = c.SetDeadline(time.Time{})

	pol := src.Policy
	up := p.cfg.Upstream
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if up != nil && !up.Bypass(name) {
				return up.DialConnect(ctx, net.JoinHostPort(name, "443"))
			}
			return p.cfg.Dialer.DialContext(ctx, p.dialer(pol, name, nameAllowed), network, net.JoinHostPort(name, "443"))
		},
		TLSClientConfig:       &tls.Config{ServerName: name, RootCAs: p.cfg.UpstreamRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		DisableCompression:    true,
	}
	defer tr.CloseIdleConnections()

	h := &inspectHandler{p: p, id: id, peer: peer, name: name, rp: &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = name
			pr.Out.Host = pr.In.Host
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
	}}
	h.rp.ErrorHandler = h.upstreamError

	ln := &oneConnListener{conn: tlsConn, done: make(chan struct{})}
	var closeOnce sync.Once
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       p.cfg.IdleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				closeOnce.Do(func() { close(ln.done) })
			}
		},
	}
	_ = srv.Serve(ln)
}

// inspectHandler checks and forwards one inspected request.
type inspectHandler struct {
	p    *Proxy
	id   string
	peer netip.Addr
	name string
	rp   *httputil.ReverseProxy
}

func (h *inspectHandler) deny(w http.ResponseWriter, mode egress.Mode, status int, reason, msg string) {
	h.p.observe(Decision{SandboxID: h.id, Host: h.name, Port: 443, Reason: reason, Mode: mode})
	http.Error(w, msg, status)
}

func (h *inspectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The sandbox's policy as it is now: a live update or a block reaches
	// the next request on a long-lived connection.
	cur, ok := h.p.src.Source(h.peer)
	switch {
	case !ok || cur.Spec.ID != h.id:
		h.deny(w, cur.Mode, http.StatusForbidden, ReasonUnknownSource, "aerolvm egress policy: sandbox not attached")
		return
	case cur.Blocked != 0:
		h.deny(w, cur.Mode, http.StatusForbidden, ReasonBlocked, "aerolvm egress policy: egress is blocked for this sandbox")
		return
	}
	// One TLS session reaches one name: a Host other than the server name
	// is domain fronting (EF-53).
	if host, ok := inspectedHost(r.Host); !ok || !strings.EqualFold(host, h.name) {
		h.deny(w, cur.Mode, http.StatusMisdirectedRequest, ReasonHostMismatch,
			fmt.Sprintf("aerolvm egress policy: Host %q does not match the TLS server name %s", r.Host, h.name))
		return
	}
	allowed, rule := cur.Policy.MatchHostPort(h.name, 443)
	if !allowed && cur.Mode == egress.ModeAllowlist {
		h.deny(w, cur.Mode, http.StatusForbidden, ReasonHostNotAllowed, egresspolicy.DenyMessage(h.name, rule))
		return
	}
	if cur.Rules.Has(h.name, 443) {
		name, reason, ok := checkRules(cur.Rules, h.name, 443, r)
		if !ok {
			h.deny(w, cur.Mode, http.StatusForbidden, reason, ruleDenyMessage(r, h.name, reason))
			return
		}
		rule = name
	}
	max := h.p.cfg.InspectMaxBody
	if r.ContentLength > max {
		h.deny(w, cur.Mode, http.StatusRequestEntityTooLarge, ReasonBodyTooLarge,
			fmt.Sprintf("aerolvm egress policy: request body over %d bytes", max))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	h.p.observe(Decision{SandboxID: h.id, Host: h.name, Port: 443, Allowed: true, Rule: rule, Mode: cur.Mode})
	h.rp.ServeHTTP(w, r)
}

func (h *inspectHandler) upstreamError(w http.ResponseWriter, _ *http.Request, err error) {
	reason, status := ReasonDialFailed, http.StatusBadGateway
	var mbe *http.MaxBytesError
	switch {
	case egresspolicyRefused(err):
		reason, status = ReasonBlockedIP, http.StatusForbidden
	case errors.Is(err, egresspolicy.ErrUpstreamProxy):
		reason = ReasonUpstreamProxy
	case errors.As(err, &mbe):
		reason, status = ReasonBodyTooLarge, http.StatusRequestEntityTooLarge
	}
	h.p.observe(Decision{SandboxID: h.id, Host: h.name, Port: 443, Reason: reason})
	h.p.log.Debug("egress proxy: inspected upstream", "sandbox_id", h.id, "host", h.name, "error", err)
	http.Error(w, fmt.Sprintf("aerolvm egress policy: %s: %s", h.name, reason), status)
}

// inspectedHost returns a request's host without its port; a port other
// than 443 can't be this session's.
func inspectedHost(hostport string) (string, bool) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.TrimSuffix(hostport, "."), hostport != ""
	}
	return strings.TrimSuffix(host, "."), port == "443"
}
