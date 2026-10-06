package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// serveHTTP handles a redirected :80 connection. Every request on a
// keep-alive connection is checked on its own Host, so switching Host on the
// second request is caught (§5.5).
func (p *Proxy) serveHTTP(c net.Conn, src egress.Source, dst netip.AddrPort) {
	id, pol := src.Spec.ID, src.Policy
	br := bufio.NewReader(c)
	var tracked *egress.TrackedConn
	defer func() {
		if tracked != nil {
			_ = tracked.Close()
		} else {
			_ = c.Close()
		}
	}()

	// Requests on one connection are sequential, so the transport's dial
	// hook reads the current request's name and match result.
	var curName string
	var curAllowed bool
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.cfg.Dialer.DialContext(ctx, p.dialer(pol, curName, curAllowed), network, addr)
		},
		MaxIdleConnsPerHost:   1,
		ResponseHeaderTimeout: 5 * time.Minute,
		DisableCompression:    true,
	}
	defer tr.CloseIdleConnections()

	for {
		_ = c.SetReadDeadline(time.Now().Add(p.cfg.IdleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if req.Method == http.MethodConnect {
			p.observe(Decision{SandboxID: id, Port: 80, Reason: ReasonBadRequest, Mode: src.Mode})
			writeHTTPError(c, http.StatusBadRequest, "aerolvm egress policy: CONNECT is not supported on port 80")
			return
		}
		host, ok := requestHost(req, dst)
		if !ok {
			p.observe(Decision{SandboxID: id, Port: 80, Reason: ReasonBadRequest, Mode: src.Mode})
			writeHTTPError(c, http.StatusBadRequest, "aerolvm egress policy: request has no usable Host")
			return
		}
		allowed, rule := true, ""
		if ip, err := netip.ParseAddr(host); err == nil {
			allowed, rule = pol.MatchIP(ip, 80)
		} else {
			allowed, rule = pol.MatchHostPort(host, 80)
		}
		if !allowed && src.Mode == egress.ModeAllowlist {
			p.observe(Decision{SandboxID: id, Host: host, Port: 80, Reason: ReasonHostNotAllowed, Mode: src.Mode})
			writeHTTPError(c, http.StatusForbidden, fmt.Sprintf("aerolvm egress policy: host %s not allowed (no rule matches)", host))
			return
		}
		// Only an explicit allow rule skips the policy at dial time (allow
		// wins, D4); a default-accept verdict leaves deny CIDRs in force.
		curName, curAllowed = host, allowed && rule != ""
		if tracked == nil {
			tracked = p.src.Track(id, host, c)
		}
		p.observe(Decision{SandboxID: id, Host: host, Port: 80, Allowed: true, Rule: rule, Mode: src.Mode})

		target := net.JoinHostPort(host, "80")
		if isUpgrade(req) {
			// After a validated Upgrade (websocket) the exchange is no longer
			// HTTP request/response: dial once, forward the request, then
			// splice raw bytes both ways.
			p.upgrade(c, br, req, id, host, target, pol, curAllowed)
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = target
		req.RequestURI = ""
		resp, err := tr.RoundTrip(req)
		if err != nil {
			reason := ReasonDialFailed
			status := http.StatusBadGateway
			if egresspolicyRefused(err) {
				reason, status = ReasonBlockedIP, http.StatusForbidden
			}
			p.observe(Decision{SandboxID: id, Host: host, Port: 80, Reason: reason, Mode: src.Mode})
			writeHTTPError(c, status, fmt.Sprintf("aerolvm egress policy: %s: %s", host, reason))
			return
		}
		werr := resp.Write(c)
		_ = resp.Body.Close()
		if werr != nil || req.Close || resp.Close {
			return
		}
	}
}

func (p *Proxy) upgrade(c net.Conn, br *bufio.Reader, req *http.Request, id, host, target string, pol *egresspolicy.Policy, allowed bool) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.DialTimeout)
	up, err := p.cfg.Dialer.DialContext(ctx, p.dialer(pol, host, allowed), "tcp", target)
	cancel()
	if err != nil {
		writeHTTPError(c, http.StatusBadGateway, fmt.Sprintf("aerolvm egress policy: %s: %s", host, ReasonDialFailed))
		return
	}
	if err := req.Write(up); err != nil {
		_ = up.Close()
		return
	}
	p.splice(c, up, br, id, host)
}

// requestHost returns the request's host without port. The port, if any,
// must be 80: a redirected :80 connection can't legitimately name another.
func requestHost(req *http.Request, dst netip.AddrPort) (string, bool) {
	h := req.Host
	if h == "" {
		h = req.URL.Host
	}
	if h == "" {
		return dst.Addr().String(), dst.IsValid()
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		if port != "80" {
			return "", false
		}
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	h = strings.Trim(h, "[]")
	return h, h != ""
}

func isUpgrade(req *http.Request) bool {
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return req.Header.Get("Upgrade") != ""
			}
		}
	}
	return false
}

func writeHTTPError(c net.Conn, status int, body string) {
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Connection": {"close"}},
		Body:          io.NopCloser(strings.NewReader(body + "\n")),
		ContentLength: int64(len(body) + 1),
		Close:         true,
	}
	_ = resp.Write(c)
}
