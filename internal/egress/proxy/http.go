package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// serveHTTP handles a redirected :80 connection. Every request on a
// keep-alive connection is checked on its own Host, so switching Host on the
// second request is caught (§5.5), and against the sandbox's policy as it is
// now, so a live update (§5.8) or a block reaches the next request too.
func (p *Proxy) serveHTTP(c net.Conn, src egress.Source, dst netip.AddrPort) {
	id, pol := src.Spec.ID, src.Policy
	peer := peerAddr(c)
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
	var curAllowed, curProxied bool
	var is func(string) bool // the connection's executable, traced on first need (P3-3)
	up := p.upstream()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if curProxied && addr == up.Addr() {
				// The operator's own proxy: not a sandbox destination, so
				// the sandbox dial guard (which would refuse its private
				// address) does not apply.
				d := net.Dialer{Timeout: p.cfg.DialTimeout}
				uc, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", egresspolicy.ErrUpstreamProxy, err)
				}
				// No sandbox destination to record, but the sandbox is
				// checked again now that the dial is done.
				if err := p.admitDialed(uc, netip.AddrPort{}, tracked, admission{ip: peer, id: id, host: curName, port: 80, pol: pol, nameAllowed: curAllowed}); err != nil {
					return nil, err
				}
				return uc, nil
			}
			uc, dst, err := p.dialGuarded(ctx, pol, curName, curAllowed, network, addr)
			if err != nil {
				return nil, err
			}
			// Recorded on the tracked downstream (so a reloaded guard
			// revokes the exchange), checked against the current guard, and
			// the sandbox checked again.
			if err := p.admitDialed(uc, dst, tracked, admission{ip: peer, id: id, host: curName, port: 80, pol: pol, nameAllowed: curAllowed}); err != nil {
				return nil, err
			}
			return uc, nil
		},
		Proxy: func(*http.Request) (*url.URL, error) {
			if !curProxied {
				return nil, nil
			}
			return &url.URL{Scheme: "http", Host: up.Addr()}, nil
		},
		ProxyConnectHeader:    up.ProxyHeader(),
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
		cur, ok := p.src.Source(peer)
		switch {
		case !ok || cur.Spec.ID != id:
			p.observe(Decision{SandboxID: id, Port: 80, Reason: ReasonUnknownSource, Mode: src.Mode})
			return
		case cur.Blocked != 0:
			p.observe(Decision{SandboxID: id, Port: 80, Reason: ReasonBlocked, Mode: cur.Mode})
			return
		}
		src, pol = cur, cur.Policy
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
			writeHTTPError(c, http.StatusForbidden, egresspolicy.DenyMessage(host, rule))
			return
		}
		rules, reason, ok := p.admit(src, src.Rules, c, dst, host, 80, &is)
		if !ok {
			p.observe(Decision{SandboxID: id, Host: host, Port: 80, Reason: reason, Mode: src.Mode})
			writeHTTPError(c, http.StatusForbidden, fmt.Sprintf("aerolvm egress policy: this program may not reach %s (network_egress_rules binaries)", host))
			return
		}
		if rules.Has(host, 80) {
			r, reason, ok := checkRules(rules, host, 80, req)
			if !ok {
				p.observe(Decision{SandboxID: id, Host: host, Port: 80, Reason: reason, Mode: src.Mode})
				writeHTTPError(c, http.StatusForbidden, ruleDenyMessage(req, host, reason))
				return
			}
			rule = r.Name()
		}
		// Only an explicit allow rule skips the policy at dial time (allow
		// wins, D4); a default-accept verdict leaves deny CIDRs in force.
		curName, curAllowed = host, allowed && rule != ""
		curProxied = up != nil && !up.Bypass(host)
		if tracked == nil {
			tracked = p.src.Track(id, host, 80, c)
		}
		p.observe(Decision{SandboxID: id, Host: host, Port: 80, Allowed: true, Rule: rule, Mode: src.Mode})

		target := net.JoinHostPort(host, "80")
		if isUpgrade(req) {
			// After a validated Upgrade (websocket) the exchange is no longer
			// HTTP request/response: dial once, forward the request, then
			// splice raw bytes both ways.
			p.upgrade(c, br, req, admission{ip: peer, id: id, host: host, port: 80, pol: pol, nameAllowed: curAllowed}, target, curProxied)
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = target
		req.RequestURI = ""
		if curProxied {
			// Absolute form through the upstream carries its credentials
			// per request.
			for k, v := range up.ProxyHeader() {
				req.Header[k] = v
			}
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			reason := ReasonDialFailed
			status := http.StatusBadGateway
			switch {
			case egresspolicyRefused(err):
				reason, status = ReasonBlockedIP, http.StatusForbidden
			case errors.Is(err, egresspolicy.ErrUpstreamProxy):
				reason = ReasonUpstreamProxy
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

// checkRules holds one request to a ruled host's rules (P3-1). It returns
// the allowing rule, or the denial reason.
func checkRules(rs *egresspolicy.Rules, host string, port uint16, req *http.Request) (rule *egresspolicy.Rule, reason string, ok bool) {
	path, ok := egresspolicy.CanonicalRequestPath(req.URL.EscapedPath())
	if !ok {
		return nil, ReasonPathNotCanonical, false
	}
	d := rs.Decide(host, port, req.Method, path)
	if !d.Allowed {
		return nil, ReasonRuleDenied, false
	}
	return d.Rule, "", true
}

// ruleDenyMessage explains a rule denial in the 403 body (CEO D4).
func ruleDenyMessage(req *http.Request, host, reason string) string {
	if reason == ReasonPathNotCanonical {
		return fmt.Sprintf("aerolvm egress policy: %s: path %q has dot segments, empty segments or encoded slashes, which network_egress_rules refuse", host, req.URL.EscapedPath())
	}
	return fmt.Sprintf("aerolvm egress policy: %s %s on %s is not allowed by network_egress_rules", req.Method, req.URL.EscapedPath(), host)
}

func (p *Proxy) upgrade(c net.Conn, br *bufio.Reader, req *http.Request, a admission, target string, proxied bool) {
	host := a.host
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.DialTimeout)
	var up net.Conn
	var upDst netip.AddrPort
	var err error
	// The chain is read once: a reload may have removed it since the request
	// was routed, and then the guarded direct dial applies.
	if chain := p.upstream(); proxied && chain != nil {
		up, err = chain.DialConnect(ctx, target)
	} else {
		up, upDst, err = p.dialGuarded(ctx, a.pol, host, a.nameAllowed, "tcp", target)
	}
	cancel()
	if err != nil {
		writeHTTPError(c, http.StatusBadGateway, fmt.Sprintf("aerolvm egress policy: %s: %s", host, ReasonDialFailed))
		return
	}
	if err := req.Write(up); err != nil {
		_ = up.Close()
		return
	}
	p.splice(c, up, br, a, upDst)
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
