package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// tlsAccessDenied is a fatal TLS alert record (level 2, description 49
// access_denied), written by hand: the proxy never runs a TLS server, so a
// denied client sees "access denied" instead of a reset (CEO D4/D10).
var tlsAccessDenied = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31}

func writeTLSAlert(c net.Conn) { _, _ = c.Write(tlsAccessDenied) }

// serveTLS handles a redirected :443 connection.
func (p *Proxy) serveTLS(c net.Conn, src egress.Source, dst netip.AddrPort) {
	id, pol := src.Spec.ID, src.Policy
	hello, br, err := egresspolicy.PeekClientHelloConn(c, p.cfg.HelloTimeout)
	if err != nil {
		hello = &egresspolicy.ClientHello{}
	}
	deny := func(reason, host string) {
		p.observe(Decision{SandboxID: id, Host: host, Port: 443, Reason: reason, Mode: src.Mode})
		writeTLSAlert(c)
		_ = c.Close()
	}

	name := hello.ServerName
	ip, isIP := hello.ServerIP()
	var target string
	var nameAllowed bool
	var rule string
	switch {
	case src.Mode == egress.ModeLearn:
		// Learn mode allows everything and records it (CEO X1).
		if name == "" || isIP {
			target = dst.String()
		} else {
			target = net.JoinHostPort(name, "443")
		}
	case name == "" || isIP:
		// No usable SNI. Allowlist mode refuses unless a CIDR allows the
		// address; deny-list mode dials the original destination (A8).
		addr := dst.Addr()
		if isIP {
			addr = ip
		}
		allowed, r := pol.MatchIP(addr, 443)
		if src.Mode == egress.ModeAllowlist && !allowed {
			reason := ReasonNoSNI
			if isIP {
				reason = ReasonSNINotAllowed
			}
			deny(reason, addr.String())
			return
		}
		// Only an explicit allow rule skips the policy at dial time (allow
		// wins, D4); a default-accept verdict leaves deny CIDRs in force.
		nameAllowed, rule = allowed && r != "", r
		target = net.JoinHostPort(addr.String(), "443")
	default:
		allowed, r := pol.MatchHostPort(name, 443)
		if !allowed && src.Mode == egress.ModeAllowlist {
			deny(ReasonSNINotAllowed, name)
			return
		}
		nameAllowed, rule = allowed && r != "", r
		// Per-binary rules (P3-3) admit the connection's executable first;
		// the rules that admitted it decide inspection.
		var is func(string) bool
		rules, reason, ok := p.admit(src, src.Rules, c, dst, name, 443, &is)
		if !ok {
			deny(reason, name)
			return
		}
		if rules.Inspected(name) {
			// An inspect rule: terminate TLS and check each request (P3-1).
			p.serveInspect(c, br, src, dst, name, nameAllowed, is)
			return
		}
		target = net.JoinHostPort(name, "443")
	}

	host := name
	if host == "" {
		host = dst.Addr().String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.DialTimeout)
	var up net.Conn
	var upDst netip.AddrPort
	if chain := p.upstream(); name != "" && !isIP && !chain.Bypass(name) {
		// The SNI decided; the operator's proxy tunnels to that name.
		up, err = chain.DialConnect(ctx, target)
	} else {
		up, upDst, err = p.dialGuarded(ctx, pol, name, nameAllowed, "tcp", target)
	}
	cancel()
	if err != nil {
		reason := ReasonDialFailed
		switch {
		case egresspolicyRefused(err):
			reason = ReasonBlockedIP
		case errors.Is(err, egresspolicy.ErrUpstreamProxy):
			reason = ReasonUpstreamProxy
		}
		p.log.Debug("egress proxy: dial", "sandbox_id", id, "target", target, "error", err)
		deny(reason, host)
		return
	}
	p.observe(Decision{SandboxID: id, Host: host, Port: 443, Allowed: true, Rule: rule, Mode: src.Mode})
	p.splice(c, up, br, admission{ip: src.Spec.IP, id: id, host: host, port: 443, pol: pol, nameAllowed: nameAllowed}, upDst)
}

// egresspolicyRefused reports a dial the shared guard refused (loopback,
// link-local, private outside the zone, a deny CIDR).
func egresspolicyRefused(err error) bool { return errors.Is(err, egresspolicy.ErrDialRefused) }
