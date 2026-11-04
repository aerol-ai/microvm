package egresspolicy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrUpstreamProxy means the operator's upstream proxy could not be reached
// or refused the tunnel (reason upstream_proxy_unavailable).
var ErrUpstreamProxy = errors.New("egress: upstream proxy unavailable")

// SyntheticTTL is the TTL of a synthetic DNS answer (§5.10 PC-4).
const SyntheticTTL = 30 * time.Second

// Upstream chains egress through the operator's HTTP proxy
// (plans/egress-domain-filtering.md §5.10 PC-4) for networks that only
// reach outside hosts through one. An allowed name that is not internal-zone
// and not no_proxy goes through it: CONNECT for TLS and raw sockets, the
// absolute form for plain HTTP. The gateway, the WASM mediator and the
// isolate proxy all use this one implementation.
type Upstream struct {
	proxy     *url.URL // no userinfo
	auth      string   // "Basic ..." or ""; never logged
	noNames   []Entry
	zone      *InternalZone
	synthetic netip.Prefix
	timeout   time.Duration
}

// NewUpstream validates the chain. auth is "user:password" from the
// operator's auth_file ("" for none). noProxy holds names (a name and its
// subdomains; "*." for subdomains only) and CIDRs; the internal zone is
// always no-proxy.
func NewUpstream(rawURL, auth string, noProxy []string, zone *InternalZone, synthetic netip.Prefix) (*Upstream, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Port() == "" {
		return nil, fmt.Errorf("upstream proxy %q: want http://host:port", rawURL)
	}
	if !synthetic.IsValid() || !synthetic.Addr().Is4() || synthetic.Bits() > 30 {
		return nil, fmt.Errorf("upstream proxy: synthetic DNS range %q: want an IPv4 prefix", synthetic)
	}
	up := &Upstream{proxy: &url.URL{Scheme: "http", Host: u.Host}, zone: zone, synthetic: synthetic.Masked(), timeout: 10 * time.Second}
	if a := strings.TrimSpace(auth); a != "" {
		if !strings.Contains(a, ":") {
			return nil, errors.New("upstream proxy auth: want user:password")
		}
		up.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(a))
	}
	for _, raw := range noProxy {
		raw = strings.TrimSpace(raw)
		// IP literals always go direct, so a CIDR entry needs no matching;
		// it is accepted because operators list their ranges there.
		if _, err := netip.ParsePrefix(raw); err == nil {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(raw, "*."), ".")
		c := canonicalName(name)
		if c == "" {
			return nil, fmt.Errorf("upstream proxy no_proxy entry %q: want a hostname, *.name or a CIDR", raw)
		}
		kind := KindHost
		if strings.HasPrefix(raw, "*.") {
			kind = KindWildcard
		}
		up.noNames = append(up.noNames, Entry{Kind: kind, Host: c})
	}
	return up, nil
}

// Bypass reports whether host goes direct: an IP literal, an internal-zone
// name, or a no_proxy match. Only names are proxied.
func (u *Upstream) Bypass(host string) bool {
	if u == nil {
		return true
	}
	host = strings.Trim(host, "[]")
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if u.zone.CoversName(host) {
		return true
	}
	c := canonicalName(host)
	if c == "" {
		return true
	}
	for _, e := range u.noNames {
		if (e.Kind == KindHost && c == e.Host) || (Entry{Kind: KindWildcard, Host: e.Host}).coversName(c) {
			return true
		}
	}
	return false
}

// Addr is the proxy's host:port: dials to it are the operator's own and
// skip the sandbox dial guard (it usually sits in private space).
func (u *Upstream) Addr() string { return u.proxy.Host }

// ProxyFunc is an http.Transport.Proxy: the upstream for names that don't
// bypass it, nil (direct) otherwise.
func (u *Upstream) ProxyFunc(req *http.Request) (*url.URL, error) {
	if u == nil || u.Bypass(req.URL.Hostname()) {
		return nil, nil
	}
	return u.proxy, nil
}

// ProxyHeader is the Proxy-Authorization header for absolute-form requests,
// or nil without credentials.
func (u *Upstream) ProxyHeader() http.Header {
	if u == nil || u.auth == "" {
		return nil
	}
	return http.Header{"Proxy-Authorization": {u.auth}}
}

// DialConnect opens a tunnel to addr (name:port) through the upstream.
func (u *Upstream) DialConnect(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: u.timeout}
	c, err := d.DialContext(ctx, "tcp", u.proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamProxy, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(u.timeout))
	}
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u.auth != "" {
		req += "Proxy-Authorization: " + u.auth + "\r\n"
	}
	if _, err := c.Write([]byte(req + "\r\n")); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: %v", ErrUpstreamProxy, err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: %v", ErrUpstreamProxy, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, fmt.Errorf("%w: CONNECT %s answered %s", ErrUpstreamProxy, addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// SyntheticIP is the stable synthetic A answer for a proxied name. Any IP in
// the range works, since the proxy routes by SNI or Host and never by IP; a
// hash keeps answers stable across queries and gateway restarts. The first
// and last address of the range are never handed out.
func (u *Upstream) SyntheticIP(name string) netip.Addr {
	h := fnv.New32a()
	_, _ = h.Write([]byte(canonicalName(name)))
	size := uint32(1) << (32 - u.synthetic.Bits())
	off := h.Sum32()%(size-2) + 1
	base := u.synthetic.Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	n += off
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// IsSynthetic reports whether ip is in the synthetic range.
func (u *Upstream) IsSynthetic(ip netip.Addr) bool {
	return u != nil && u.synthetic.Contains(ip.Unmap())
}

// bufferedConn returns bytes the CONNECT reader already buffered first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
