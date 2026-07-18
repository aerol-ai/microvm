package isolate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// EgressPolicy is the per-sandbox outbound policy enforced by the host-side
// egress proxy (plans/isolate-runtime.md §4 Phase 3). Mirrored from the
// driver-level type so pkg/isolate does not import the runtime package.
type EgressPolicy struct {
	BlockAll bool
	Allow    []string
	Deny     []string
}

// SetEgressPolicy registers (or replaces) the outbound policy for a sandbox.
// Called after Load. Unload clears it. Until a policy is set, egress for that
// sandbox id is denied (fail-closed).
func (h *Host) SetEgressPolicy(id string, p EgressPolicy) {
	if id == "" {
		return
	}
	h.mu.Lock()
	if h.egressPolicy == nil {
		h.egressPolicy = make(map[string]EgressPolicy)
	}
	h.egressPolicy[id] = p
	h.mu.Unlock()
}

// startEgressServer is the Phase-3 attributed egress boundary: every outbound
// fetch an isolate makes hits this socket. The controller stamps x-sb-id on
// the request (via a per-sandbox outbound shim isolate), so ownership is known
// at accept/handler time — the same connection-ownership lesson that delayed
// the WASM resident-host flag. Undeclared destinations are refused.
func (h *Host) startEgressServer() error {
	ln, err := net.Listen("unix", h.egressSock)
	if err != nil {
		return fmt.Errorf("isolate: listen egress socket: %w", err)
	}
	h.egressSrv = &http.Server{Handler: http.HandlerFunc(h.serveEgress)}
	go func() { _ = h.egressSrv.Serve(ln) }()
	return nil
}

func (h *Host) serveEgress(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.Header.Get("x-sb-id"))
	if id == "" {
		http.Error(w, "egress denied: missing x-sb-id attribution", http.StatusForbidden)
		return
	}
	h.mu.RLock()
	p, ok := h.egressPolicy[id]
	h.mu.RUnlock()
	if !ok {
		http.Error(w, "egress denied: no policy for sandbox", http.StatusForbidden)
		return
	}
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
		if hname, _, err := net.SplitHostPort(host); err == nil {
			host = hname
		}
	}
	if !egressAllowed(p, host) {
		http.Error(w, "egress denied by sandbox policy", http.StatusForbidden)
		return
	}
	// Defense-in-depth against SSRF: isolate egress runs from the HOST network
	// namespace, so a hostname allowlist alone would still let untrusted tenant
	// JS reach the sandboxd API on loopback and the cloud metadata endpoint
	// (169.254.169.254 → instance IAM credentials). Reject an IP-literal
	// destination in a special-use range up front, and — because a hostname can
	// resolve into those ranges (or be rebound) — the shared egressTransport
	// re-checks the resolved IP at dial time (egressDialControl).
	if ip := net.ParseIP(host); ip != nil && isBlockedEgressIP(ip) {
		http.Error(w, "egress denied: destination is a blocked (loopback/link-local/private) address", http.StatusForbidden)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header.Del("x-sb-id")
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "https"
	}
	resp, err := egressTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "egress proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func egressAllowed(p EgressPolicy, host string) bool {
	if p.BlockAll {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, d := range p.Deny {
		if hostMatches(host, d) {
			return false
		}
	}
	if len(p.Allow) == 0 {
		return true
	}
	for _, a := range p.Allow {
		if hostMatches(host, a) {
			return true
		}
	}
	return false
}

// egressTransport is the shared outbound transport for the egress proxy. Its
// dial Control hook runs AFTER DNS resolution with the concrete IP, so it
// blocks special-use destinations even when reached via a hostname (or a
// rebound one) — the authoritative SSRF guard behind the literal check in
// serveEgress.
var egressTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   egressDialControl,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: time.Second,
}

func egressDialControl(_, address string, _ syscall.RawConn) error {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedEgressIP(ip) {
		return fmt.Errorf("egress denied: destination %s is in a blocked (loopback/link-local/private) range", ip)
	}
	return nil
}

// isBlockedEgressIP reports whether ip is in a range untrusted isolate code
// must never reach through the host proxy: loopback (the sandboxd API), link-
// local (cloud metadata 169.254.169.254 / fe80::/10), private (RFC1918 + ULA),
// unspecified, and multicast.
func isBlockedEgressIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

func hostMatches(host, rule string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule == "" {
		return false
	}
	if strings.Contains(rule, "/") {
		_, n, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && n.Contains(ip)
	}
	if host == rule {
		return true
	}
	if strings.HasPrefix(rule, ".") && strings.HasSuffix(host, rule) {
		return true
	}
	return false
}
