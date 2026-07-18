package isolate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

// SetEgressPolicy registers (or replaces) the outbound policy for a sandbox and
// (re)assigns its egress slot (§4). A non-block-all policy claims a free slot
// and lazily binds that slot's listener; block-all releases any slot so the
// sandbox binds EGRESS_DENY. Until a policy is set — or when the pool is
// exhausted — the sandbox has no slot and its egress is denied (fail-closed).
// Called after Load; Unload clears both policy and slot.
func (h *Host) SetEgressPolicy(id string, p EgressPolicy) {
	if id == "" {
		return
	}
	h.mu.Lock()
	if h.egressPolicy == nil {
		h.egressPolicy = make(map[string]EgressPolicy)
	}
	h.egressPolicy[id] = p

	if p.BlockAll {
		// No slot for block-all: it binds EGRESS_DENY. Drop any prior slot.
		if slot, ok := h.slotByID[id]; ok {
			h.freeSlotLocked(id, slot)
		}
		h.mu.Unlock()
		return
	}
	if _, ok := h.slotByID[id]; ok {
		h.mu.Unlock() // already assigned; the policy replacement above suffices
		return
	}
	slot := -1
	for i, occ := range h.idBySlot {
		if occ == "" {
			slot = i
			break
		}
	}
	if slot < 0 {
		h.mu.Unlock()
		// No silent caps: a sandbox beyond the pool falls back to deny-all.
		h.logger.Warn("isolate egress pool exhausted; sandbox falls back to deny-all egress",
			"group", h.cfg.GroupKey, "sandbox", id, "pool_size", h.cfg.EgressPoolSize)
		return
	}
	if err := h.startSlotServerLocked(slot); err != nil {
		h.mu.Unlock()
		h.logger.Error("isolate: failed to bind egress slot listener; sandbox falls back to deny-all",
			"group", h.cfg.GroupKey, "sandbox", id, "slot", slot, "err", err)
		return
	}
	h.slotByID[id] = slot
	h.idBySlot[slot] = id
	h.mu.Unlock()
}

// startSlotServerLocked binds the per-slot egress listener. Caller holds h.mu;
// net.Listen on a local UDS is fast enough to hold the lock across.
func (h *Host) startSlotServerLocked(slot int) error {
	sock := h.egressSocks[slot]
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("isolate: listen egress slot %d socket: %w", slot, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serveEgressSlot(slot, w, r)
	})}
	h.slotSrv[slot] = srv
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// freeSlotLocked releases a sandbox's slot and tears its listener down; a
// subsequent outbound on that (now unbound) socket is refused at connect until
// the slot is reassigned. Caller holds h.mu.
func (h *Host) freeSlotLocked(id string, slot int) {
	delete(h.slotByID, id)
	if slot >= 0 && slot < len(h.idBySlot) && h.idBySlot[slot] == id {
		h.idBySlot[slot] = ""
	}
	if slot >= 0 && slot < len(h.slotSrv) && h.slotSrv[slot] != nil {
		_ = h.slotSrv[slot].Close()
		h.slotSrv[slot] = nil
		_ = os.Remove(h.egressSocks[slot])
	}
}

// startEgressDenyServer starts the always-on EGRESS_DENY service. Block-all and
// pool-exhausted sandboxes bind it; it fail-closed 403s every request.
func (h *Host) startEgressDenyServer() error {
	ln, err := net.Listen("unix", h.egressDenySock)
	if err != nil {
		return fmt.Errorf("isolate: listen egress-deny socket: %w", err)
	}
	h.egressDenySrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "egress denied: sandbox has no egress slot (block-all or pool exhausted)", http.StatusForbidden)
	})}
	go func() { _ = h.egressDenySrv.Serve(ln) }()
	return nil
}

// serveEgressSlot is the per-slot egress handler: the SOCKET identifies the
// sandbox (idBySlot[slot]), so no header trust is involved — a forged header on
// the outbound request is irrelevant. It applies that sandbox's policy + SSRF
// guard, then proxies. A slot with no current owner (a teardown race) fails
// closed.
func (h *Host) serveEgressSlot(slot int, w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	var id string
	if slot >= 0 && slot < len(h.idBySlot) {
		id = h.idBySlot[slot]
	}
	p, ok := h.egressPolicy[id]
	h.mu.RUnlock()
	if id == "" || !ok {
		http.Error(w, "egress denied: slot has no attributed sandbox", http.StatusForbidden)
		return
	}
	h.proxyEgress(w, r, p)
}

// proxyEgress enforces p (allowlist/denylist + SSRF IP-range block) and proxies
// the request. The isolate reaches this only via its own slot socket, so p is
// unambiguously this sandbox's policy.
//
// workerd delivers an external egress service the request with the target
// authority in the Host header and only path+query in the URL — and it does NOT
// convey the original scheme (spike-observed: http:// and https:// arrive
// identically with an empty scheme). So we reconstruct the absolute upstream URL
// from the Host header and force https: an isolate cannot make a plaintext
// egress call, which is the safe default for an allowlist proxy and the only
// scheme we can honor unambiguously.
func (h *Host) proxyEgress(w http.ResponseWriter, r *http.Request, p EgressPolicy) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host := authority
	if hname, _, err := net.SplitHostPort(authority); err == nil {
		host = hname
	}
	if host == "" {
		http.Error(w, "egress denied: no destination host", http.StatusForbidden)
		return
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
	outReq.URL.Scheme = "https"
	outReq.URL.Host = authority
	outReq.Host = authority
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
