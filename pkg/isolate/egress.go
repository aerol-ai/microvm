package isolate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// EgressObserver is notified when a sandbox is allowed to contact a destination
// through the host egress proxy. Must be non-blocking. Destination is host or
// host:port — never credentials.
type EgressObserver func(sandboxID, network, destination string)

// EgressDenialObserver receives each refused egress request with the
// shared denial reason (plans/egress-domain-filtering.md H5, P1-7), so
// isolate denials land in the same audit log and counters as the gateway's.
// Called synchronously on the request path: it must not block.
type EgressDenialObserver func(sandboxID, destination, reason string)

// Denial reasons, shared with the gateway's vocabulary.
const (
	DenyReasonHostNotAllowed = "host_not_allowed"
	DenyReasonIPNotAllowed   = "ip_not_allowed"
	DenyReasonBlockedIP      = "blocked_ip"
	DenyReasonBadRequest     = "bad_request"
)

// EgressPolicy is the per-sandbox outbound policy enforced by the host-side
// egress proxy (plans/isolate-runtime.md §4 Phase 3). Mirrored from the
// driver-level type so pkg/isolate does not import the runtime package. The
// lists use the shared pkg/egresspolicy grammar and its allow-wins precedence
// (plans/egress-domain-filtering.md D4, D15), the same as every other runtime.
type EgressPolicy struct {
	BlockAll bool
	Allow    []string
	Deny     []string
}

// isolateGuard is isolate's dial posture (D15): isolate egress leaves from
// the host's own network namespace, so it is always strict: no private
// destination, whatever a policy CIDR says. The private-cloud operator file
// (§5.10) adds its deny floor, and its internal zone only with the explicit
// internal_zone.isolate opt-in. nil means the default strict guard.
var isolateGuard atomic.Pointer[egresspolicy.DialGuard]

// SetEgressDialGuard installs the operator's guard for every isolate host in
// this process. Strict is forced on: the operator can widen isolate only
// through ZoneInStrict.
func SetEgressDialGuard(g egresspolicy.DialGuard) {
	g.Strict = true
	isolateGuard.Store(&g)
}

// EgressDialGuard returns the guard isolate egress dials with now.
func EgressDialGuard() egresspolicy.DialGuard { return currentIsolateGuard() }

func currentIsolateGuard() egresspolicy.DialGuard {
	if g := isolateGuard.Load(); g != nil {
		return *g
	}
	return egresspolicy.DialGuard{Strict: true}
}

func compileEgressPolicy(p EgressPolicy) (*egresspolicy.Policy, error) {
	return egresspolicy.Compile(egresspolicy.Spec{AllowOut: p.Allow, DenyOut: p.Deny, BlockAll: p.BlockAll})
}

// SetEgressPolicy registers (or replaces) the outbound policy for a sandbox and
// (re)assigns its egress slot (§4). A non-block-all policy claims a free slot
// and lazily binds that slot's listener; block-all releases any slot so the
// sandbox binds EGRESS_DENY. Until a policy is set — or when the pool is
// exhausted — the sandbox has no slot and its egress is denied (fail-closed).
// Called after Load; Unload clears both policy and slot.
//
// Creates validate the lists first (internal/service), so a policy that does
// not compile here is a stored row from before the shared grammar (for
// example a hostname in Deny, D15). It is enforced as block-all rather than
// guessed at: fail closed, never open.
func (h *Host) SetEgressPolicy(id string, raw EgressPolicy) {
	if id == "" {
		return
	}
	p, err := compileEgressPolicy(raw)
	if err != nil {
		h.logger.Error("isolate: egress policy does not compile; sandbox egress is blocked",
			"group", h.cfg.GroupKey, "sandbox", id, "err", err)
		p = egresspolicy.BlockAllPolicy()
	}
	h.mu.Lock()
	if h.egressPolicy == nil {
		h.egressPolicy = make(map[string]*egresspolicy.Policy)
	}
	h.egressPolicy[id] = p

	if p.BlockAll() {
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
	if err := h.grantJailAccess(sock); err != nil {
		_ = ln.Close()
		return err
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.serveEgressSlot(slot, w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
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
	h.egressDenySrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The socket carries no sandbox identity, so nothing to audit;
			// the body still says why.
			http.Error(w, "aerolvm egress policy: host "+r.Host+" not allowed (network_block_all, or the node's isolate egress pool is exhausted)", http.StatusForbidden)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
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
	if id == "" || !ok || p == nil {
		http.Error(w, "aerolvm egress policy: host "+r.Host+" not allowed (no sandbox owns this egress slot)", http.StatusForbidden)
		return
	}
	h.proxyEgress(w, r, id, p)
}

// proxyEgress enforces p (the shared egresspolicy matcher + SSRF IP-range
// block) and proxies the request. The isolate reaches this only via its own
// slot socket, so p is unambiguously this sandbox's policy. sandboxID
// attributes the destination for audit (E3a); empty id skips observation.
//
// workerd delivers an external egress service the request with the target
// authority in the Host header and only path+query in the URL — and it does NOT
// convey the original scheme (spike-observed: http:// and https:// arrive
// identically with an empty scheme). So we reconstruct the absolute upstream URL
// from the Host header and force https: an isolate cannot make a plaintext
// egress call, which is the safe default for an allowlist proxy and the only
// scheme we can honor unambiguously.
func (h *Host) proxyEgress(w http.ResponseWriter, r *http.Request, sandboxID string, p *egresspolicy.Policy) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, port, ok := splitAuthority(authority)
	if host == "" {
		h.denyEgress(w, sandboxID, authority, DenyReasonBadRequest, "aerolvm egress policy: request has no destination host")
		return
	}
	if !ok {
		h.denyEgress(w, sandboxID, authority, DenyReasonBadRequest, "aerolvm egress policy: "+authority+": invalid destination port")
		return
	}
	// Port semantics are the shared grammar's (plans/egress-domain-filtering.md
	// §5.1): a bare host allows 80/443 and host:port exactly that port, so the
	// match is on the port the proxy will actually dial.
	if allowed, rule := p.MatchHostPort(host, port); !allowed {
		reason := DenyReasonHostNotAllowed
		if _, err := netip.ParseAddr(host); err == nil {
			reason = DenyReasonIPNotAllowed
		}
		h.denyEgress(w, sandboxID, authority, reason, egresspolicy.DenyMessage(authority, rule))
		return
	}
	// Defense-in-depth against SSRF: isolate egress runs from the HOST network
	// namespace, so a hostname allowlist alone would still let untrusted tenant
	// JS reach the sandboxd API on loopback and the cloud metadata endpoint
	// (169.254.169.254 → instance IAM credentials). Reject an IP-literal
	// destination in a special-use range up front, and — because a hostname can
	// resolve into those ranges (or be rebound) — the shared egressTransport
	// re-checks the resolved IP at dial time (guardedDial).
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := currentIsolateGuard().Check(nil, egresspolicy.DialTarget{Addr: netip.AddrPortFrom(ip, port)}); err != nil {
			h.denyEgress(w, sandboxID, authority, DenyReasonBlockedIP, "aerolvm egress policy: host "+authority+" is a blocked address ("+dialReason(err)+")")
			return
		}
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL.Scheme = "https"
	outReq.URL.Host = authority
	outReq.Host = authority
	resp, err := egressTransport.RoundTrip(outReq)
	if err != nil {
		// A hostname that resolved into a blocked range is refused by the
		// dial guard: a policy denial, not a network fault.
		if errors.Is(err, egresspolicy.ErrDialRefused) {
			h.denyEgress(w, sandboxID, authority, DenyReasonBlockedIP, "aerolvm egress policy: host "+authority+" resolves to a blocked address ("+dialReason(err)+")")
			return
		}
		http.Error(w, "egress proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Successful upstream contact — record destination (bytes stay on netstats).
	h.observeEgress(sandboxID, "tcp", authority)
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// denyEgress answers a refused request with a 403 that names the
// destination and why (CEO D4), and reports it for audit (H5).
func (h *Host) denyEgress(w http.ResponseWriter, sandboxID, destination, reason, msg string) {
	h.mu.RLock()
	obs := h.egressDenialObserver
	h.mu.RUnlock()
	if obs != nil && sandboxID != "" {
		obs(sandboxID, destination, reason)
	}
	http.Error(w, msg, http.StatusForbidden)
}

// splitAuthority returns the destination host and the port the proxy will
// dial. The proxy always upgrades to https, so an authority without a port
// is dialed, and policed, as 443. ok is false for a port that is not 1-65535.
func splitAuthority(authority string) (host string, port uint16, ok bool) {
	h, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), 443, true
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return h, 0, false
	}
	return h, uint16(n), true
}

// dialReason names why the guard refused, for the 403 body.
func dialReason(err error) string {
	var de *egresspolicy.DialError
	if errors.As(err, &de) {
		if de.Rule != "" {
			return de.Reason + " " + de.Rule
		}
		return de.Reason
	}
	return "blocked"
}

// guardedDial dials with the isolate guard's Control hook, which runs AFTER
// DNS resolution with the concrete IP: it blocks special-use destinations
// even when reached through a hostname (or a rebound one), the authoritative
// SSRF guard behind the literal check in proxyEgress. The hostname is passed
// along so an operator internal zone (when opted in for isolate) can admit
// names under its suffixes. The hook is policy-independent, which is what
// keeps pooling connections across sandboxes safe.
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	name := ""
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if _, perr := netip.ParseAddr(host); perr != nil {
			name = host
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: currentIsolateGuard().Control(nil, name, false)}
	return d.DialContext(ctx, network, addr)
}

// egressTransport is the shared outbound transport for the egress proxy,
// dialing through guardedDial. Typed as RoundTripper so offline tests can
// swap in a fake without dialing the network.
var egressTransport http.RoundTripper = &http.Transport{
	DialContext:           guardedDial,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: time.Second,
}
