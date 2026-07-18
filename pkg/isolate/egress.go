package isolate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

func (h *Host) clearEgressPolicy(id string) {
	h.mu.Lock()
	delete(h.egressPolicy, id)
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
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header.Del("x-sb-id")
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "https"
	}
	resp, err := http.DefaultTransport.RoundTrip(outReq)
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
