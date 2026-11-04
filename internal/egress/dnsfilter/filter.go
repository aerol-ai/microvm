// Package dnsfilter is the egress gateway's filtering DNS resolver
// (plans/egress-domain-filtering.md §5.4). Every DNS query from a
// gateway-mode sandbox is redirected here, whatever resolver it named. Names
// outside an allowlist-mode sandbox's policy get NXDOMAIN and never reach an
// upstream, which closes DNS as an exfiltration channel.
package dnsfilter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// Defaults (SB_EGRESS_DNS_QPS and the learned-element TTL clamp).
const (
	DefaultQPS        = 50
	minLearnedTTL     = 30 * time.Second
	maxLearnedTTL     = time.Hour
	defaultUpstreamTO = 4 * time.Second
	limiterIdle       = 10 * time.Minute
)

// Denial reasons, shared with audit and the explainable-denial text.
const (
	ReasonNotAllowed  = "dns_not_allowed"
	ReasonRateLimited = "dns_rate_limited"
	ReasonLearnedCap  = "learned_cap"
	ReasonBlocked     = "blocked"
	ReasonUnknownSrc  = "unknown_source"
)

// Sources resolves a query's source IP to its sandbox (*egress.Gateway).
type Sources interface {
	Source(netip.Addr) (egress.Source, bool)
}

// Learner opens (src, ip, port) for a host:port rule (*egress.Gateway). The
// name lets the gateway send a flow a per-binary rule traces to the proxy.
type Learner interface {
	LearnFor(id, name string, dst netip.Addr, port uint16, ttl time.Duration) error
}

// Decision is one decided query, for audit and learn-mode recording.
type Decision struct {
	SandboxID string
	Name      string
	QType     uint16
	Allowed   bool
	Reason    string
	Rule      string
	Mode      egress.Mode
	Answers   []netip.Addr
}

// Observer receives decisions. It must not block.
type Observer func(Decision)

// Config tunes a Filter.
type Config struct {
	// Upstreams are host:port resolvers, tried in order. The default is the
	// host's own resolver (DefaultUpstreams); SB_EGRESS_DNS_UPSTREAMS
	// overrides it for air-gapped or corporate DNS.
	Upstreams []string
	QPS       float64
	Burst     int
	// Guard filters resolved IPs before they become learned elements: the
	// same dial rules the proxy applies (spec review 3 C5).
	Guard   egresspolicy.DialGuard
	Timeout time.Duration
	Logger  *slog.Logger
	// Upstream, when set, answers allowed names it proxies with a synthetic
	// A record instead of asking a resolver that may not know outside names
	// (§5.10 PC-4).
	Upstream *egresspolicy.Upstream
}

// Filter is a dns.Handler.
type Filter struct {
	src     Sources
	learner Learner
	observe Observer
	cfg     Config
	client  *dns.Client
	tcp     *dns.Client
	flight  singleflight.Group
	log     *slog.Logger

	limMu    sync.Mutex
	limiters map[string]*limiterEntry

	queries atomic.Uint64

	// opMu guards cfg.Guard and cfg.Upstream, which an operator-file reload
	// replaces while queries run (review finding 7).
	opMu sync.RWMutex
}

// SetOperator replaces the dial guard and upstream chain from a reloaded
// operator file; queries after it see the new ones.
func (f *Filter) SetOperator(g egresspolicy.DialGuard, up *egresspolicy.Upstream) {
	f.opMu.Lock()
	f.cfg.Guard, f.cfg.Upstream = g, up
	f.opMu.Unlock()
}

func (f *Filter) guard() egresspolicy.DialGuard {
	f.opMu.RLock()
	defer f.opMu.RUnlock()
	return f.cfg.Guard
}

func (f *Filter) upstream() *egresspolicy.Upstream {
	f.opMu.RLock()
	defer f.opMu.RUnlock()
	return f.cfg.Upstream
}

type limiterEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// Queries returns how many queries reached the filter, refused ones included
// (aerolvm_egress_dns_queries_total; rate() of it is the DNS QPS panel).
func (f *Filter) Queries() uint64 { return f.queries.Load() }

// New builds a Filter.
func New(src Sources, learner Learner, observe Observer, cfg Config) *Filter {
	if cfg.QPS <= 0 {
		cfg.QPS = DefaultQPS
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.QPS) * 2
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultUpstreamTO
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if observe == nil {
		observe = func(Decision) {}
	}
	return &Filter{
		src: src, learner: learner, observe: observe, cfg: cfg, log: cfg.Logger,
		client:   &dns.Client{Net: "udp", Timeout: cfg.Timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: cfg.Timeout},
		limiters: map[string]*limiterEntry{},
	}
}

func remoteAddr(w dns.ResponseWriter) netip.Addr {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

// ServeDNS implements dns.Handler.
func (f *Filter) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	f.queries.Add(1)
	src := remoteAddr(w)
	s, ok := f.src.Source(src)
	if !ok {
		f.reply(w, r, failure(r, dns.RcodeRefused, ""))
		return
	}
	id := s.Spec.ID
	if s.Blocked != 0 {
		// Block-all and quota blocks stay silent drops (CEO D10): no answer.
		f.observe(Decision{SandboxID: id, Reason: ReasonBlocked, Mode: s.Mode})
		return
	}
	if !f.allow(id) {
		f.observe(Decision{SandboxID: id, Reason: ReasonRateLimited, Mode: s.Mode})
		f.reply(w, r, withEDE(failure(r, dns.RcodeRefused, ""), "aerolvm egress policy: DNS rate limit"))
		return
	}
	if len(r.Question) != 1 {
		f.reply(w, r, failure(r, dns.RcodeFormatError, ""))
		return
	}
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	if q.Qtype == dns.TypeANY {
		f.reply(w, r, failure(r, dns.RcodeNotImplemented, ""))
		return
	}

	allowed, rule := true, ""
	if s.Mode == egress.ModeAllowlist {
		allowed, rule = s.Policy.MatchHost(name)
	}
	if !allowed {
		f.observe(Decision{SandboxID: id, Name: name, QType: q.Qtype, Reason: ReasonNotAllowed, Mode: s.Mode})
		f.reply(w, r, withEDE(failure(r, dns.RcodeNameError, ""), fmt.Sprintf("aerolvm egress policy: %s not allowed", name)))
		return
	}
	switch q.Qtype {
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		// IPv6 egress isn't filtered (Q4) and HTTPS/SVCB would hand out ECH
		// configs: answer NODATA so clients fall back to A over IPv4.
		f.observe(Decision{SandboxID: id, Name: name, QType: q.Qtype, Allowed: true, Rule: rule, Mode: s.Mode})
		f.reply(w, r, failure(r, dns.RcodeSuccess, ""))
		return
	}

	if up := f.upstream(); up != nil && q.Qtype == dns.TypeA && !up.Bypass(name) {
		// The proxy routes by SNI or Host, so any address in the synthetic
		// range reaches the right place; nothing is learned, since a
		// synthetic IP must never open a forward path.
		ip := up.SyntheticIP(name)
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.RecursionAvailable = true
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(egresspolicy.SyntheticTTL / time.Second)},
			A:   ip.AsSlice(),
		}}
		f.observe(Decision{SandboxID: id, Name: name, QType: q.Qtype, Allowed: true, Rule: rule, Mode: s.Mode})
		f.reply(w, r, resp)
		return
	}
	resp, err := f.forward(r, q)
	if err != nil {
		f.log.Warn("egress dns: upstream failed", "sandbox_id", id, "name", name, "error", err)
		f.reply(w, r, failure(r, dns.RcodeServerFailure, ""))
		return
	}
	answers := aRecords(resp)
	// host:port rules open learned elements BEFORE the answer leaves, or the
	// client's connect races the set update (§5.4).
	if s.Mode != egress.ModeLearn {
		if reason, err := f.learn(s, name, resp, answers); err != nil {
			f.observe(Decision{SandboxID: id, Name: name, QType: q.Qtype, Reason: reason, Rule: rule, Mode: s.Mode})
			if reason == ReasonLearnedCap {
				f.reply(w, r, withEDE(failure(r, dns.RcodeRefused, ""), "aerolvm egress policy: learned cap"))
				return
			}
			if reason == ReasonNotAllowed {
				f.reply(w, r, failure(r, dns.RcodeNameError, ""))
				return
			}
			f.reply(w, r, failure(r, dns.RcodeServerFailure, ""))
			return
		}
	}
	f.observe(Decision{SandboxID: id, Name: name, QType: q.Qtype, Allowed: true, Rule: rule, Mode: s.Mode, Answers: answers})
	f.reply(w, r, resp)
}

// allow applies the per-sandbox token bucket.
func (f *Filter) allow(id string) bool {
	now := time.Now()
	f.limMu.Lock()
	defer f.limMu.Unlock()
	e := f.limiters[id]
	if e == nil {
		// seen is set before the sweep: a zero time looks idle, and the
		// sweep would drop this entry and so reset its bucket next query.
		e = &limiterEntry{lim: rate.NewLimiter(rate.Limit(f.cfg.QPS), f.cfg.Burst), seen: now}
		f.limiters[id] = e
		if len(f.limiters)%256 == 0 {
			f.sweepLimitersLocked(now)
		}
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

func (f *Filter) sweepLimitersLocked(now time.Time) {
	for id, e := range f.limiters {
		if now.Sub(e.seen) > limiterIdle {
			delete(f.limiters, id)
		}
	}
}

// learn adds (src, ip, port) for every host:port rule the name matches.
func (f *Filter) learn(s egress.Source, name string, resp *dns.Msg, answers []netip.Addr) (string, error) {
	if f.learner == nil || len(answers) == 0 {
		return "", nil
	}
	var ports []uint16
	seen := map[uint16]bool{}
	for _, e := range s.Policy.HostPortRules() {
		if seen[e.Port] {
			continue
		}
		if ok, _ := s.Policy.MatchHostPort(name, e.Port); ok {
			seen[e.Port] = true
			ports = append(ports, e.Port)
		}
	}
	if len(ports) == 0 {
		return "", nil
	}
	ttl := clampTTL(minTTL(resp))
	for _, ip := range answers {
		for _, port := range ports {
			if err := f.guard().Check(s.Policy, egresspolicy.DialTarget{Name: name, NameAllowed: true, Addr: netip.AddrPortFrom(ip, port)}); err != nil {
				continue // loopback, link-local, private outside the zone: never learned
			}
			if err := f.learner.LearnFor(s.Spec.ID, name, ip, port, ttl); err != nil {
				if errors.Is(err, egress.ErrLearnedCap) {
					return ReasonLearnedCap, err
				}
				if errors.Is(err, egress.ErrNotPermitted) {
					// The policy changed while the upstream answered.
					return ReasonNotAllowed, err
				}
				return "learned_write_failed", err
			}
		}
	}
	return "", nil
}

func clampTTL(ttl time.Duration) time.Duration {
	if ttl < minLearnedTTL {
		return minLearnedTTL
	}
	if ttl > maxLearnedTTL {
		return maxLearnedTTL
	}
	return ttl
}

func minTTL(m *dns.Msg) time.Duration {
	var min uint32
	first := true
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; first || t < min {
			min, first = t, false
		}
	}
	return time.Duration(min) * time.Second
}

func aRecords(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// forward resolves q upstream, deduplicating identical in-flight lookups. The
// upstream is asked over UDP whatever transport the sandbox used, with a TCP
// retry on truncation, so a TCP-only client never depends on the upstream
// accepting TCP.
func (f *Filter) forward(r *dns.Msg, q dns.Question) (*dns.Msg, error) {
	key := fmt.Sprintf("%s/%d/%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
	v, err, _ := f.flight.Do(key, func() (any, error) {
		up := new(dns.Msg)
		up.SetQuestion(q.Name, q.Qtype)
		up.Question[0].Qclass = q.Qclass
		up.RecursionDesired = r.RecursionDesired
		up.CheckingDisabled = r.CheckingDisabled
		// Re-create EDNS without client options: EDNS Client Subnet is never
		// passed through (§5.4).
		up.SetEdns0(4096, false)
		return f.exchange(up)
	})
	if err != nil {
		return nil, err
	}
	resp := v.(*dns.Msg).Copy()
	resp.Id = r.Id
	stripECS(resp)
	return resp, nil
}

func (f *Filter) exchange(m *dns.Msg) (*dns.Msg, error) {
	ups := f.cfg.Upstreams
	if len(ups) == 0 {
		return nil, errors.New("no DNS upstreams configured")
	}
	var lastErr error
	for _, up := range ups {
		ctx, cancel := context.WithTimeout(context.Background(), f.cfg.Timeout)
		resp, _, err := f.client.ExchangeContext(ctx, m, up)
		cancel()
		if err == nil && resp != nil && resp.Truncated {
			ctx, cancel := context.WithTimeout(context.Background(), f.cfg.Timeout)
			resp, _, err = f.tcp.ExchangeContext(ctx, m, up)
			cancel()
		}
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func stripECS(m *dns.Msg) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, ecs := o.(*dns.EDNS0_SUBNET); !ecs {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
}

// failure builds an answerless response with rcode.
func failure(r *dns.Msg, rcode int, _ string) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	return m
}

// withEDE attaches RFC 8914 Extended DNS Error 15 "Blocked" with the reason,
// so `dig` explains the denial (CEO D4).
func withEDE(m *dns.Msg, text string) *dns.Msg {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(1232, false)
		opt = m.IsEdns0()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: text})
	return m
}

// reply writes m, truncating for UDP to the client's advertised size.
func (f *Filter) reply(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg) {
	if !isTCP(w) {
		size := dns.MinMsgSize
		if o := r.IsEdns0(); o != nil {
			size = int(o.UDPSize())
		}
		m.Truncate(size)
	}
	if err := w.WriteMsg(m); err != nil {
		f.log.Debug("egress dns: write reply", "error", err)
	}
}

// DefaultUpstreams reads nameservers from a resolv.conf (normally the host's
// /etc/resolv.conf, whose 127.0.0.53 stub the gateway itself can reach).
func DefaultUpstreams(path string) []string {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil || len(cfg.Servers) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out
}
