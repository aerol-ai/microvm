package dnsfilter

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

var loopback = netip.MustParseAddr("127.0.0.1")

type fakeSources struct {
	mu  sync.Mutex
	src map[netip.Addr]egress.Source
}

func (f *fakeSources) Source(ip netip.Addr) (egress.Source, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.src[ip]
	return s, ok
}

type fakeLearner struct {
	mu    sync.Mutex
	added []string
	err   error
	ttls  []time.Duration
}

func (l *fakeLearner) LearnFor(id, _ string, dst netip.Addr, port uint16, ttl time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.added = append(l.added, netip.AddrPortFrom(dst, port).String())
	l.ttls = append(l.ttls, ttl)
	return nil
}

func compile(t *testing.T, allow, deny []string, learn bool) *egresspolicy.Policy {
	t.Helper()
	mode := egresspolicy.ModeEnforce
	if learn {
		mode = egresspolicy.ModeLearn
	}
	p, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: allow, DenyOut: deny, Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// upstream is a fake resolver: A records with TTL 5, plus counters.
type upstream struct {
	mu      sync.Mutex
	queries []string
	addr    string
	fail    bool
}

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		u.mu.Lock()
		u.queries = append(u.queries, r.Question[0].Name)
		fail := u.fail
		u.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		if fail {
			m.Rcode = dns.RcodeServerFailure
		}
		switch r.Question[0].Name {
		case "pypi.org.", "github.com.", "files.pythonhosted.org.":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP("140.82.112.3")})
		case "internal.github.com.":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 7200}, A: net.ParseIP("10.0.0.5")},
				&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 7200}, A: net.ParseIP("127.0.0.1")})
		}
		if o := r.IsEdns0(); o != nil {
			m.SetEdns0(o.UDPSize(), false)
			m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("1.2.3.0").To4()})
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	u.addr = pc.LocalAddr().String()
	return u
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.queries)
}

type harness struct {
	addr, tcpAddr string
	src           *fakeSources
	learner       *fakeLearner
	up            *upstream
	mu            sync.Mutex
	decisions     []Decision
}

func startFilter(t *testing.T, source egress.Source, cfg Config) *harness {
	t.Helper()
	h := &harness{src: &fakeSources{src: map[netip.Addr]egress.Source{loopback: source}}, learner: &fakeLearner{}, up: startUpstream(t)}
	cfg.Upstreams = append([]string{h.up.addr}, cfg.Upstreams...)
	f := New(h.src, h.learner, func(d Decision) {
		h.mu.Lock()
		h.decisions = append(h.decisions, d)
		h.mu.Unlock()
	}, cfg)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	us := &dns.Server{PacketConn: pc, Handler: f}
	go func() { _ = us.ActivateAndServe() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &dns.Server{Listener: ln, Handler: f}
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	h.addr, h.tcpAddr = pc.LocalAddr().String(), ln.Addr().String()
	return h
}

func query(t *testing.T, addr, name string, qtype uint16, tcp bool) *dns.Msg {
	t.Helper()
	c := &dns.Client{Timeout: 2 * time.Second}
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(1232, false)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func ede(m *dns.Msg) *dns.EDNS0_EDE {
	if o := m.IsEdns0(); o != nil {
		for _, opt := range o.Option {
			if e, ok := opt.(*dns.EDNS0_EDE); ok {
				return e
			}
		}
	}
	return nil
}

func allowlist(t *testing.T, allow ...string) egress.Source {
	return egress.Source{Spec: egress.Spec{ID: "sb"}, Policy: compile(t, allow, nil, false), Mode: egress.ModeAllowlist}
}

func TestAllowlistNameDecisions(t *testing.T) {
	h := startFilter(t, allowlist(t, "pypi.org", "*.pythonhosted.org"), Config{})
	for _, tcp := range []bool{false, true} {
		addr := h.addr
		if tcp {
			addr = h.tcpAddr
		}
		resp := query(t, addr, "pypi.org", dns.TypeA, tcp)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("allowed name: %v", resp)
		}
		if o := resp.IsEdns0(); o != nil {
			for _, opt := range o.Option {
				if _, ok := opt.(*dns.EDNS0_SUBNET); ok {
					t.Fatal("ECS must be stripped from answers")
				}
			}
		}
		before := h.up.count()
		resp = query(t, addr, "evil.example", dns.TypeA, tcp)
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("denied name rcode = %d, want NXDOMAIN", resp.Rcode)
		}
		if e := ede(resp); e == nil || e.InfoCode != dns.ExtendedErrorCodeBlocked || e.ExtraText != "aerolvm egress policy: evil.example not allowed" {
			t.Fatalf("EDE = %+v, want 15 Blocked with reason (CEO D4)", e)
		}
		if h.up.count() != before {
			t.Fatal("a denied name reached the upstream")
		}
	}
	if resp := query(t, h.addr, "files.pythonhosted.org", dns.TypeA, false); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("wildcard name: rcode %d", resp.Rcode)
	}
	if resp := query(t, h.addr, "pythonhosted.org", dns.TypeA, false); resp.Rcode != dns.RcodeNameError {
		t.Fatal("wildcard must not cover the apex")
	}
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		resp := query(t, h.addr, "pypi.org", qt, false)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Fatalf("qtype %d: want NODATA, got %v", qt, resp)
		}
	}
	if resp := query(t, h.addr, "pypi.org", dns.TypeANY, false); resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("ANY rcode = %d, want NOTIMP", resp.Rcode)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var denied int
	for _, d := range h.decisions {
		if d.Reason == ReasonNotAllowed && d.Name == "evil.example" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("denials observed = %d, want 2", denied)
	}
}

func TestDenylistAndLearnForwardEverything(t *testing.T) {
	for _, src := range []egress.Source{
		{Spec: egress.Spec{ID: "sb"}, Policy: compile(t, nil, []string{"10.0.0.0/8"}, false), Mode: egress.ModeDenylist},
		{Spec: egress.Spec{ID: "sb", Learn: true}, Policy: compile(t, nil, nil, true), Mode: egress.ModeLearn},
	} {
		h := startFilter(t, src, Config{})
		resp := query(t, h.addr, "anything.example", dns.TypeA, false)
		if resp.Rcode == dns.RcodeNameError && ede(resp) != nil {
			t.Fatalf("mode %s must forward unlisted names", src.Mode)
		}
		if h.up.count() == 0 {
			t.Fatalf("mode %s: nothing reached the upstream", src.Mode)
		}
	}
}

func TestUnknownSourceAndBlocked(t *testing.T) {
	src := allowlist(t, "pypi.org")
	h := startFilter(t, src, Config{})
	h.src.mu.Lock()
	delete(h.src.src, loopback)
	h.src.mu.Unlock()
	if resp := query(t, h.addr, "pypi.org", dns.TypeA, false); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("unknown source rcode = %d, want REFUSED", resp.Rcode)
	}
	src.Blocked = egress.BlockQuota
	h.src.mu.Lock()
	h.src.src[loopback] = src
	h.src.mu.Unlock()
	c := &dns.Client{Timeout: 300 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("pypi.org.", dns.TypeA)
	if _, _, err := c.Exchange(m, h.addr); err == nil {
		t.Fatal("a blocked sandbox must get no answer (silent drop, CEO D10)")
	}
}

func TestRateLimit(t *testing.T) {
	h := startFilter(t, allowlist(t, "pypi.org"), Config{QPS: 1, Burst: 2})
	var refused int
	for i := 0; i < 5; i++ {
		resp := query(t, h.addr, "pypi.org", dns.TypeA, false)
		if resp.Rcode == dns.RcodeRefused {
			refused++
			if e := ede(resp); e == nil || e.InfoCode != dns.ExtendedErrorCodeBlocked {
				t.Fatal("rate-limited answer must carry EDE 15")
			}
		}
	}
	if refused == 0 {
		t.Fatal("QPS cap never refused")
	}
}

// TestLearnedElements covers §5.4: host:port rules open (ip, port) before the
// answer, with a clamped TTL, and never for loopback or private addresses.
func TestLearnedElements(t *testing.T) {
	h := startFilter(t, allowlist(t, "github.com:22", "*.github.com:22", "pypi.org"), Config{})
	if resp := query(t, h.addr, "github.com", dns.TypeA, false); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %d", resp.Rcode)
	}
	h.learner.mu.Lock()
	if len(h.learner.added) != 1 || h.learner.added[0] != "140.82.112.3:22" || h.learner.ttls[0] != minLearnedTTL {
		t.Fatalf("learned = %v ttls %v", h.learner.added, h.learner.ttls)
	}
	h.learner.mu.Unlock()
	if resp := query(t, h.addr, "pypi.org", dns.TypeA, false); resp.Rcode != dns.RcodeSuccess {
		t.Fatal("bare host must still resolve")
	}
	query(t, h.addr, "internal.github.com", dns.TypeA, false)
	h.learner.mu.Lock()
	n := len(h.learner.added)
	h.learner.mu.Unlock()
	if n != 1 {
		t.Fatalf("private/loopback answers must never be learned (C5), got %d elements", n)
	}
	h.learner.mu.Lock()
	h.learner.err = egress.ErrLearnedCap
	h.learner.mu.Unlock()
	resp := query(t, h.addr, "github.com", dns.TypeA, false)
	if resp.Rcode != dns.RcodeRefused || ede(resp) == nil {
		t.Fatalf("learned cap: rcode %d, want REFUSED + EDE (EF-62)", resp.Rcode)
	}
	h.learner.mu.Lock()
	h.learner.err = errors.New("netlink busy")
	h.learner.mu.Unlock()
	if resp := query(t, h.addr, "github.com", dns.TypeA, false); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("learned write failure must fail closed: rcode %d", resp.Rcode)
	}
}

func TestUpstreamFailureAndFallback(t *testing.T) {
	h := startFilter(t, allowlist(t, "pypi.org"), Config{Timeout: 300 * time.Millisecond})
	h.up.mu.Lock()
	h.up.fail = true
	h.up.mu.Unlock()
	if resp := query(t, h.addr, "pypi.org", dns.TypeA, false); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("upstream SERVFAIL passes through, got %d", resp.Rcode)
	}
	bad := startFilter(t, allowlist(t, "pypi.org"), Config{Timeout: 200 * time.Millisecond})
	bad.src.mu.Lock()
	bad.src.mu.Unlock()
	f := New(bad.src, nil, nil, Config{Upstreams: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond})
	if _, err := f.exchange(new(dns.Msg).SetQuestion("pypi.org.", dns.TypeA)); err == nil {
		t.Fatal("unreachable upstream must error")
	}
	if _, err := New(bad.src, nil, nil, Config{}).exchange(new(dns.Msg)); err == nil {
		t.Fatal("no upstreams must error")
	}
}

func TestFormErrAndHelpers(t *testing.T) {
	h := startFilter(t, allowlist(t, "pypi.org"), Config{})
	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = nil
	resp, _, err := c.Exchange(m, h.addr)
	if err == nil && resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("no question rcode %d", resp.Rcode)
	}
	if clampTTL(0) != minLearnedTTL || clampTTL(5*time.Hour) != maxLearnedTTL || clampTTL(time.Minute) != time.Minute {
		t.Fatal("TTL clamp")
	}
	dir := t.TempDir()
	rc := filepath.Join(dir, "resolv.conf")
	_ = os.WriteFile(rc, []byte("nameserver 127.0.0.53\nnameserver 10.0.0.2\n"), 0o600)
	if ups := DefaultUpstreams(rc); len(ups) != 2 || ups[0] != "127.0.0.53:53" {
		t.Fatalf("DefaultUpstreams = %v", ups)
	}
	if DefaultUpstreams(filepath.Join(dir, "missing")) != nil {
		t.Fatal("missing resolv.conf")
	}
	f := New(nil, nil, nil, Config{QPS: 1})
	for i := 0; i < 300; i++ {
		f.allow(string(rune('a' + i%26)))
	}
}

// TestQueriesCounted: every query that reaches the filter counts, refused
// ones included (aerolvm_egress_dns_queries_total, the DNS QPS panel).
func TestQueriesCounted(t *testing.T) {
	f := New(&fakeSources{src: map[netip.Addr]egress.Source{}}, nil, nil, Config{Upstreams: []string{"127.0.0.1:1"}})
	m := new(dns.Msg)
	m.SetQuestion("pypi.org.", dns.TypeA)
	for i := 0; i < 3; i++ {
		f.ServeDNS(&recordWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}}, m)
	}
	if f.Queries() != 3 {
		t.Fatalf("Queries() = %d, want 3", f.Queries())
	}
}

// TestSyntheticAnswersForProxiedNames (§5.10 PC-4, EF-82): an allowed name
// the upstream proxies gets a synthetic A with the short TTL, no resolver
// lookup and no learned element; a no_proxy name is resolved as usual; a
// name that isn't allowed still gets NXDOMAIN.
func TestSyntheticAnswersForProxiedNames(t *testing.T) {
	up, err := egresspolicy.NewUpstream("http://10.1.1.1:3128", "", []string{"mirror.example"}, nil, netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	h := startFilter(t, allowlist(t, "pypi.org", "mirror.example", "git.example:22"), Config{Upstream: up})
	resp := query(t, h.addr, "pypi.org", dns.TypeA, false)
	if len(resp.Answer) != 1 {
		t.Fatalf("answer = %v", resp.Answer)
	}
	a := resp.Answer[0].(*dns.A)
	ip, _ := netip.AddrFromSlice(a.A)
	if !up.IsSynthetic(ip.Unmap()) || a.Hdr.Ttl != 30 {
		t.Fatalf("synthetic answer = %v ttl=%d", ip, a.Hdr.Ttl)
	}
	h.up.mu.Lock()
	asked := len(h.up.queries)
	h.up.mu.Unlock()
	if asked != 0 {
		t.Fatal("a proxied name must not reach the resolver")
	}
	if aaaa := query(t, h.addr, "pypi.org", dns.TypeAAAA, false); len(aaaa.Answer) != 0 || aaaa.Rcode != dns.RcodeSuccess {
		t.Fatal("AAAA stays NODATA")
	}
	query(t, h.addr, "mirror.example", dns.TypeA, false)
	h.up.mu.Lock()
	asked = len(h.up.queries)
	h.up.mu.Unlock()
	if asked != 1 {
		t.Fatalf("a no_proxy name is resolved normally (resolver saw %d)", asked)
	}
	query(t, h.addr, "git.example", dns.TypeA, false)
	h.learner.mu.Lock()
	learned := len(h.learner.added)
	h.learner.mu.Unlock()
	if learned != 0 {
		t.Fatal("a synthetic answer must never become a learned element")
	}
	if nx := query(t, h.addr, "evil.example", dns.TypeA, false); nx.Rcode != dns.RcodeNameError {
		t.Fatal("names that aren't allowed still get NXDOMAIN")
	}
}
