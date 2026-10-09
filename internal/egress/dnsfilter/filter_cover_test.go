package dnsfilter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	"github.com/aerol-ai/microvm/internal/egress"
)

var sandboxUDP = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

// failingWriter drops every reply with an error, as a client that went away.
type failingWriter struct{ recordWriter }

func (w *failingWriter) WriteMsg(*dns.Msg) error { return errors.New("client gone") }

// TestServeDNSDirectEdges covers what a dns.Server never hands the handler
// (its accept func answers a multi-question query itself) and transports
// other than UDP and TCP.
func TestServeDNSDirectEdges(t *testing.T) {
	src := &fakeSources{src: map[netip.Addr]egress.Source{loopback: allowlist(t, "pypi.org")}}
	f := New(src, nil, nil, Config{Upstreams: []string{"127.0.0.1:1"}})
	two := new(dns.Msg)
	two.SetQuestion("pypi.org.", dns.TypeA)
	two.Question = append(two.Question, two.Question[0])
	one := new(dns.Msg).SetQuestion("pypi.org.", dns.TypeA)
	for _, tc := range []struct {
		name   string
		remote net.Addr
		q      *dns.Msg
		rcode  int
	}{
		{"two questions", sandboxUDP, two, dns.RcodeFormatError},
		{"unix transport has no source", &net.UnixAddr{Name: "/run/dns.sock", Net: "unix"}, one, dns.RcodeRefused},
	} {
		w := &recordWriter{remote: tc.remote}
		f.ServeDNS(w, tc.q)
		if w.msg == nil || w.msg.Rcode != tc.rcode {
			t.Fatalf("%s: reply = %v, want rcode %d", tc.name, w.msg, tc.rcode)
		}
	}
	// A reply the client can't take is logged, not retried.
	f.ServeDNS(&failingWriter{recordWriter{remote: &net.UnixAddr{Name: "/run/dns.sock", Net: "unix"}}}, one)
}

// TestLearnRaceWithPolicyChange: the policy narrowed while the upstream
// answered, so the learned write is refused and the name gets NXDOMAIN, not
// SERVFAIL.
func TestLearnRaceWithPolicyChange(t *testing.T) {
	h := startFilter(t, allowlist(t, "github.com:22"), Config{})
	h.learner.mu.Lock()
	h.learner.err = fmt.Errorf("%w: github.com:22", egress.ErrNotPermitted)
	h.learner.mu.Unlock()
	if resp := query(t, h.addr, "github.com", dns.TypeA, false); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if d := h.decisions[len(h.decisions)-1]; d.Reason != ReasonNotAllowed || d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
}

// TestLimiterSweepRunsEvery256Sandboxes: the 256th distinct sandbox sweeps
// limiters idle past limiterIdle.
func TestLimiterSweepRunsEvery256Sandboxes(t *testing.T) {
	f := New(&fakeSources{}, nil, nil, Config{})
	f.limiters["idle"] = &limiterEntry{lim: rate.NewLimiter(1, 1), seen: time.Now().Add(-limiterIdle - time.Minute)}
	for i := 1; i < 256; i++ {
		f.allow(fmt.Sprintf("sb-%d", i))
	}
	if _, ok := f.limiters["idle"]; ok {
		t.Fatal("the idle limiter survived the sweep")
	}
	if _, ok := f.limiters["sb-1"]; !ok {
		t.Fatal("a live limiter was swept")
	}
}

// startTruncatingUpstream answers UDP with TC set and no records, and TCP in
// full, on one port.
func startTruncatingUpstream(t *testing.T) string {
	t.Helper()
	var ln net.Listener
	var pc net.PacketConn
	for i := 0; i < 10 && pc == nil; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if p, err := net.ListenPacket("udp", l.Addr().String()); err == nil {
			ln, pc = l, p
		} else {
			_ = l.Close()
		}
	}
	if pc == nil {
		t.Fatal("no port free on both TCP and UDP")
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Truncated = true
		} else {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("140.82.112.3")})
		}
		_ = w.WriteMsg(m)
	})
	us := &dns.Server{PacketConn: pc, Handler: h}
	ts := &dns.Server{Listener: ln, Handler: h}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	return ln.Addr().String()
}

func TestTruncatedUpstreamRetriesOverTCP(t *testing.T) {
	f := New(&fakeSources{}, nil, nil, Config{Upstreams: []string{startTruncatingUpstream(t)}, Timeout: 2 * time.Second})
	resp, err := f.exchange(new(dns.Msg).SetQuestion("github.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("answer = %v, want the full TCP answer", resp)
	}
}

func TestStripECSKeepsOtherOptions(t *testing.T) {
	stripECS(new(dns.Msg)) // no OPT record: nothing to strip
	m := new(dns.Msg)
	m.SetEdns0(1232, false)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("1.2.3.0").To4()},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	stripECS(m)
	if len(opt.Option) != 1 {
		t.Fatalf("options = %v, want only the cookie", opt.Option)
	}
	if _, ok := opt.Option[0].(*dns.EDNS0_COOKIE); !ok {
		t.Fatalf("kept %T, want the cookie", opt.Option[0])
	}
}
