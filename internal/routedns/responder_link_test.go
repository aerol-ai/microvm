package routedns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Regression for the cluster-bank-flagship UC-171 drops (2026-11-01): with
// ingress proxy routing on, systemd-resolved sends *.rt.internal to this
// responder, and a reply without OPT to its EDNS0 probe makes it walk down
// its feature levels. An EDNS0 query gets OPT back; a plain one does not.
func TestResponderEchoesEDNS0(t *testing.T) {
	r := newTestResponder()
	r.Owner.Set("sb1.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 2280})
	addr, _ := startResponder(t, r)

	for _, tc := range []struct {
		name     string
		edns     bool
		wantOPT  bool
		wantSize uint16
	}{
		{"EDNS0 query", true, true, ednsUDPSize},
		{"plain query", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion("sb1.sandbox.test.", dns.TypeA)
			if tc.edns {
				m.SetEdns0(4096, false)
			}
			in, _, err := new(dns.Client).Exchange(m, addr)
			if err != nil {
				t.Fatal(err)
			}
			opt := in.IsEdns0()
			if (opt != nil) != tc.wantOPT {
				t.Fatalf("OPT in reply = %v, want %v", opt != nil, tc.wantOPT)
			}
			if opt != nil && (opt.UDPSize() != tc.wantSize || opt.Do()) {
				t.Fatalf("OPT udp size %d do=%v, want %d and no DO", opt.UDPSize(), opt.Do(), tc.wantSize)
			}
			if in.Rcode != dns.RcodeSuccess || aOf(in) != "10.0.0.5" {
				t.Fatalf("rcode=%s answer=%q, want NOERROR 10.0.0.5", dns.RcodeToString[in.Rcode], aOf(in))
			}
		})
	}
}

type addrDNSWriter struct {
	local, remote net.Addr
	msg           *dns.Msg
}

func (w *addrDNSWriter) LocalAddr() net.Addr       { return w.local }
func (w *addrDNSWriter) RemoteAddr() net.Addr      { return w.remote }
func (w *addrDNSWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *addrDNSWriter) Write([]byte) (int, error) { return 0, nil }
func (w *addrDNSWriter) Close() error              { return nil }
func (w *addrDNSWriter) TsigStatus() error         { return nil }
func (w *addrDNSWriter) TsigTimersOnly(bool)       {}
func (w *addrDNSWriter) Hijack()                   {}

// The link listener sits on 169.254.53.53, which a sandbox routed through
// this host could address. Only this node gets answers: loopback, or a
// query from the listener's own address (how systemd-resolved's link-pinned
// socket arrives). Anything else is REFUSED with no record in it.
func TestResponderAnswersOnlyThisNode(t *testing.T) {
	r := newTestResponder()
	r.Owner.Set("sb1.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 2280})
	link := net.ParseIP("169.254.53.53")
	udp := func(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 53053} }
	tcp := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 53053} }
	for _, tc := range []struct {
		name          string
		local, remote net.Addr
		wantRcode     int
	}{
		{"loopback listener, loopback client", udp("127.0.0.1"), udp("127.0.0.1"), dns.RcodeSuccess},
		{"link listener, systemd-resolved from the link address", udp(link.String()), udp(link.String()), dns.RcodeSuccess},
		{"link listener over TCP from the link address", tcp(link.String()), tcp(link.String()), dns.RcodeSuccess},
		{"link listener, a sandbox's address", udp(link.String()), udp("10.88.9.79"), dns.RcodeRefused},
		{"link listener, another node", tcp(link.String()), tcp("10.42.1.73"), dns.RcodeRefused},
		{"wildcard listener never matches a remote", udp("0.0.0.0"), udp("10.88.9.79"), dns.RcodeRefused},
		{"no remote address", udp(link.String()), nil, dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &addrDNSWriter{local: tc.local, remote: tc.remote}
			req := new(dns.Msg)
			req.SetQuestion("sb1.sandbox.test.", dns.TypeA)
			r.ServeDNS(w, req)
			if w.msg == nil || w.msg.Rcode != tc.wantRcode {
				t.Fatalf("reply = %v, want rcode %s", w.msg, dns.RcodeToString[tc.wantRcode])
			}
			if tc.wantRcode == dns.RcodeRefused && (len(w.msg.Answer) != 0 || len(w.msg.Ns) != 0) {
				t.Fatalf("a refused reply carries records: %v", w.msg)
			}
			if tc.wantRcode == dns.RcodeSuccess && aOf(w.msg) != "10.0.0.5" {
				t.Fatalf("answer = %q, want 10.0.0.5", aOf(w.msg))
			}
		})
	}
}
