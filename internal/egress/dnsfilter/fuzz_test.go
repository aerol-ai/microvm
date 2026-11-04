package dnsfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// recordWriter is a dns.ResponseWriter that keeps the last reply.
type recordWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *recordWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53054}
}
func (w *recordWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *recordWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *recordWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordWriter) Close() error                { return nil }
func (w *recordWriter) TsigStatus() error           { return nil }
func (w *recordWriter) TsigTimersOnly(bool)         {}
func (w *recordWriter) Hijack()                     {}

// FuzzServeDNS feeds arbitrary wire messages from a sandbox (EF-71): the
// filter must never panic or hang, and a name outside the allowlist must
// never be forwarded.
func FuzzServeDNS(f *testing.F) {
	for _, name := range []string{"pypi.org.", "evil.example.", "x.", "."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.SetEdns0(1232, false)
		if b, err := m.Pack(); err == nil {
			f.Add(b)
		}
	}
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: []string{"pypi.org"}})
	if err != nil {
		f.Fatal(err)
	}
	src := &fakeSources{src: map[netip.Addr]egress.Source{loopback: {Spec: egress.Spec{ID: "sb"}, Policy: pol, Mode: egress.ModeAllowlist}}}
	filter := New(src, nil, nil, Config{Upstreams: []string{"127.0.0.1:1"}, Timeout: 1, QPS: 1e9, Burst: 1 << 30})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := new(dns.Msg)
		if err := r.Unpack(data); err != nil {
			return
		}
		w := &recordWriter{remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}}
		filter.ServeDNS(w, r)
	})
}
