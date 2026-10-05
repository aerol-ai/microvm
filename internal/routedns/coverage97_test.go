package routedns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type coverage97DNSWriter struct {
	msg *dns.Msg
}

func (w *coverage97DNSWriter) LocalAddr() net.Addr       { return nil }
func (w *coverage97DNSWriter) RemoteAddr() net.Addr      { return nil }
func (w *coverage97DNSWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *coverage97DNSWriter) Write([]byte) (int, error) { return 0, nil }
func (w *coverage97DNSWriter) Close() error              { return nil }
func (w *coverage97DNSWriter) TsigStatus() error         { return nil }
func (w *coverage97DNSWriter) TsigTimersOnly(bool)       {}
func (w *coverage97DNSWriter) Hijack()                   {}

func TestCoverage97RejectsMalformedQuestion(t *testing.T) {
	r := newTestResponder()
	w := &coverage97DNSWriter{}
	req := new(dns.Msg)
	req.SetQuestion("sb1.sandbox.test.", dns.TypeA)
	req.Question = nil
	r.ServeDNS(w, req)
	if w.msg == nil || w.msg.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %v", w.msg)
	}
}
