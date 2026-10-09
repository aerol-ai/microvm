package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

type fixedSrc struct {
	src egress.Source
	ok  bool
}

func (f fixedSrc) Source(netip.Addr) (egress.Source, bool)                    { return f.src, f.ok }
func (f fixedSrc) Track(string, string, uint16, net.Conn) *egress.TrackedConn { return nil }
func (f fixedSrc) BinName(string, netip.AddrPort) (string, bool)              { return "", false }

func TestInspectHandlerRefusesBeforeDial(t *testing.T) {
	peer := netip.MustParseAddr("10.1.0.8")
	p := New(fixedSrc{}, func(Decision) {}, Config{})
	h := &inspectHandler{p: p, id: "sb", peer: peer, name: "example.com"}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"

	h.p.src = fixedSrc{}
	h.ServeHTTP(httptest.NewRecorder(), req)

	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "other"}}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "sb"}, Blocked: egress.BlockQuota}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	req.Host = "front.example"
	h.p.src = fixedSrc{ok: true, src: egress.Source{Spec: egress.Spec{ID: "sb"}}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	h.p.src = fixedSrc{ok: true, src: egress.Source{
		Spec: egress.Spec{ID: "sb"}, Policy: pol, Mode: egress.ModeAllowlist,
	}}
	h.name = "other.example"
	h.ServeHTTP(httptest.NewRecorder(), req)
}
