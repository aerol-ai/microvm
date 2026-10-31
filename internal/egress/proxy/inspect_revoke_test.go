package proxy

import (
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// heldTrack holds inspection admission at Track until released: before the
// connection is registered, or (after) registered but not yet marked
// inspected.
type heldTrack struct {
	*egress.Gateway
	after            bool
	entered, release chan struct{}
	once             sync.Once
}

func (s *heldTrack) Track(id, host string, port uint16, c net.Conn) *egress.TrackedConn {
	var tc *egress.TrackedConn
	if s.after {
		tc = s.Gateway.Track(id, host, port, c)
	}
	s.once.Do(func() { close(s.entered) })
	<-s.release
	if !s.after {
		tc = s.Gateway.Track(id, host, port, c)
	}
	return tc
}

// TestInspectAdmissionDoesNotSurviveTheRevokeClear: a key revoke's gateway
// clear drops the inspector, then closes every connection marked inspected
// (eng D21). A connection being admitted across the clear holds the
// inspector it loaded; it must not go on to complete TLS and serve
// requests with the dropped CA, wherever admission stood when the clear
// ran.
func TestInspectAdmissionDoesNotSurviveTheRevokeClear(t *testing.T) {
	for name, after := range map[string]bool{"before Track": false, "between Track and MarkInspected": true} {
		t.Run(name, func(t *testing.T) {
			held := &heldTrack{after: after, entered: make(chan struct{}), release: make(chan struct{})}
			rule := egresspolicy.RuleSpec{Host: "api.example.com", Inspect: true, Paths: []string{"/repos/**"}}
			r := newInspectRigOver(t, Config{}, func(g *egress.Gateway) Sources { held.Gateway = g; return held }, rule)
			spec := allowSpec("api.example.com")
			spec.IP = peer
			spec.Rules = []egresspolicy.RuleSpec{rule}
			if err := r.gw.Update(spec); err != nil {
				t.Fatal(err)
			}
			client := r.client(false)
			defer client.CloseIdleConnections()
			result := make(chan int, 1)
			go func() {
				code, _, _ := do(t, client, http.MethodGet, "https://api.example.com/repos/x", "", "")
				result <- code
			}()
			select {
			case <-held.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("no inspection admission")
			}
			// The gateway's clear (gatewayd clearInspectCA), while admission
			// holds the old inspector.
			r.proxy.SetInspector(nil)
			r.gw.DropSecrets()
			r.gw.CloseInspected()
			close(held.release)
			if code := <-result; code == http.StatusOK {
				t.Fatal("a request admitted across the revoke clear was served")
			}
		})
	}
}
