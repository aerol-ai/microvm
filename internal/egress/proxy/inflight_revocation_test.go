package proxy

// Regression tests from the third review of PR #622: each reproduces a
// finding against the reviewed head (7935cfe6) and passes with its fix.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

type pausedDialer struct {
	base            *fakeDialer
	entered, resume chan struct{}
}

func (d *pausedDialer) DialContext(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	c, err := d.base.DialContext(ctx, dialer, network, address)
	if err != nil {
		return nil, err
	}
	close(d.entered)
	select {
	case <-d.resume:
		return c, nil
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	}
}

func TestInFlightTLSDialHonorsRevocation(t *testing.T) {
	for _, hold := range []bool{false, true} {
		t.Run(map[bool]string{false: "narrow-policy", true: "hold"}[hold], func(t *testing.T) {
			r := newRig(t, 443, allowSpec("pypi.org"), Config{DialTimeout: 3 * time.Second})
			r.dialer.resolve["pypi.org"] = "151.101.0.223"
			r.dialer.backend["pypi.org"] = tlsBackend(t)
			d := &pausedDialer{base: r.dialer, entered: make(chan struct{}), resume: make(chan struct{})}
			r.proxy.cfg.Dialer = d
			type result struct {
				body string
				err  error
			}
			done := make(chan result, 1)
			go func() { body, err := tlsGet(r.addr, "pypi.org"); done <- result{body, err} }()
			select {
			case <-d.entered:
			case <-time.After(3 * time.Second):
				close(d.resume)
				t.Fatal("dial not entered")
			}
			var err error
			if hold {
				err = r.gw.SetBlocked("sb", egress.BlockHold, true)
			} else {
				next := allowSpec("github.com")
				next.IP = peer
				err = r.gw.Attach(next)
			}
			close(d.resume)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-done:
				if got.err == nil && strings.Contains(got.body, "secure-ok") {
					t.Fatal("TLS request to revoked host completed after policy/hold change while dial was in flight")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connection failed to settle")
			}
		})
	}
}
