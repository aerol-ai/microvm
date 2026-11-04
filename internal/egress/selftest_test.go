package egress

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeProbeNet struct {
	setupErr error
	sendErr  error
	closed   bool
	sent     bool
}

func (f *fakeProbeNet) Setup(context.Context, Bridge, netip.Addr, int) (ProbeEnv, error) {
	if f.setupErr != nil {
		return nil, f.setupErr
	}
	return f, nil
}
func (f *fakeProbeNet) Send(context.Context) error { f.sent = true; return f.sendErr }
func (f *fakeProbeNet) Close() error               { f.closed = true; return nil }

type fakeProber struct {
	res      ProbeResult
	beginErr error
	endErr   error
	reqs     []ProbeRequest
}

func (f *fakeProber) Probe(_ context.Context, p ProbeRequest) (ProbeResult, error) {
	f.reqs = append(f.reqs, p)
	if p.Begin {
		return ProbeResult{}, f.beginErr
	}
	return f.res, f.endErr
}

// TestSelfTestVerdicts (T41): pass when both flows arrive; ErrBridgeAbsent
// for a bridge that isn't there yet; ErrSelfTest for a broken redirect or a
// probe network that can't be built; a gateway that can't be asked is not a
// verdict on the bridge.
func TestSelfTestVerdicts(t *testing.T) {
	ctx := context.Background()
	b := Bridge{Name: "docker0", GatewayIP: netip.MustParseAddr("172.17.0.1")}

	pn, gw := &fakeProbeNet{}, &fakeProber{res: ProbeResult{DNSSeen: true, ProxySeen: true}}
	if err := SelfTest(ctx, gw, pn, b, 1); err != nil {
		t.Fatal(err)
	}
	if !pn.sent || !pn.closed || len(gw.reqs) != 2 || gw.reqs[0].Source != ProbeSource(1) || !gw.reqs[0].Begin || gw.reqs[1].Wait != SelfTestWait {
		t.Fatalf("probe flow: %+v sent=%v closed=%v", gw.reqs, pn.sent, pn.closed)
	}

	if err := SelfTest(ctx, gw, &fakeProbeNet{setupErr: ErrBridgeAbsent}, b, 0); !errors.Is(err, ErrBridgeAbsent) {
		t.Fatalf("absent: %v", err)
	}
	if err := SelfTest(ctx, gw, &fakeProbeNet{setupErr: errors.New("EPERM")}, b, 0); !errors.Is(err, ErrSelfTest) {
		t.Fatalf("setup failure must be a self-test failure: %v", err)
	}
	ipv6 := &fakeProbeNet{setupErr: errors.Join(ErrSelfTest, errors.New("bridge carries IPv6"))}
	if err := SelfTest(ctx, gw, ipv6, b, 0); !errors.Is(err, ErrSelfTest) {
		t.Fatalf("precondition failure: %v", err)
	}
	pn = &fakeProbeNet{sendErr: errors.New("i/o timeout")}
	if err := SelfTest(ctx, &fakeProber{res: ProbeResult{DNSSeen: true}}, pn, b, 0); !errors.Is(err, ErrSelfTest) || !pn.closed {
		t.Fatalf("dropped proxy flow (INPUT DROP host): %v", err)
	}
	for _, g := range []*fakeProber{{beginErr: ErrUnavailable}, {endErr: ErrUnavailable}} {
		if err := SelfTest(ctx, g, &fakeProbeNet{}, b, 0); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSelfTest) {
			t.Fatalf("gateway outage must pass through, not fail the bridge: %v", err)
		}
	}
	if ProbeSource(0) != netip.MustParseAddr("169.254.250.1") {
		t.Fatal("probe source range")
	}
}
