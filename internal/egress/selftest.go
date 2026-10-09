package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrSelfTest marks a failed per-bridge self-test (plans/egress-domain-
// filtering.md §5.3 step 4, T41): redirected traffic from that bridge does
// not reach the gateway (a host INPUT policy of DROP, bridge netfilter off,
// IPv6 on the bridge). The node then refuses gateway-mode creates with 501.
var ErrSelfTest = errors.New("egress: gateway self-test failed")

// ErrBridgeAbsent means the bridge has no link yet, like containerd's
// aerolvm0 before the first CNI ADD. Not a failure: nothing can run there
// yet, and the test runs once it appears.
var ErrBridgeAbsent = errors.New("egress: bridge not present yet")

// ProbeSource is the reserved link-local /32 the self-test uses on the
// bridge at index i. IPAM never hands out 169.254.250.0/24.
func ProbeSource(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{169, 254, 250, byte(i + 1)})
}

// ProbeNet builds the probe's network: a test netns joined to the bridge by
// a veth, with src as its only address and a host route back. It needs
// root, which is why it is sandboxd's job and not the gateway's (S5).
type ProbeNet interface {
	Setup(ctx context.Context, b Bridge, src netip.Addr, index int) (ProbeEnv, error)
}

// ProbeEnv is one live probe network.
type ProbeEnv interface {
	// Send emits one DNS query and opens one TCP connection to port 443,
	// both toward a TEST-NET address from inside the netns, so both can
	// only arrive through the redirect.
	Send(ctx context.Context) error
	Close() error
}

// Prober is the gateway side: it treats the probe source as a gateway-mode
// sandbox for the window and reports what reached its listeners.
type Prober interface {
	Probe(ctx context.Context, p ProbeRequest) (ProbeResult, error)
}

// SelfTestWait bounds how long the gateway watches for the probe flow.
const SelfTestWait = 3 * time.Second

// SelfTest probes one bridge. It returns nil on success, ErrBridgeAbsent
// when the bridge doesn't exist yet, an ErrSelfTest when the redirect path
// is broken, and any other error when the gateway itself couldn't be asked
// (that is a gateway outage, not a verdict on the bridge).
func SelfTest(ctx context.Context, gw Prober, pn ProbeNet, b Bridge, index int) error {
	src := ProbeSource(index)
	env, err := pn.Setup(ctx, b, src, index)
	if err != nil {
		if errors.Is(err, ErrBridgeAbsent) || errors.Is(err, ErrSelfTest) {
			return err
		}
		return fmt.Errorf("%w: bridge %s: probe network: %v", ErrSelfTest, b.Name, err)
	}
	defer func() { _ = env.Close() }()
	if _, err := gw.Probe(ctx, ProbeRequest{Bridge: b.Name, Source: src, Begin: true}); err != nil {
		return err
	}
	sendErr := env.Send(ctx)
	res, err := gw.Probe(ctx, ProbeRequest{Bridge: b.Name, Source: src, Wait: SelfTestWait})
	if err != nil {
		return err
	}
	if !res.DNSSeen || !res.ProxySeen {
		return fmt.Errorf("%w: bridge %s: redirected traffic did not reach the gateway (dns=%v proxy=%v, send: %v); check the host INPUT policy for the gateway ports",
			ErrSelfTest, b.Name, res.DNSSeen, res.ProxySeen, sendErr)
	}
	return nil
}
