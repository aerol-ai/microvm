package service

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeSelfTestNet answers Setup per bridge: absent bridges report
// ErrBridgeAbsent, everything else gets a no-op probe env.
type fakeSelfTestNet struct {
	mu     sync.Mutex
	absent map[string]bool
	setups int
}

func (f *fakeSelfTestNet) Setup(_ context.Context, b egress.Bridge, _ netip.Addr, _ int) (egress.ProbeEnv, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups++
	if f.absent[b.Name] {
		return nil, egress.ErrBridgeAbsent
	}
	return noopProbeEnv{}, nil
}

type noopProbeEnv struct{}

func (noopProbeEnv) Send(context.Context) error { return nil }
func (noopProbeEnv) Close() error               { return nil }

// TestSelfTestFailureRefusesGatewayMode (T41): a bridge whose redirect is
// broken makes gateway-mode creates 501 and drops readiness for placement;
// a passing re-test restores both. Plain creates are unaffected.
func TestSelfTestFailureRefusesGatewayMode(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	pn := &fakeSelfTestNet{}
	svc.SetEgressSelfTest(pn)
	ctx := context.Background()
	gw.probeRes = egress.ProbeResult{DNSSeen: true} // INPUT DROP: the proxy flow never arrives
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	// The sync only requests the test; until the first round runs, gateway
	// mode is a retryable 503 and readiness is withheld.
	if !svc.egressSelfTestPending() || svc.EgressGatewayReady() {
		t.Fatal("readiness must wait for the first self-test round")
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("create before the first round = %v, want 503", err)
	}
	if pn.setups != 0 {
		t.Fatal("the sync must not probe inline (it can be on a create path)")
	}
	svc.retryEgressSelfTests(ctx, false)
	if !svc.egressSelfTestFailed() || svc.EgressGatewayReady() || expvarFloat(t, "aerolvm_egress_selftest_ok") != 0 {
		t.Fatal("a failed self-test must mark the node unavailable")
	}
	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if !errors.Is(err, ErrEgressSelfTestFailed) || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("gateway-mode create = %v, want 501 self-test failure", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("a CIDR-only create must not need the gateway: %v", err)
	}
	// Retries back off while it keeps failing.
	first := svc.egressSelfTest.backoff
	svc.egressSelfTest.next = time.Now().Add(-time.Second)
	svc.retryEgressSelfTests(ctx, false)
	if svc.egressSelfTest.backoff <= first {
		t.Fatalf("backoff %v did not grow from %v", svc.egressSelfTest.backoff, first)
	}
	// The operator fixes the host firewall; the next retry passes.
	gw.mu.Lock()
	gw.probeRes = egress.ProbeResult{DNSSeen: true, ProxySeen: true}
	gw.mu.Unlock()
	svc.retryEgressSelfTests(ctx, true)
	if svc.egressSelfTestFailed() || !svc.EgressGatewayReady() || expvarFloat(t, "aerolvm_egress_selftest_ok") != 1 {
		t.Fatal("a passing re-test must restore the node")
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	if !svc.egressSelfTest.next.IsZero() {
		t.Fatal("nothing left to retry once every bridge passed")
	}
	before := pn.setups
	svc.retryEgressSelfTests(ctx, true)
	if pn.setups != before {
		t.Fatal("passed bridges are not re-probed between full syncs")
	}
}

// TestSelfTestAbsentBridgeIsPending: containerd's aerolvm0 before the first
// sandbox is not a failure; it is re-tested soon, and a gateway-mode attach
// kicks the re-test so the bridge is checked right after it appears.
func TestSelfTestAbsentBridgeIsPending(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	gw.probeRes = egress.ProbeResult{DNSSeen: true, ProxySeen: true}
	pn := &fakeSelfTestNet{absent: map[string]bool{"docker0": true}}
	svc.SetEgressSelfTest(pn)
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	svc.retryEgressSelfTests(ctx, false)
	if svc.egressSelfTestFailed() || !svc.EgressGatewayReady() {
		t.Fatal("an absent bridge must not mark the node unavailable")
	}
	if svc.egressSelfTest.next.IsZero() {
		t.Fatal("an absent bridge must be re-tested")
	}
	svc.kickEgressSelfTest()
	select {
	case <-svc.egressSelfTestKick():
	default:
		t.Fatal("an attach with an untested bridge must kick the re-test")
	}
	pn.mu.Lock()
	pn.absent = nil
	pn.mu.Unlock()
	svc.retryEgressSelfTests(ctx, true)
	if !svc.egressSelfTest.next.IsZero() || svc.egressSelfTest.status["docker0"] != selfTestPassed {
		t.Fatalf("bridge must pass once present: %+v", svc.egressSelfTest.status)
	}
	svc.kickEgressSelfTest() // nothing pending: no-op
	select {
	case <-svc.egressSelfTestKick():
		t.Fatal("no kick once everything passed")
	default:
	}
}

// TestSelfTestGatewayOutageIsNotAVerdict: when the gateway can't be asked,
// that is an outage, not a failure that would 501 the node: the full
// re-test stays requested for the next tick.
func TestSelfTestGatewayOutageIsNotAVerdict(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	gw.probeErr = egress.ErrUnavailable
	svc.SetEgressSelfTest(&fakeSelfTestNet{})
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	svc.retryEgressSelfTests(ctx, false)
	if svc.egressSelfTestFailed() || !svc.egressSelfTestPending() || !svc.egressSelfTest.retestAll {
		t.Fatal("an outage is not a verdict; the re-test must stay requested")
	}
	gw.mu.Lock()
	gw.probeErr, gw.probeRes = nil, egress.ProbeResult{DNSSeen: true, ProxySeen: true}
	gw.mu.Unlock()
	svc.retryEgressSelfTests(ctx, false)
	if svc.egressSelfTestPending() || !svc.EgressGatewayReady() {
		t.Fatal("the next tick must finish the round")
	}
	svc.SetEgressSelfTest(nil)
	if svc.egressSelfTestKick() != nil || svc.egressSelfTestFailed() {
		t.Fatal("no self-test wired")
	}
	svc.kickEgressSelfTest()
	svc.retryEgressSelfTests(context.Background(), true)
}

// TestSuperviseRunsTheFirstSelfTestRound: in production the supervisor
// bootstraps the gateway and runs the first round in the same tick.
func TestSuperviseRunsTheFirstSelfTestRound(t *testing.T) {
	svc, gw, _ := newEgressHarness(t)
	gw.probeRes = egress.ProbeResult{DNSSeen: true, ProxySeen: true}
	svc.SetEgressSelfTest(&fakeSelfTestNet{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.SuperviseEgressGateway(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !svc.EgressGatewayReady() {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
