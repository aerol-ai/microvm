package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/ipv6fence"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// memGuestFirewall is the helper's guest firewall calls in memory (M1 PR
// 14): it records each.
type memGuestFirewall struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (m *memGuestFirewall) record(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf(format, args...))
}

func (m *memGuestFirewall) recorded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

func (m *memGuestFirewall) EnsureGuestFirewall(context.Context) error {
	m.record("ensure")
	return m.err
}

func (m *memGuestFirewall) SetGuestNodeGuard(_ context.Context, allow []*rootdpb.NodePort) (bool, error) {
	var s []string
	for _, p := range allow {
		s = append(s, fmt.Sprintf("%s/%d@%s", p.GetProto(), p.GetPort(), p.GetDst()))
	}
	m.record("guard %v", s)
	return true, m.err
}

func (m *memGuestFirewall) SetGuestEgressFloor(_ context.Context, cidrs []string) (bool, error) {
	m.record("floor %v", cidrs)
	return true, m.err
}

func (m *memGuestFirewall) GuestRules(_ context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	m.record("%s %s %v %v", strings.TrimPrefix(op.String(), "SANDBOX_RULES_OP_"), ip, allow, deny)
	return op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, m.err
}

// TestHelperGuestRules: the Firecracker driver's NetRules in split mode,
// each method one call to the helper's guest firewall, in single mode's
// order; the floor and the guard keep their last lists for a re-assert.
func TestHelperGuestRules(t *testing.T) {
	m := &memGuestFirewall{}
	tap := netip.MustParsePrefix("172.16.0.0/20")
	r := newHelperGuestRules(m, tap)
	ip := "172.16.0.14"
	if rep, err := r.ReassertFloor(); rep || err != nil {
		t.Fatalf("a re-assert before any floor = %v, %v", rep, err)
	}
	if rep, err := r.ReassertNodeGuard(); rep || err != nil {
		t.Fatalf("a re-assert before any guard = %v, %v", rep, err)
	}
	for _, step := range []func() error{
		func() error { return r.BlockAllEgress(ip) },
		func() error { return r.ApplyEgressPolicy(ip, []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}) },
		func() error { return r.HoldEgress(ip) },
		func() error { return r.BlockAllIngress(ip) },
		func() error { return r.LiftBlockAllEgress(ip) },
		func() error { return r.ClearHoldEgress(ip) },
		func() error { return r.ClearBlockAllIngress(ip) },
		func() error { return r.ClearEgressPolicy(ip, []string{"1.2.3.4/32"}, nil) },
		func() error { return r.ClearBlockAllEgress(ip) },
		func() error { return r.BlockAllEgress("") }, // no address, no rule: nothing is sent
		func() error {
			return r.SetNodeGuard(tap, []netrules.NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: netip.MustParseAddr("10.0.1.5")}})
		},
		func() error { return r.SetFloor(tap, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if rep, err := r.ReassertFloor(); !rep || err != nil {
		t.Fatalf("ReassertFloor = %v, %v", rep, err)
	}
	if rep, err := r.ReassertNodeGuard(); !rep || err != nil {
		t.Fatalf("ReassertNodeGuard = %v, %v", rep, err)
	}
	want := []string{
		"BLOCK_EGRESS 172.16.0.14 [] []",
		"APPLY_EGRESS_POLICY 172.16.0.14 [1.2.3.4/32] [10.0.0.0/8]",
		"HOLD_EGRESS 172.16.0.14 [] []",
		"BLOCK_INGRESS 172.16.0.14 [] []",
		"LIFT_BLOCK_EGRESS 172.16.0.14 [] []",
		"CLEAR_HOLD_EGRESS 172.16.0.14 [] []",
		"CLEAR_BLOCK_INGRESS 172.16.0.14 [] []",
		"CLEAR_EGRESS_POLICY 172.16.0.14 [1.2.3.4/32] []",
		"CLEAR_BLOCK_EGRESS 172.16.0.14 [] []",
		"guard [tcp/15080@ udp/53@10.0.1.5]",
		"floor [10.20.0.0/16]",
		"floor [10.20.0.0/16]",
		"guard [tcp/15080@ udp/53@10.0.1.5]",
	}
	if got := m.recorded(); !slices.Equal(got, want) {
		t.Fatalf("calls\n got %q\nwant %q", got, want)
	}
	if r.BridgeSubnet() != tap || !r.Enabled() {
		t.Fatalf("subnet %s", r.BridgeSubnet())
	}
	m.err = errors.New("helper away")
	if err := r.SetFloor(tap, nil); err == nil {
		t.Fatal("a floor the helper did not set")
	}
	if err := r.SetNodeGuard(tap, nil); err == nil {
		t.Fatal("a guard the helper did not set")
	}
}

// TestBootSplitGuestFirewall: the guests' firewall is set up at boot, and a
// helper that cannot, or is too old to, stops the start.
func TestBootSplitGuestFirewall(t *testing.T) {
	cfg := config.Config{FirecrackerTapBaseCIDR: "172.16.0.0/20"}
	m := &memGuestFirewall{}
	rules, subnet, err := bootSplitGuestFirewall(context.Background(), cfg, m)
	if err != nil || rules == nil || subnet != netip.MustParsePrefix("172.16.0.0/20") || !slices.Equal(m.recorded(), []string{"ensure"}) {
		t.Fatalf("boot = %v %s %v (calls %q)", rules, subnet, err, m.recorded())
	}
	m.err = &rootclient.UnsupportedError{Feature: rootdpb.FeatureEnsureGuestFirewall}
	if _, _, err := bootSplitGuestFirewall(context.Background(), cfg, m); err == nil || !strings.Contains(err.Error(), "newer helper") {
		t.Fatalf("too old: %v", err)
	}
	m.err = rootclient.ErrUnavailable
	if _, _, err := bootSplitGuestFirewall(context.Background(), cfg, m); !errors.Is(err, rootclient.ErrUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
	m.err = nil
	if _, _, err := bootSplitGuestFirewall(context.Background(), config.Config{FirecrackerTapBaseCIDR: "x"}, m); err == nil {
		t.Fatal("a bad TAP base passed")
	}
}

// TestHelperFenceGuests: with Firecracker on, the create gate holds
// Firecracker creates until the helper's fence covers the TAPs, and keeps
// that apart from the bridge's state; an older helper, whose fence leaves
// the TAPs out, holds them for good.
func TestHelperFenceGuests(t *testing.T) {
	m := newMemFirewall()
	f := newHelperFence(m, testLogger(), true)
	for _, rt := range []string{models.ContainerEngineContainerd, models.RuntimeFirecracker} {
		if err := f.Ready(rt); !errors.Is(err, ipv6fence.ErrNotSynced) {
			t.Fatalf("%s before a sync: %v", rt, err)
		}
	}
	// An older helper: the bridge fenced, the TAPs not.
	if err := f.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.Ready(models.ContainerEngineContainerd); err != nil {
		t.Fatalf("the bridge: %v", err)
	}
	if err := f.Ready(models.RuntimeFirecracker); !errors.Is(err, errGuestsUnfenced) {
		t.Fatalf("TAPs an older helper leaves out: %v", err)
	}
	if rt, err := f.notReady(); rt != models.RuntimeFirecracker || err == nil {
		t.Fatalf("notReady = %s, %v", rt, err)
	}
	m.mu.Lock()
	m.guests, m.guestFence = true, "nft: no such table"
	m.mu.Unlock()
	if err := f.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.Ready(models.RuntimeFirecracker); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("TAPs not fenced yet: %v", err)
	}
	if err := f.Ready(models.RuntimeWasm); err == nil {
		t.Fatal("split mode fenced WASM")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := service.New(config.Config{}, testLogger(), nil, nil, nil, nil, nil, nil, nil)
	f.wire(ctx, svc, 5*time.Millisecond)
	m.mu.Lock()
	m.guestFence = ""
	m.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for f.Ready(models.RuntimeFirecracker) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the fence was not asked again")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rt, err := f.notReady(); rt != "" || err != nil {
		t.Fatalf("notReady = %s, %v", rt, err)
	}
	// A failed call holds every runtime.
	m.mu.Lock()
	m.err = rootclient.ErrUnavailable
	m.mu.Unlock()
	if err := f.sync(context.Background()); err == nil || f.Ready(models.RuntimeFirecracker) == nil || f.Ready(models.ContainerEngineContainerd) == nil {
		t.Fatal("a failed call left the fence ready")
	}
	cancel()
	// The boot step logs a fence not yet in place and goes on.
	m2 := newMemFirewall()
	if fence, err := bootSplitFirewall(context.Background(), m2, testLogger(), true); err != nil || fence.Ready(models.RuntimeFirecracker) == nil {
		t.Fatalf("boot with TAPs not fenced: %v, %v", fence, err)
	}
}
