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
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// memFirewall is the helper's firewall calls in memory: it records each.
type memFirewall struct {
	mu    sync.Mutex
	calls []string
	fence string
	// guests: the fence covers the TAPs (a helper that serves
	// Firecracker), with guestFence why not yet.
	guests     bool
	guestFence string
	err        error             // every call's answer
	release    []error           // ReleaseSandbox's answers, in turn
	prepared   map[string]string // netns name -> address PrepareSandbox gave
}

func newMemFirewall() *memFirewall { return &memFirewall{prepared: map[string]string{}} }

func (m *memFirewall) record(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf(format, args...))
}

func (m *memFirewall) recorded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

func (m *memFirewall) EnsureHostFences(context.Context) (rootclient.Fences, error) {
	m.record("ensure")
	m.mu.Lock()
	defer m.mu.Unlock()
	return rootclient.Fences{Containerd: m.fence, Firecracker: m.guestFence, CoversFirecracker: m.guests}, m.err
}

func (m *memFirewall) SetNodeGuard(_ context.Context, allow []*rootdpb.NodePort) (bool, error) {
	var s []string
	for _, p := range allow {
		s = append(s, fmt.Sprintf("%s/%d@%s", p.GetProto(), p.GetPort(), p.GetDst()))
	}
	m.record("guard %v", s)
	return false, m.err
}

func (m *memFirewall) SetEgressFloor(_ context.Context, cidrs []string) (bool, error) {
	m.record("floor %v", cidrs)
	return false, m.err
}

func (m *memFirewall) SandboxRules(_ context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	m.record("%s %s %v %v", strings.TrimPrefix(op.String(), "SANDBOX_RULES_OP_"), ip, allow, deny)
	return op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, m.err
}

func (m *memFirewall) PrepareSandbox(_ context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	fw := req.GetFirewall()
	m.record("prepare %s %v ip=%s block=%v %v %v", req.GetNetnsName(), req.GetParts(), req.GetContainerIp(),
		fw.GetBlockAllEgress(), fw.GetAllowCidrs(), fw.GetDenyCidrs())
	if m.err != nil {
		return nil, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ip := fmt.Sprintf("10.88.0.%d", len(m.prepared)+2)
	m.prepared[req.GetNetnsName()] = ip
	return &rootdpb.PrepareSandboxResponse{NetnsPath: "/run/aerolvm-rootd/netns/" + req.GetNetnsName(), ContainerIp: ip}, nil
}

func (m *memFirewall) ReleaseSandbox(_ context.Context, req *rootdpb.ReleaseSandboxRequest) error {
	m.record("release %s ip=%s %v", req.GetNetnsName(), req.GetContainerIp(), req.GetParts())
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.release) > 0 {
		err := m.release[0]
		m.release = m.release[1:]
		return err
	}
	return m.err
}

// TestHelperFirewall: each of the driver's firewall methods is one helper
// call, with the same address and lists; an empty address is no call, as
// in netrules; a re-assert sends the last list again.
func TestHelperFirewall(t *testing.T) {
	m := newMemFirewall()
	f := newHelperFirewall(m, "10.88.0.0/16")
	if !f.Enabled() || f.BridgeSubnet() != netip.MustParsePrefix("10.88.0.0/16") {
		t.Fatal("enabled, subnet")
	}
	ip := "10.88.0.5"
	allow, deny := []string{"1.2.3.4/32"}, []string{"10.0.0.0/8"}
	if ins, err := f.BlockAllEgressReport(ip); err != nil || !ins {
		t.Fatalf("report %v %v", ins, err)
	}
	for _, err := range []error{
		f.BlockAllEgress(ip), f.LiftBlockAllEgress(ip), f.ClearBlockAllEgress(ip), f.BlockAllIngress(ip),
		f.ClearBlockAllIngress(ip), f.ApplyEgressPolicy(ip, allow, deny), f.ClearEgressPolicy(ip, allow, deny),
		f.HoldEgress(ip), f.ClearHoldEgress(ip), f.BlockAllEgress(" "),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"BLOCK_EGRESS 10.88.0.5 [] []", "BLOCK_EGRESS 10.88.0.5 [] []", "LIFT_BLOCK_EGRESS 10.88.0.5 [] []",
		"CLEAR_BLOCK_EGRESS 10.88.0.5 [] []", "BLOCK_INGRESS 10.88.0.5 [] []", "CLEAR_BLOCK_INGRESS 10.88.0.5 [] []",
		"APPLY_EGRESS_POLICY 10.88.0.5 [1.2.3.4/32] [10.0.0.0/8]", "CLEAR_EGRESS_POLICY 10.88.0.5 [1.2.3.4/32] [10.0.0.0/8]",
		"HOLD_EGRESS 10.88.0.5 [] []", "CLEAR_HOLD_EGRESS 10.88.0.5 [] []",
	}
	if got := m.recorded(); !slices.Equal(got, want) {
		t.Fatalf("calls\n%q\nwant\n%q", got, want)
	}
	m.calls = nil
	// Before a list was set, a re-assert sends nothing.
	if r, err := f.ReassertNodeGuard(); r || err != nil || len(m.recorded()) != 0 {
		t.Fatalf("reassert before set: %v %v %v", r, err, m.recorded())
	}
	if r, err := f.ReassertFloor(); r || err != nil {
		t.Fatalf("reassert floor before set: %v %v", r, err)
	}
	guard := []netrules.NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: netip.MustParseAddr("10.0.1.5")}}
	if err := f.SetNodeGuard(netip.Prefix{}, guard); err != nil {
		t.Fatal(err)
	}
	if err := f.SetFloor(netip.Prefix{}, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReassertNodeGuard(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReassertFloor(); err != nil {
		t.Fatal(err)
	}
	want = []string{"guard [tcp/15080@ udp/53@10.0.1.5]", "floor [10.20.0.0/16]", "guard [tcp/15080@ udp/53@10.0.1.5]", "floor [10.20.0.0/16]"}
	if got := m.recorded(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	// A failed set keeps the list it had.
	m.err = errors.New("xtables lock")
	if err := f.SetNodeGuard(netip.Prefix{}, nil); err == nil {
		t.Fatal("a failed set succeeded")
	}
	if err := f.SetFloor(netip.Prefix{}, nil); err == nil {
		t.Fatal("a failed floor succeeded")
	}
	m.err = nil
	m.calls = nil
	if _, err := f.ReassertNodeGuard(); err != nil || !slices.Equal(m.recorded(), []string{"guard [tcp/15080@ udp/53@10.0.1.5]"}) {
		t.Fatalf("reassert after a failed set: %v %v", err, m.recorded())
	}
	// A warm create's rules: one PrepareSandbox, firewall part alone.
	m.calls = nil
	if err := f.ApplyCreateRules(context.Background(), "aerol-netns-1", ip, true, allow, nil); err != nil {
		t.Fatal(err)
	}
	if got := m.recorded(); !slices.Equal(got, []string{"prepare aerol-netns-1 [firewall] ip=10.88.0.5 block=true [1.2.3.4/32] []"}) {
		t.Fatalf("calls %q", got)
	}
	if !f.FoldsIntoBuild() || !f.ClearsOnRelease() {
		t.Fatal("the helper's firewall folds into builds and clears on release")
	}
}

// TestHelperFence: the create gate's answer is the helper's last report;
// it is asked again while the fence is not in place.
func TestHelperFence(t *testing.T) {
	m := newMemFirewall()
	f := newHelperFence(m, testLogger(), false)
	if err := f.Ready(models.ContainerEngineContainerd); !errors.Is(err, ipv6fence.ErrNotSynced) {
		t.Fatalf("before a sync: %v", err)
	}
	m.fence = "nft: no such table"
	if err := f.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.Ready(models.ContainerEngineContainerd); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("a fence not in place: %v", err)
	}
	if err := f.Ready(models.RuntimeFirecracker); err == nil {
		t.Fatal("a node with no Firecracker fenced Firecracker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := service.New(config.Config{}, testLogger(), nil, nil, nil, nil, nil, nil, nil)
	f.wire(ctx, svc, 5*time.Millisecond)
	m.mu.Lock()
	m.fence = ""
	m.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for f.Ready(models.ContainerEngineContainerd) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the fence was not asked again")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A call that fails is the state too.
	m.mu.Lock()
	m.err = rootclient.ErrUnavailable
	m.mu.Unlock()
	if err := f.sync(context.Background()); err == nil || f.Ready(models.ContainerEngineContainerd) == nil {
		t.Fatal("a failed call left the fence ready")
	}
	cancel()
}

// TestBootSplitFirewall: a failed host step stops the start, with what to
// do when the helper is too old; a fence not in place does not.
func TestBootSplitFirewall(t *testing.T) {
	m := newMemFirewall()
	m.fence = "no nft"
	f, err := bootSplitFirewall(context.Background(), m, testLogger(), false)
	if err != nil || f.Ready(models.ContainerEngineContainerd) == nil {
		t.Fatalf("fence not in place: %v %v", f, err)
	}
	m.err = &rootclient.UnsupportedError{Feature: rootdpb.FeatureEnsureHost}
	if _, err := bootSplitFirewall(context.Background(), m, testLogger(), false); err == nil || !strings.Contains(err.Error(), "newer helper") {
		t.Fatalf("too old: %v", err)
	}
	m.err = rootclient.ErrUnavailable
	if _, err := bootSplitFirewall(context.Background(), m, testLogger(), false); !errors.Is(err, rootclient.ErrUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
}

// TestHelperNetnsHostWithTheFirewall: a cold create's build carries its
// rules (one PrepareSandbox, marked applied); a build without them stays
// RealizeNetns; a release is one ReleaseSandbox with the address's rules;
// an address another slot holds now is left to it.
func TestHelperNetnsHostWithTheFirewall(t *testing.T) {
	mh, m := newMemHelper(), newMemFirewall()
	h := newHelperNetnsHost(mh, "10.88.0.0/16", testLogger())
	h.fw = m
	ctx := context.Background()
	if _, _, err := h.Realize(ctx, netns.Slot{SlotID: "aerol-netns-0", SandboxID: "aerol-netns-0"}); err != nil {
		t.Fatal(err)
	}
	if len(m.recorded()) != 0 || len(mh.ns) != 1 {
		t.Fatalf("a build with no rules went to PrepareSandbox: %v", m.recorded())
	}
	rules := &cntr.BuildRules{BlockAll: true, Allow: []string{"1.2.3.4/32"}}
	rctx := cntr.ContextWithBuildRules(ctx, rules)
	path, ip, err := h.Realize(rctx, netns.Slot{SlotID: "s-1", SandboxID: "sb-1"})
	if err != nil || path == "" || ip == "" || !rules.Applied() {
		t.Fatalf("Realize = %q %q %v applied=%v", path, ip, err, rules.Applied())
	}
	if got := m.recorded(); !slices.Equal(got, []string{"prepare sb-1 [netns firewall] ip= block=true [1.2.3.4/32] []"}) {
		t.Fatalf("calls %q", got)
	}
	m.calls = nil
	if err := h.Remove(ctx, netns.Slot{SlotID: "s-1", SandboxID: "sb-1", NetnsPath: path, ContainerIP: ip}); err != nil {
		t.Fatal(err)
	}
	if got := m.recorded(); !slices.Equal(got, []string{"release sb-1 ip=" + ip + " [netns firewall]"}) {
		t.Fatalf("calls %q", got)
	}
	// The recorded address is another slot's now: the release goes on
	// without it.
	m.calls = nil
	m.release = []error{&rootclient.RefusedError{Refusal: rootclient.Refusal{Reason: string(rootpolicy.RuleLease)}, Err: errors.New("leased")}}
	if err := h.Remove(ctx, netns.Slot{SlotID: "s-2", SandboxID: "sb-2", NetnsPath: "/x/sb-2", ContainerIP: "10.88.0.9"}); err != nil {
		t.Fatal(err)
	}
	if got := m.recorded(); !slices.Equal(got, []string{"release sb-2 ip=10.88.0.9 [netns firewall]", "release sb-2 ip= [netns firewall]"}) {
		t.Fatalf("calls %q", got)
	}
	// Any other refusal is the answer.
	m.calls = nil
	m.release = []error{&rootclient.RefusedError{Refusal: rootclient.Refusal{Reason: "not_sandbox_netns"}, Err: errors.New("no")}}
	if err := h.Remove(ctx, netns.Slot{SlotID: "s-3", SandboxID: "sb-3", NetnsPath: "/x/sb-3", ContainerIP: "10.88.0.10"}); err == nil || len(m.recorded()) != 1 {
		t.Fatalf("Remove = %v, calls %v", err, m.recorded())
	}
	// A build that failed after the helper may have run part of it is
	// released, its rules part included, under its name.
	m.calls = nil
	m.err = rootclient.ErrUnavailable
	rules = &cntr.BuildRules{BlockAll: true}
	if _, _, err := h.Realize(cntr.ContextWithBuildRules(ctx, rules), netns.Slot{SlotID: "s-4", SandboxID: "sb-4"}); !errors.Is(err, rootclient.ErrUnavailable) || rules.Applied() {
		t.Fatalf("Realize = %v applied=%v", err, rules.Applied())
	}
	if got := m.recorded(); len(got) != 2 || got[1] != "release sb-4 ip= [netns firewall]" {
		t.Fatalf("calls %q", got)
	}
}

// TestWireContainerEngineSplitFirewall: with the host firewall on, a split
// boot runs the helper's host step, gives the driver the helper's firewall
// and the create gate the helper's fence, and touches no kernel rule in
// process. The driver's rule calls, node guard and floor reach the helper.
func TestWireContainerEngineSplitFirewall(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := splitConfig()
	cfg.EnableNetworkRules = true
	cfg.ContainerdNamespace, cfg.ContainerdSocket = "aerolvm", "/run/containerd/containerd.sock"
	cfg.ContainerdNetnsPoolSize, cfg.ContainerdNetnsPoolRefillInterval = 1, time.Hour
	cfg.ContainerdBridgeSubnet = "10.88.0.0/16"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	m := newMemFirewall()
	h := &engineHelper{memHelper: newMemHelper(), memFirewall: m}
	w, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if w.fence == nil || w.fence.Ready(models.ContainerEngineContainerd) != nil || !w.driver.NetRulesEnabled() {
		t.Fatalf("fence %v, rules on %v", w.fence, w.driver.NetRulesEnabled())
	}
	if got := m.recorded(); !slices.Equal(got, []string{"ensure"}) {
		t.Fatalf("boot calls %q", got)
	}
	m.calls = nil
	if err := w.driver.ApplyNetworkBlockAll("10.88.0.7"); err != nil {
		t.Fatal(err)
	}
	if err := w.driver.SetNodeGuard(ctx, []netrules.NodePort{{Proto: "tcp", Port: 15080}}); err != nil {
		t.Fatal(err)
	}
	if err := w.driver.SetEgressFloor(ctx, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	want := []string{"BLOCK_EGRESS 10.88.0.7 [] []", "guard [tcp/15080@]", "floor [10.20.0.0/16]"}
	if got := m.recorded(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	// A destroy makes no clears of its own: the slot's release does them.
	m.calls = nil
	_ = w.driver.Destroy(ctx, &models.Sandbox{ID: "sb-gone", ContainerIP: "10.88.0.7", NetworkAllowOut: []string{"1.2.3.4/32"}})
	for _, c := range m.recorded() {
		if strings.Contains(c, "CLEAR") {
			t.Fatalf("a destroy cleared rules itself: %q", m.recorded())
		}
	}

	// The host step failing stops the boot.
	m2 := newMemFirewall()
	m2.err = errors.New("nft: Operation not permitted")
	if _, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, &engineHelper{memHelper: newMemHelper(), memFirewall: m2}); err == nil {
		t.Fatal("a failed host step did not stop the boot")
	}
	// Enterprise mode with the firewall off: the fence, and no rules.
	cfg.EnableNetworkRules, cfg.EnterpriseMode = false, true
	m3 := newMemFirewall()
	w3, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, &engineHelper{memHelper: newMemHelper(), memFirewall: m3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w3.Stop)
	if w3.fence == nil || w3.driver.NetRulesEnabled() {
		t.Fatalf("enterprise without rules: fence %v rules %v", w3.fence, w3.driver.NetRulesEnabled())
	}
}
