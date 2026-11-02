package containerd

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

func TestNetworkRulesNilManagerNoOp(t *testing.T) {
	d := New(Config{}, nil, nil)
	if err := d.ApplyNetworkBlockAll("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyNetworkBlockIngress("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkBlockIngress("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkBlockEgress("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkRules("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyEgressPolicy("10.0.0.1", []string{"1.2.3.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearEgressPolicy("10.0.0.1", []string{"1.2.3.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.PushAllowedPorts(t.Context(), "10.0.0.1", "tok", []int{8080}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureRunscConfigNilDriverAndDefaultRunDir(t *testing.T) {
	var d *Driver
	if _, err := d.ensureRunscConfig(); err == nil {
		t.Fatal("want nil driver error")
	}
	// Empty RunDir uses the production default path under /var/lib — skip
	// writing there; just assert the path formula when RunDir is set to a
	// short temp via Config after New.
	tmp := shortReadyDir(t)
	d2 := New(Config{RunDir: tmp}, nil, nil)
	path, err := d2.ensureRunscConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Second call is idempotent (file already exists).
	path2, err := d2.ensureRunscConfig()
	if err != nil || path2 != path {
		t.Fatalf("path=%q path2=%q err=%v", path, path2, err)
	}
}

func TestNetworkRulesWithManager(t *testing.T) {
	be := &netrulesMemBackend{}
	mgr := netrules.NewWithBackend(be)
	d := New(Config{}, mgr, nil)
	ip := "10.88.0.5"
	if err := d.ApplyNetworkBlockAll(ip); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyNetworkBlockIngress(ip); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyEgressPolicy(ip, nil, []string{"0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearEgressPolicy(ip, nil, []string{"0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkBlockIngress(ip); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkBlockEgress(ip); err != nil {
		t.Fatal(err)
	}
	if err := d.ClearNetworkRules(ip); err != nil {
		t.Fatal(err)
	}
}

// netrulesMemBackend is a minimal backend for driver network rule tests.
type netrulesMemBackend struct {
	rules []string
}

// EnsureInputChain satisfies the netrules input bootstrap (P0-5).
func (m *netrulesMemBackend) EnsureInputChain(string) error { return nil }

func (m *netrulesMemBackend) Exists(table, chain string, spec ...string) (bool, error) {
	key := table + "|" + chain
	for _, s := range spec {
		key += "|" + s
	}
	for _, r := range m.rules {
		if r == key {
			return true, nil
		}
	}
	return false, nil
}

func (m *netrulesMemBackend) Insert(table, chain string, _ int, spec ...string) error {
	key := table + "|" + chain
	for _, s := range spec {
		key += "|" + s
	}
	m.rules = append(m.rules, key)
	return nil
}

func (m *netrulesMemBackend) Delete(table, chain string, spec ...string) error {
	key := table + "|" + chain
	for _, s := range spec {
		key += "|" + s
	}
	for i, r := range m.rules {
		if r == key {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return errors.New("No chain/target/match by that name")
}

func (m *netrulesMemBackend) EnsureUserChain(string) error   { return nil }
func (m *netrulesMemBackend) EnsureForwardJump(string) error { return nil }

// floorMemBackend adds the floor chain operations (§5.10 PC-2).
type floorMemBackend struct{ netrulesMemBackend }

func (f *floorMemBackend) EnsureJumpChain(string, string) error { return nil }
func (f *floorMemBackend) FlushChain(string) error              { f.rules = nil; return nil }

func TestSetEgressFloorUsesTheCNISubnet(t *testing.T) {
	be := &floorMemBackend{}
	mgr := netrules.NewWithBackend(be)
	mgr.SetBridgeSubnet("10.88.0.0/16")
	d := New(Config{}, mgr, nil)
	if err := d.SetEgressFloor(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	// The operator's range, and the CNI subnet to itself (sandboxes are
	// isolated from each other by default).
	if len(be.rules) != 2 || !strings.Contains(be.rules[0], "10.88.0.0/16|-d|10.20.0.0/16") || !strings.Contains(be.rules[1], "10.88.0.0/16|-d|10.88.0.0/16") {
		t.Fatalf("floor rules = %v", be.rules)
	}
	// The floor's re-assert goes to the manager (in place: nothing to do).
	if repaired, err := d.ReassertEgressFloor(context.Background()); repaired || err != nil {
		t.Fatalf("re-assert of a floor in place: %v %v", repaired, err)
	}
	// No firewall: no floor, said so (the service allows it outside
	// enterprise mode, like the node guard), and nothing to re-assert.
	if err := New(Config{}, nil, nil).SetEgressFloor(context.Background(), nil); !errors.Is(err, sbruntime.ErrEgressFloorUnavailable) {
		t.Fatalf("no rules manager: %v", err)
	}
	off, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(Config{}, off, nil).SetEgressFloor(context.Background(), nil); !errors.Is(err, sbruntime.ErrEgressFloorUnavailable) {
		t.Fatalf("rules disabled: %v", err)
	}
	if repaired, err := New(Config{}, nil, nil).ReassertEgressFloor(context.Background()); repaired || err != nil {
		t.Fatal("no rules manager: nothing to re-assert")
	}
	// A firewall but no CNI subnet: an error, never a silent success the
	// create gate would read as "installed".
	if err := New(Config{}, netrules.NewWithBackend(&floorMemBackend{}), nil).SetEgressFloor(context.Background(), nil); err == nil {
		t.Fatal("no CNI subnet must not pass for a floor")
	}
}

// NetRulesEnabled is what the service asks before it accepts network policy
// for a containerd sandbox: true only over a live manager.
func TestDriverNetRulesEnabled(t *testing.T) {
	disabled, err := netrules.NewWithOptions(false, netrules.BackendExec, netrules.ChainAerolvmUser)
	if err != nil {
		t.Fatal(err)
	}
	if New(Config{}, nil, nil).NetRulesEnabled() {
		t.Fatal("nil manager reported enabled")
	}
	if New(Config{}, disabled, nil).NetRulesEnabled() {
		t.Fatal("disabled manager reported enabled")
	}
	if !New(Config{}, netrules.NewWithBackend(&netrulesFailInsertBackend{}), nil).NetRulesEnabled() {
		t.Fatal("live manager reported disabled")
	}
}

// TestDriverNodeGuardUsesTheCNISubnet: the node guard covers the CNI
// bridge's subnet; a driver without a firewall reports the guard as
// unavailable rather than pretending it is in place.
func TestDriverNodeGuardUsesTheCNISubnet(t *testing.T) {
	ctx := context.Background()
	if err := New(Config{}, nil, nil).SetNodeGuard(ctx, nil); !errors.Is(err, sbruntime.ErrNodeGuardUnavailable) {
		t.Fatalf("no rules manager: %v", err)
	}
	off, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(Config{}, off, nil).SetNodeGuard(ctx, nil); !errors.Is(err, sbruntime.ErrNodeGuardUnavailable) {
		t.Fatalf("rules disabled: %v", err)
	}
	if repaired, err := New(Config{}, nil, nil).ReassertNodeGuard(ctx); repaired || err != nil {
		t.Fatal("no rules manager: nothing to re-assert")
	}
	be := &nodeMemBackend{}
	mgr := netrules.NewWithBackend(be)
	mgr.SetBridgeSubnet("10.88.0.0/16")
	d := New(Config{}, mgr, nil)
	if err := d.SetNodeGuard(ctx, []netrules.NodePort{{Proto: "udp", Port: 53054}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(be.rules, "\n")
	if !strings.Contains(joined, "-s|10.88.0.0/16|-p|udp|--dport|53054") || !strings.Contains(joined, "-s|10.88.0.0/16|-m|comment|--comment|sbx-node-guard|-j|DROP") {
		t.Fatalf("node guard rules = %v", be.rules)
	}
	if _, err := d.ReassertNodeGuard(ctx); err != nil {
		t.Fatal(err)
	}
}

// nodeMemBackend flushes one chain at a time, as the kernel does.
type nodeMemBackend struct{ netrulesMemBackend }

func (n *nodeMemBackend) EnsureJumpChain(string, string) error { return nil }
func (n *nodeMemBackend) FlushChain(chain string) error {
	kept := n.rules[:0]
	for _, r := range n.rules {
		if !strings.HasPrefix(r, "filter|"+chain+"|") {
			kept = append(kept, r)
		}
	}
	n.rules = kept
	return nil
}
