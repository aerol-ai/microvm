package containerd

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

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
	if len(be.rules) != 1 || !strings.Contains(be.rules[0], "10.88.0.0/16|-d|10.20.0.0/16") {
		t.Fatalf("floor rules = %v", be.rules)
	}
	if err := New(Config{}, nil, nil).SetEgressFloor(context.Background(), nil); err != nil {
		t.Fatal("no rules manager is a no-op")
	}
}
