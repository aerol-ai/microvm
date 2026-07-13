package containerd

import (
	"errors"
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
