package netrules

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

func TestEnsureChainConcurrentLatchFastPath(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mgr.EnsureChain(); err != nil {
				t.Errorf("EnsureChain: %v", err)
			}
		}()
	}
	wg.Wait()
	if !mgr.chainReady.Load() {
		t.Fatal("chainReady should latch")
	}
}

func TestEnsureBridgeForwardAcceptSkipsExistingRules(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	mgr.SetBridgeSubnet("10.88.0.0/16")
	if err := be.Insert("filter", ChainAerolvmUser, 1, "-s", "10.88.0.0/16", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	if err := be.Insert("filter", ChainAerolvmUser, 1, "-d", "10.88.0.0/16", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ensureBridgeForwardAccept(); err != nil {
		t.Fatalf("ensureBridgeForwardAccept: %v", err)
	}
	if be.countMatching("ACCEPT") != 2 {
		t.Fatalf("rules = %v", be.rules)
	}
}

type bridgeInsertFailBackend struct {
	memBackend
	fail bool
}

func (b *bridgeInsertFailBackend) Insert(table, chain string, pos int, spec ...string) error {
	if b.fail {
		return errors.New("bridge insert boom")
	}
	return b.memBackend.Insert(table, chain, pos, spec...)
}

func TestEnsureBridgeForwardAcceptInsertError(t *testing.T) {
	be := &bridgeInsertFailBackend{fail: true}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	mgr.SetBridgeSubnet("10.88.0.0/16")
	if err := mgr.ensureBridgeForwardAccept(); err == nil {
		t.Fatal("expected insert error")
	}
}

func TestReassertChainPropagatesBootstrapErrors(t *testing.T) {
	mgr := &Manager{enabled: true, ipt: &failingBootstrap{failChain: true}, userChain: ChainAerolvmUser}
	if err := mgr.ReassertChain(); err == nil {
		t.Fatal("want chain error")
	}
	mgr = &Manager{enabled: true, ipt: &failingBootstrap{failJump: true}, userChain: ChainAerolvmUser}
	if err := mgr.ReassertChain(); err == nil {
		t.Fatal("want jump error")
	}
}

func TestExecBackendChainExistsError(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	t.Setenv("FAKE_IPTABLES_FAIL", "chain")
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)
	if err := be.EnsureUserChain(ChainAerolvmUser); err == nil {
		t.Fatal("expected ChainExists error")
	}
}

func TestExecBackendForwardCheckError(t *testing.T) {
	script, _ := writeBootstrapIPTables(t)
	ipt, err := iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be := newExecBackend(ipt)
	if err := be.EnsureUserChain(ChainAerolvmUser); err != nil {
		t.Fatalf("EnsureUserChain: %v", err)
	}
	t.Setenv("FAKE_IPTABLES_FAIL", "check")
	ipt, err = iptables.New(iptables.Path(script))
	if err != nil {
		t.Fatalf("iptables.New: %v", err)
	}
	be = newExecBackend(ipt)
	if err := be.EnsureForwardJump(ChainAerolvmUser); err == nil {
		t.Fatal("expected forward Exists error")
	}
}

func TestIptablesVersionDefaultSeam(t *testing.T) {
	_, _ = iptablesVersion()
}

func TestLockIPEmptyIsNoOp(t *testing.T) {
	mgr := NewWithBackend(&memBackend{})
	unlock := mgr.lockIP("")
	unlock()
}

func TestBlockAllIngressIdempotentAndClearError(t *testing.T) {
	mgr := NewWithBackend(&memBackend{})
	if err := mgr.BlockAllIngress("10.0.0.8"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.BlockAllIngress("10.0.0.8"); err != nil {
		t.Fatal(err)
	}

	sticky := &stickyDeleteBackend{
		countingBackend: countingBackend{memBackend: memBackend{}},
		deleteFail:      os.ErrPermission,
	}
	mgr = NewWithBackend(sticky)
	if err := mgr.BlockAllIngress("10.0.0.8"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ClearBlockAllIngress("10.0.0.8"); err == nil {
		t.Fatal("expected clear ingress error")
	}
}

type allowlistInsertFailBackend struct {
	memBackend
	inserts int
}

func (b *allowlistInsertFailBackend) Insert(table, chain string, pos int, spec ...string) error {
	b.inserts++
	if b.inserts == 3 {
		return errors.New("accept insert boom")
	}
	return b.memBackend.Insert(table, chain, pos, spec...)
}

func TestApplyEgressPolicyAllowlistInsertError(t *testing.T) {
	mgr := NewWithBackend(&allowlistInsertFailBackend{})
	if err := mgr.ApplyEgressPolicy("10.0.0.9", []string{"1.1.1.1/32", "8.8.8.8/32"}, nil); err == nil {
		t.Fatal("expected insert error on second ACCEPT")
	}
}
