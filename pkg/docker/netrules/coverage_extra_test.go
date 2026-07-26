package netrules

import (
	"errors"
	"runtime"
	"testing"
)

func TestSetBridgeSubnetNilGuard(t *testing.T) {
	var m *Manager
	m.SetBridgeSubnet("10.88.0.0/16") // no-op on nil
}

func TestResetChainLatchNilGuard(t *testing.T) {
	var m *Manager
	m.ResetChainLatch() // no-op on nil
}

func TestReassertChainNilAndNonBootstrap(t *testing.T) {
	var m *Manager
	if err := m.ReassertChain(); err != nil {
		t.Fatalf("nil manager: %v", err)
	}

	m = &Manager{enabled: true, ipt: ruleOnlyBackend{}}
	if err := m.ReassertChain(); err != nil {
		t.Fatalf("non-bootstrap backend should no-op: %v", err)
	}
}

func TestNewWithOptionsBranches(t *testing.T) {
	m, err := NewWithOptions(false, "bogus", ChainAerolvmUser)
	if err != nil || m == nil || m.Enabled() {
		t.Fatalf("disabled = %+v, %v", m, err)
	}

	m, err = NewWithOptions(true, "", "")
	if err != nil || m == nil {
		t.Fatalf("enabled on %s: %+v, %v", runtime.GOOS, m, err)
	}
	if runtime.GOOS != "linux" && m.Enabled() {
		t.Fatal("non-linux enabled request must return disabled manager")
	}

	if runtime.GOOS == "linux" {
		_, err = NewWithOptions(true, "bogus", "")
		if err == nil {
			t.Fatal("unknown backend should error on linux")
		}
	}
}

type existsFailBackend struct {
	memBackend
}

func (existsFailBackend) Exists(string, string, ...string) (bool, error) {
	return false, errors.New("exists boom")
}

func TestEnsureBridgeForwardAcceptExistsError(t *testing.T) {
	mgr := &Manager{enabled: true, ipt: &existsFailBackend{}, userChain: ChainAerolvmUser}
	mgr.SetBridgeSubnet("10.88.0.0/16")
	if err := mgr.EnsureChain(); err == nil {
		t.Fatal("expected exists error from bridge forward accept")
	}
}

type stickyDeleteFailBackend struct {
	memBackend
}

func (s *stickyDeleteFailBackend) Delete(string, string, ...string) error {
	return errors.New("delete boom")
}

func TestClearBlockAllIngressDeleteError(t *testing.T) {
	// Delete must fail while Exists still sees the rule — otherwise
	// deleteUntilGone treats "gone" as success (netlink confirm path).
	backend := &stickyDeleteFailBackend{}
	mgr := NewWithBackend(backend)
	if err := mgr.BlockAllIngress("10.0.0.8"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.ClearBlockAllIngress("10.0.0.8"); err == nil {
		t.Fatal("expected delete error")
	}
}

func TestReassertChainDisabled(t *testing.T) {
	mgr := &Manager{enabled: false, userChain: ChainAerolvmUser}
	if err := mgr.ReassertChain(); err != nil {
		t.Fatalf("disabled reassert: %v", err)
	}
}

func TestReassertChainBridgeSubnet(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	mgr.SetBridgeSubnet("10.88.0.0/16")
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	be.reset()
	if err := mgr.ReassertChain(); err != nil {
		t.Fatalf("ReassertChain: %v", err)
	}
	if !be.hasChain(ChainAerolvmUser) {
		t.Fatal("chain not re-created")
	}
}
