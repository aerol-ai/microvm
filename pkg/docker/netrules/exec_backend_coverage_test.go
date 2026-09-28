package netrules

import (
	"testing"

	"github.com/coreos/go-iptables/iptables"
)

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
