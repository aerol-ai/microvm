package netrules

import (
	"errors"
	"os"
	"testing"
)

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
